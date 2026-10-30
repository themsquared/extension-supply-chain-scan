# extension-supply-chain-scan

A stdlib-only Python scanner for the documented indicators of compromise
from the Claude Code for VS Code / Cursor Marketplace extension backdoor
(version 2.1.313, disclosed 2026-10-30). No dependencies, no network calls,
and no reproduction of the actual malware: it checks for the planted
filenames, SSH key comment, and persistence artifacts that the public
writeup already disclosed.

> I work at Solo.io, which makes [agentgateway](https://agentgateway.dev).
> This repo and the write-up it supports are about a public supply-chain
> incident in an IDE extension, not a product comparison, and the scanner
> only checks for the documented IOCs below.

## What happened (short version)

On 2026-10-30, security research firm Phorion disclosed that the official
Claude Code extension for VS Code, as distributed through the **Cursor
Marketplace**, had been compromised at version 2.1.313. The backdoored
`extension.js` bundle had an immediately-invoked function injected ahead of
the normal extension code, so the payload runs the moment the extension
loads, before the user does anything.

The injected code:

1. Appends an attacker-controlled Ed25519 public key (comment
   `svc-telemetry`) to `~/.ssh/authorized_keys`, then tries to turn on the
   local SSH daemon (`systemctl`/`service` on Linux, `systemsetup` on
   macOS, PowerShell's OpenSSH Server on Windows).
2. Opens an outbound reverse SSH tunnel (`-R *:0:localhost:22`) to
   `134.209.82[.]225`, using a second embedded key (comment
   `svc-telemetry-tun`). The attacker then logs back in through that tunnel
   using the key planted in step 1, so inbound sessions appear to come from
   `localhost` in the victim's own SSH logs.
3. Installs platform-specific persistence: a disguised user LaunchAgent
   (`~/Library/LaunchAgents/com.apple.sysmond.plist`) on macOS, an
   `@reboot` cron entry on Linux, and a scheduled task or Startup-folder
   script on Windows.
4. Sends a one-time recon beacon (hostname, OS, public IP, and the *names*
   of up to 40 environment variables matching `KEY|TOKEN|SECRET|PASS|AWS|GCP`,
   not their values) to the same IP over plain HTTP.

Phorion also found an implementation bug: the macOS enable-SSH check reads
`systemsetup -getremotelogin` without elevation, which fails with an
administrator-access error that the malware's own helper treats as "already
on". That skips the enable step on a Mac where Remote Login was off, which
limits (but does not eliminate) impact on fresh macOS installs, since the
keys and persistence still get dropped either way.

Cursor pulled the compromised release from its marketplace and the matching
npm/VSCode packages.

Full technical writeup, which this repo's IOC list is sourced from:

- [Phorion: Official Claude Code Extension Compromise](https://phorion.io/blog/offical-claude-code-vsx-compromise/)

## The value proposition this maps to

The **Cursor Marketplace**, a third-party extension registry, served a
backdoored bundle under the extension's real name and publisher. Phorion's
public writeup does not implicate Anthropic's own release pipeline. An IDE extension runs with the full permissions of the
IDE and the user running it, so once that one file loads, it can write to
`~/.ssh`, read source trees, and reach the network with zero additional
prompts or approvals. For anyone running agent tooling on a developer
laptop, the IDE's extension marketplace is as much a trust boundary as any
registry agentgateway fronts, and it is usually the one with the weakest
controls: no mTLS, no policy engine, often no pinned version. The same
discipline that argues for scoped credentials and egress controls in front
of an AI gateway argues for pinning and verifying editor extensions too.

## Quickstart

```bash
git clone https://github.com/themsquared/extension-supply-chain-scan.git
cd extension-supply-chain-scan
./scripts/demo.sh
```

This runs the scanner three times:

1. Against `fixtures/clean_home/` — expect `CLEAN`, exit 0.
2. Against `fixtures/compromised_home/` (and `fixtures/compromised_tmp/`),
   which contain inert stub files using the real incident's artifact names
   (`.smt`, `.smtk`, `com.apple.sysmond.plist`, a `svc-telemetry` key
   comment, a `.stk_*` file) with no functional payload — expect
   `COMPROMISED`, exit 2.
3. Against this machine's real `$HOME`, informationally.

Or run it directly against any home directory:

```bash
python3 scan.py                           # your real $HOME and $TMPDIR
python3 scan.py --home /path/to/home --tmp /path/to/tmp
```

Exit codes: `0` clean, `1` suspicious (corroborating evidence only), `2`
confirmed IOC present.

## What it checks

From the public writeup's documented artifacts:

- **Recalled extension version** installed under `.vscode/extensions`,
  `.vscode-server/extensions`, or `.cursor/extensions`
  (`anthropic.claude-code-2.1.313-*`), and a SHA-256 check of its
  `extension.js` against the published backdoored-bundle hash
  (`ecb58cb2...6bf15`) when present.
- **`~/.ssh/authorized_keys`** for the planted key's comment
  (`svc-telemetry`).
- **`<TMPDIR>/.stk_*`** — the initial tunnel private key, named with the
  first 10 hex characters of `MD5(hostname + HOME)`.
- **`~/.config/.smt` and `~/.config/.smtk`** (macOS/Linux persistence
  script and recreated tunnel key) and **`~/.config/smt.cmd` /
  `~/.config/smtk`** (Windows equivalents).
- **`~/Library/LaunchAgents/com.apple.sysmond.plist`** — the disguised
  macOS LaunchAgent.
- **The Windows Startup-folder fallback script**
  (`...\Start Menu\Programs\Startup\sysmon.cmd`).
- **An `@reboot` crontab entry referencing `.smt`** on Linux/macOS, via a
  best-effort `crontab -l` (skip with `--skip-crontab`).

## What it does not check

This is a point-in-time filesystem scan, not an EDR agent. It does not scan
the network for the C2 IP (`134.209.82.225`), inspect running processes for
active `ssh`/`autossh` tunnels, or detect a variant that renames the
planted artifacts. If any CRITICAL finding appears, assume the tunnel was
or could be live and follow the remediation steps the scanner prints:
rebuild rather than clean in place, and rotate every credential the
affected account could reach, especially anything matching
`KEY|TOKEN|SECRET|PASS|AWS|GCP`, since the beacon specifically enumerates
those variable names.

## Architecture notes

`scan.py` is a single stdlib file on purpose: something a developer can
pull down and run on a personal laptop during an active scare without
installing a new dependency. It runs independent checks (extension
install, SSH keys, temp-dir tunnel key, persistence artifacts, crontab) and
aggregates the worst severity into the process exit code so it is
scriptable in CI or a fleet-wide sweep via SSH/MDM.

## License

Apache-2.0. See [LICENSE](LICENSE).

Topics: `supply-chain-security`, `vscode`, `ide-extensions`,
`incident-response`, `ai-agents`, `mcp`, `agent-security`
