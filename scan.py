#!/usr/bin/env python3
"""
IOC scanner for the Claude Code for VS Code / Cursor Marketplace extension
compromise (extension.js 2.1.313, disclosed 2026-10-30 by Phorion).

Stdlib only, no network calls, no dependencies. Detects the documented
filesystem and SSH-key artifacts from the public writeup without
reproducing or bundling any of the actual malicious code. See README.md
for sources and the full IOC list.

Usage:
    python3 scan.py                      # scan the real $HOME
    python3 scan.py --home /path/to/home # scan an arbitrary home dir (fixtures, other users)
"""
import argparse
import glob
import hashlib
import os
import sys

BAD_VERSION = "2.1.313"
BAD_EXTENSION_SHA256 = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
SSH_KEY_COMMENT = "svc-telemetry"
C2_IP = "134.209.82.225"

EXTENSION_ROOTS = [".vscode/extensions", ".vscode-server/extensions", ".cursor/extensions"]


def find_extension_dirs(home):
    hits = []
    for root in EXTENSION_ROOTS:
        pattern = os.path.join(home, root, f"anthropic.claude-code-{BAD_VERSION}-*")
        hits.extend(glob.glob(pattern))
    return hits


def scan_extension_install(home):
    findings = []
    for d in find_extension_dirs(home):
        findings.append(("CRITICAL", f"recalled extension version installed: {d}"))
        bundle = os.path.join(d, "extension.js")
        if os.path.isfile(bundle):
            digest = hashlib.sha256(open(bundle, "rb").read()).hexdigest()
            if digest == BAD_EXTENSION_SHA256:
                findings.append(("CRITICAL", f"extension.js matches the backdoored hash: {bundle}"))
            else:
                findings.append(("WARN", f"extension.js present but hash differs (platform build or already patched): {bundle}"))
    return findings


def scan_authorized_keys(home):
    findings = []
    path = os.path.join(home, ".ssh", "authorized_keys")
    if os.path.isfile(path):
        content = open(path, "r", errors="ignore").read()
        if SSH_KEY_COMMENT in content:
            findings.append(("CRITICAL", f"planted SSH key comment '{SSH_KEY_COMMENT}' present: {path}"))
    return findings


def scan_tmp_tunnel_key(tmp_dir):
    findings = []
    for match in glob.glob(os.path.join(tmp_dir, ".stk_*")):
        findings.append(("CRITICAL", f"tunnel private key artifact present: {match}"))
    return findings


def scan_persistence_unix(home):
    findings = []
    for name in (".smt", ".smtk"):
        path = os.path.join(home, ".config", name)
        if os.path.isfile(path):
            findings.append(("CRITICAL", f"persistence artifact present: {path}"))
    plist = os.path.join(home, "Library", "LaunchAgents", "com.apple.sysmond.plist")
    if os.path.isfile(plist):
        findings.append(("CRITICAL", f"disguised LaunchAgent present: {plist}"))
    return findings


def scan_persistence_windows(home):
    findings = []
    for name in ("smt.cmd", "smtk"):
        path = os.path.join(home, ".config", name)
        if os.path.isfile(path):
            findings.append(("CRITICAL", f"persistence artifact present: {path}"))
    startup = os.path.join(
        home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "sysmon.cmd"
    )
    if os.path.isfile(startup):
        findings.append(("CRITICAL", f"Startup-folder persistence script present: {startup}"))
    return findings


def scan_crontab():
    findings = []
    try:
        import subprocess

        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3)
        if out.returncode == 0 and ".smt" in out.stdout:
            findings.append(("CRITICAL", "crontab contains an @reboot entry referencing .smt"))
    except Exception:
        pass
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", default=os.path.expanduser("~"), help="home directory to scan (default: real $HOME)")
    parser.add_argument("--tmp", default=os.environ.get("TMPDIR", "/tmp"), help="temp directory to scan for tunnel keys")
    parser.add_argument("--skip-crontab", action="store_true", help="skip the live crontab -l check")
    args = parser.parse_args()

    home = os.path.abspath(args.home)
    print(f"Scanning home: {home}")
    print(f"Scanning temp dir: {args.tmp}")
    print()

    all_findings = []
    all_findings.extend(scan_extension_install(home))
    all_findings.extend(scan_authorized_keys(home))
    all_findings.extend(scan_tmp_tunnel_key(args.tmp))
    all_findings.extend(scan_persistence_unix(home))
    all_findings.extend(scan_persistence_windows(home))
    if not args.skip_crontab:
        all_findings.extend(scan_crontab())

    if not all_findings:
        print(f"CLEAN: no known IOCs from the {BAD_VERSION} extension compromise found.")
        return 0

    critical = [f for f in all_findings if f[0] == "CRITICAL"]
    warn = [f for f in all_findings if f[0] == "WARN"]

    for sev, msg in critical + warn:
        print(f"[{sev}] {msg}")

    if critical:
        print()
        print("COMPROMISED: treat this host as breached. Do not clean in place.")
        print(f"  1. Kill active tunnel processes: 'ssh'/'autossh' connecting to {C2_IP}.")
        print(f"  2. Remove the '{SSH_KEY_COMMENT}' key from ~/.ssh/authorized_keys.")
        print("  3. Unload and delete the LaunchAgent / cron entry / scheduled task, plus ~/.config/.smt*.")
        print("  4. Rotate every credential this account could reach: cloud keys, SSH/GPG keys, CI tokens.")
        print("  5. Rebuild the dev environment rather than trusting it clean after manual removal.")
        return 2
    if warn:
        print()
        print("SUSPICIOUS: corroborating evidence only. Investigate before ruling this out.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
