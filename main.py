#!/usr/bin/env python3
"""
GAMA — Greyware Analysis and Mitigation Approach
CenturiaLabs / ClickSafe UAE — v1.0

Interactive orchestrator. Every step is an analyst choice.
Technology collects. The analyst interprets.
"""

import os
import sys
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# ─── ANSI colours ───────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"

def clr(text, color): return f"{color}{text}{C.RESET}"
def bold(text):       return f"{C.BOLD}{text}{C.RESET}"
def ok(text):         print(f"  {clr('✓', C.GREEN)} {text}")
def warn(text):       print(f"  {clr('!', C.YELLOW)} {text}")
def err(text):        print(f"  {clr('✗', C.RED)} {text}")
def info(text):       print(f"  {clr('·', C.CYAN)} {text}")
def sep():            print(f"  {clr('─' * 58, C.GRAY)}")

WORKSPACE_ROOT = Path(__file__).parent / "workspace"
MODULES_DIR    = Path(__file__).parent / "modules"
RULES_DIR      = Path(__file__).parent / "rules"
FRIDA_DIR      = Path(__file__).parent / "frida_scripts"

# ─── session state ─────────────────────────────────────────────
session = {
    "workspace":  None,
    "apk_path":   None,
    "apk_name":   None,
    "hypothesis": None,
    "phase":      0,
    "findings":   [],
}

# ─── workspace utilities ──────────────────────────────────────────
def load_workspace(ws_path: Path):
    meta = ws_path / "meta.json"
    if meta.exists():
        with open(meta) as f:
            data = json.load(f)
        session.update(data)
        session["workspace"] = ws_path
        ok(f"Workspace loaded: {bold(ws_path.name)}")
        if session.get("hypothesis"):
            info(f"Active hypothesis: {session['hypothesis'][:80]}...")
    else:
        warn("meta.json not found in the selected workspace.")

def save_session():
    if not session["workspace"]:
        return
    meta = session["workspace"] / "meta.json"
    data = {k: str(v) if isinstance(v, Path) else v
            for k, v in session.items() if k != "workspace"}
    with open(meta, "w") as f:
        json.dump(data, f, indent=2, default=str)

def findings_path():
    if not session["workspace"]:
        return None
    return session["workspace"] / "findings.jsonl"

def add_finding(phase, technique, description, evidence, classification="hypothesis"):
    """Append a finding to the workspace JSONL log. Append-only."""
    finding = {
        "timestamp": datetime.now().isoformat(),
        "phase": phase,
        "gama_technique": technique,
        "description": description,
        "evidence": evidence,
        "classification": classification,
        "analyst_note": ""
    }
    fp = findings_path()
    if fp:
        with open(fp, "a") as f:
            f.write(json.dumps(finding) + "\n")
    session["findings"].append(finding)
    return finding

def load_findings():
    fp = findings_path()
    if not fp or not fp.exists():
        return []
    findings = []
    with open(fp) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return findings

# ─── banner ─────────────────────────────────────────────────────
def print_banner():
    os.system("clear")
    print(f"""
{clr('  ██████╗  █████╗ ███╗   ███╗ █████╗', C.BLUE)}
{clr('  ██╔════╝ ██╔══██╗████╗ ████║██╔══██╗', C.BLUE)}
{clr('  ██║  ███╗███████║██╔████╔██║███████║', C.BLUE)}
{clr('  ██║   ██║██╔══██║██║╚██╔╝██║██╔══██║', C.BLUE)}
{clr('  ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║', C.BLUE)}
{clr('   ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝', C.BLUE)}

  {bold('Greyware Analysis and Mitigation Approach')}  {clr('v1.0', C.GRAY)}
  {clr('CenturiaLabs · ClickSafe UAE', C.GRAY)}
  {clr('Technology collects. The analyst interprets.', C.DIM)}
""")

def print_status_bar():
    ws   = session["workspace"].name if session["workspace"] else clr("none", C.RED)
    apk  = session["apk_name"] or clr("none", C.RED)
    ph   = f"Phase {session['phase']}"
    nf   = len(load_findings())
    hyp  = "✓" if session.get("hypothesis") else clr("✗", C.RED)
    print(f"  {clr('workspace', C.GRAY)} {bold(ws)}  "
          f"{clr('APK', C.GRAY)} {bold(apk)}  "
          f"{clr('phase', C.GRAY)} {bold(ph)}  "
          f"{clr('findings', C.GRAY)} {bold(nf)}  "
          f"{clr('hypothesis', C.GRAY)} {hyp}")
    sep()

# ─── main menu ────────────────────────────────────────────
def main_menu():
    print_banner()
    print_status_bar()
    print(f"""
  {bold('WORKSPACE')}
  {clr('1', C.CYAN)}  New workspace (new analysis)
  {clr('2', C.CYAN)}  Open existing workspace
  {clr('3', C.CYAN)}  List workspaces

  {bold('ANALYSIS — GAMA PHASES')}
  {clr('4', C.PURPLE)}  Phase 0  — Intake and threat hypothesis
  {clr('5', C.PURPLE)}  Phase 1  — Static analysis (APK, manifest, smali)
  {clr('6', C.PURPLE)}  Phase 2  — URI schemes and IPC channels
  {clr('7', C.PURPLE)}  Phase 3  — Dynamic setup (checklist + Frida)
  {clr('8', C.CYAN)}   Phase 4  — Network analysis (Zeek / pcap)
  {clr('9', C.YELLOW)} Phase 5  — Correlation and finding classification
  {clr('10', C.YELLOW)} Phase 6  — Enforcement rule generation
  {clr('11', C.YELLOW)} Phase 7  — Report and disclosure

  {bold('FINDINGS')}
  {clr('12', C.GREEN)}  View current findings
  {clr('13', C.GREEN)}  Add manual finding
  {clr('14', C.GREEN)}  Modify finding classification

  {clr('0', C.GRAY)}   Exit
""")
    return input(f"  {clr('▶', C.BLUE)} ").strip()

# ─── Tab completion for file paths ───────────────────────────────
def _enable_tab_completion():
    try:
        import readline
        import glob
        def completer(text, state):
            matches = glob.glob(text + '*')
            return matches[state] if state < len(matches) else None
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass   # readline not available on all platforms (e.g. Windows)

_enable_tab_completion()


# ─── XAPK / APKS handler ─────────────────────────────────────────
def resolve_apk(input_path: str) -> tuple:
    """
    Accepts .apk, .xapk, or .apks input.
    XAPK and APKS are ZIP archives — extracts the base APK automatically.
    Returns (apk_path, apk_name, notes) or (None, None, error_msg).
    """
    ap = Path(input_path.strip("'\"").rstrip("/"))

    # ── If user passed a directory: look for APK files inside ────
    if ap.is_dir():
        candidates = (
            list(ap.glob("*.apk")) +
            list(ap.glob("*.xapk")) +
            list(ap.glob("*.apks"))
        )
        if not candidates:
            return None, None, f"Directory contains no APK/XAPK/APKS files: {ap}"
        if len(candidates) == 1:
            info(f"Found: {candidates[0].name}")
            ap = candidates[0]
        else:
            print(f"\n  {bold('Multiple APK files found — choose one:')}")
            for i, c in enumerate(candidates, 1):
                size = round(c.stat().st_size / 1024 / 1024, 1)
                print(f"  {clr(str(i), C.CYAN)}  {c.name}  {clr(f'({size} MB)', C.GRAY)}")
            choice = input(f"  {clr('▶', C.BLUE)} ").strip()
            try:
                ap = candidates[int(choice) - 1]
            except (ValueError, IndexError):
                return None, None, "Invalid selection."

    if not ap.exists():
        return None, None, f"File not found: {ap}"

    suffix = ap.suffix.lower()

    # Standard APK — pass through
    if suffix == ".apk":
        return str(ap.resolve()), ap.name, None

    # XAPK or APKS — both are ZIP archives
    if suffix in (".xapk", ".apks"):
        import zipfile
        if not zipfile.is_zipfile(ap):
            return None, None, f"{suffix.upper()} file is not a valid ZIP archive"

        extract_dir = ap.parent / f"{ap.stem}_extracted"
        extract_dir.mkdir(exist_ok=True)

        with zipfile.ZipFile(ap) as z:
            members = z.namelist()
            info(f"Archive contents: {members}")

            apk_members = [m for m in members if m.endswith('.apk')]
            if not apk_members:
                return None, None, f"No .apk found inside {suffix.upper()} archive"

            # Prefer base.apk, otherwise pick the largest
            base = next((m for m in apk_members if 'base' in m.lower()), None)
            if not base:
                sizes = {m: z.getinfo(m).file_size for m in apk_members}
                base  = max(sizes, key=sizes.get)

            out_path = extract_dir / Path(base).name
            with z.open(base) as src, open(out_path, 'wb') as dst:
                dst.write(src.read())

            ok(f"Extracted base APK: {out_path.name}")

            splits = [m for m in apk_members if m != base]
            if splits:
                info(f"Split APKs (for reference): {splits}")

        return str(out_path.resolve()), out_path.name, f"Extracted from {ap.name}"

    return None, None, (
        f"Unsupported format: '{ap.suffix}' (supported: .apk, .xapk, .apks)\n"
        f"  Did you mean to pass a directory? Try: {ap.parent}/"
    )


# ─── 1. New workspace ─────────────────────────────────────────
def new_workspace():
    print_banner()
    print(f"  {bold('NEW WORKSPACE')}\n")
    name = input(f"  Analysis name {clr('(e.g. graveyard-empire-v2.1)', C.GRAY)}: ").strip()
    if not name:
        err("Invalid name.")
        input("  Press enter to continue...")
        return

    # filesystem-safe slug
    slug = name.lower().replace(" ", "-").replace("/", "-")
    slug = "".join(c if c.isalnum() or c == "-" else "-" for c in slug)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    ws   = WORKSPACE_ROOT / f"{ts}_{slug}"

    # Guard against collision (should not happen with seconds, but be safe)
    suffix = 0
    while ws.exists():
        suffix += 1
        ws = WORKSPACE_ROOT / f"{ts}_{slug}_{suffix}"

    # Create workspace directories
    ws.mkdir(parents=True, exist_ok=True)
    for subdir in ("static", "dynamic", "network", "rules", "report"):
        (ws / subdir).mkdir(exist_ok=True)

    # apk / xapk / apks
    apk_input = input(f"  APK path {clr('(.apk / .xapk / .apks — press enter to skip)', C.GRAY)}: ").strip()
    apk_path  = None
    apk_name  = None
    if apk_input:
        apk_path, apk_name, note = resolve_apk(apk_input)
        if apk_path:
            if note:
                info(note)
        else:
            warn(f"Could not resolve APK: {note} — you can set it later.")

    session["workspace"]  = ws
    session["apk_path"]   = apk_path
    session["apk_name"]   = apk_name
    session["hypothesis"] = None
    session["phase"]      = 0
    session["findings"]   = []
    save_session()

    ok(f"Workspace created: {ws}")
    info("Structure: static/ dynamic/ network/ rules/ report/")
    input("  Press enter to continue...")

# ─── 2. Open workspace ──────────────────────────────────────────
def open_workspace():
    print_banner()
    print(f"  {bold('OPEN WORKSPACE')}\n")
    workspaces = sorted(WORKSPACE_ROOT.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not workspaces:
        warn("No workspaces found.")
        input("  Press enter to continue...")
        return

    for i, ws in enumerate(workspaces[:15], 1):
        meta = ws / "meta.json"
        apk  = ""
        phase = "0"
        if meta.exists():
            try:
                d = json.loads(meta.read_text())
                apk   = d.get("apk_name", "")
                phase = str(d.get("phase", 0))
            except Exception:
                pass
        nf = len(list(ws.glob("findings.jsonl")))
        print(f"  {clr(str(i), C.CYAN)}  {bold(ws.name)}"
              f"  {clr(apk, C.GRAY)}  phase {phase}")

    choice = input(f"\n  {clr('▶', C.BLUE)} Number: ").strip()
    try:
        ws = workspaces[int(choice) - 1]
        load_workspace(ws)
    except (ValueError, IndexError):
        err("Invalid choice.")
    input("  Press enter to continue...")

# ─── 3. List workspaces ─────────────────────────────────────────
def list_workspaces():
    print_banner()
    print(f"  {bold('EXISTING WORKSPACES')}\n")
    workspaces = sorted(WORKSPACE_ROOT.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not workspaces:
        warn("No workspaces found.")
    for ws in workspaces:
        findings_count = 0
        fp = ws / "findings.jsonl"
        if fp.exists():
            findings_count = sum(1 for _ in fp.open())
        meta = ws / "meta.json"
        apk  = ""
        if meta.exists():
            try:
                apk = json.loads(meta.read_text()).get("apk_name", "")
            except Exception:
                pass
        mtime = datetime.fromtimestamp(ws.stat().st_mtime).strftime("%d/%m %H:%M")
        print(f"  {clr(mtime, C.GRAY)}  {bold(ws.name)}"
              f"  {clr(apk or '—', C.GRAY)}"
              f"  {clr(str(findings_count) + ' findings', C.GREEN if findings_count else C.GRAY)}")
    input("\n  Press enter to continue...")

# ─── helper: requires active workspace ──────────────────────────
def require_workspace():
    if not session["workspace"]:
        warn("No active workspace. Create or open a workspace first.")
        input("  Press enter to continue...")
        return False
    return True

# ─── PHASE 0: Intake and Threat Hypothesis ─────────────────────────
def phase0_intake():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 0 — INTAKE AND THREAT HYPOTHESIS')}\n")
    print(f"  {clr('Before touching the code. Formulate the hypothesis.', C.DIM)}\n")

    # APK se non impostato
    if not session["apk_path"]:
        apk_input = input(f"  APK path: ").strip()
        if apk_input:
            ap = Path(apk_input.strip("'\""))
            if ap.exists():
                session["apk_path"] = str(ap.resolve())
                session["apk_name"] = ap.name
                save_session()

    sep()
    print(f"  {bold('APPLICATION METADATA')}")
    fields = {
        "app_name":      "Application name",
        "developer":     "Developer / Entity",
        "category":      "Play Store category",
        "version":       "Version analysed",
        "apk_sha256":    "APK SHA-256",
        "declared_size": "Declared size (MB)",
        "actual_size":   "Actual APK size (MB)",
        "permissions":   "Anomalous permissions detected",
        "sdks":          "SDK dependencies identified",
    }
    meta_out = {}
    for key, label in fields.items():
        val = input(f"  {clr(label, C.CYAN)}: ").strip()
        if val:
            meta_out[key] = val

    # auto-calculate size delta if APK present
    if session.get("apk_path"):
        ap = Path(session["apk_path"])
        if ap.exists():
            actual_mb = round(ap.stat().st_size / 1024 / 1024, 2)
            info(f"APK size detected automatically: {bold(str(actual_mb))} MB")
            meta_out["actual_size_auto"] = actual_mb

    sep()
    print(f"\n  {bold('THREAT HYPOTHESIS')}")
    print(f"  {clr('Describe in natural language what you suspect.', C.DIM)}")
    print(f"  {clr('Example: \"I suspect this app collects device data', C.DIM)}")
    print(f"  {clr('  via SDK-level bypass invisible to the network layer.\"', C.DIM)}\n")
    hypothesis = input(f"  {clr('Primary hypothesis', C.YELLOW)}: ").strip()

    sep()
    print(f"\n  {bold('FALSIFICATION CRITERIA')}")
    print(f"  {clr('When can you say the hypothesis is WRONG?', C.DIM)}\n")
    null_hypothesis = input(f"  {clr('Null hypothesis', C.GRAY)}: ").strip()

    sep()
    print(f"\n  {bold('SUSPICION TRIGGERS')}")
    print(f"  {clr('What triggered this analysis?', C.DIM)}\n")
    triggers = []
    print(f"  {clr('Enter triggers (empty enter to finish):', C.GRAY)}")
    while True:
        t = input(f"  {clr('+', C.GREEN)} ").strip()
        if not t: break
        triggers.append(t)

    # save all
    session["hypothesis"] = hypothesis
    session["phase"] = max(session["phase"], 1)

    out = {
        "phase": 0,
        "timestamp": datetime.now().isoformat(),
        "metadata": meta_out,
        "hypothesis": hypothesis,
        "null_hypothesis": null_hypothesis,
        "triggers": triggers,
    }
    out_path = session["workspace"] / "static" / "phase0_intake.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    save_session()
    ok(f"Intake saved: {out_path.name}")
    info("Recommended next step: Phase 1 — Static analysis")
    input("  Press enter to continue...")

# ─── PHASE 1: Static Analysis ─────────────────────────────────────
def phase1_static():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 1 — STATIC ANALYSIS')}\n")

    if not session.get("apk_path"):
        warn("APK not set in workspace.")
        apk_input = input(f"  APK path {clr('(.apk / .xapk / .apks)', C.GRAY)}: ").strip()
        if not apk_input: return
        apk_path, apk_name, note = resolve_apk(apk_input)
        if not apk_path:
            err(f"Could not resolve APK: {note}")
            input("  Press enter to continue...")
            return
        if note:
            info(note)
        session["apk_path"] = apk_path
        session["apk_name"] = apk_name
        save_session()

    apk = Path(session["apk_path"])
    static_dir = session["workspace"] / "static"

    sep()
    print(f"  {bold('APK')}")
    info(f"File:   {apk}")
    info(f"Size:   {round(apk.stat().st_size / 1024 / 1024, 2)} MB")
    info(f"Suffix: {apk.suffix.lower()}")

    sep()
    print(f"  {bold('TOOLS DETECTED')}")
    tools = {
        "apktool":  shutil.which("apktool"),
        "jadx":     shutil.which("jadx"),
        "aapt2":    shutil.which("aapt2"),
        "strings":  shutil.which("strings"),
        "readelf":  shutil.which("readelf"),
    }
    critical_missing = []
    for tool, path in tools.items():
        if path:
            ok(f"{tool}: {clr(path, C.GRAY)}")
        else:
            warn(f"{tool}: {clr('not found', C.RED)}")
            if tool in ("apktool", "jadx"):
                critical_missing.append(tool)

    if critical_missing:
        sep()
        err(f"Critical tools missing: {', '.join(critical_missing)}")
        info("Operations 1-4 and 'Run all' will not produce results without apktool.")
        info("Install apktool: sudo apt install apktool  OR  https://apktool.org")

    sep()
    print(f"\n  {bold('AVAILABLE OPERATIONS')}\n")
    print(f"  {clr('1', C.CYAN)}  Decompile APK with apktool")
    print(f"  {clr('2', C.CYAN)}  Decompile APK with jadx (Java source)")
    print(f"  {clr('3', C.PURPLE)}  Extract and analyse AndroidManifest.xml")
    print(f"  {clr('4', C.PURPLE)}  URI scheme scanner (manifest + smali)")
    print(f"  {clr('5', C.PURPLE)}  SDK fingerprint (smali class names)")
    print(f"  {clr('6', C.PURPLE)}  Size delta (declared vs actual)")
    print(f"  {clr('7', C.PURPLE)}  List native .so files")
    print(f"  {clr('8', C.YELLOW)}  Run all operations")
    print(f"  {clr('0', C.GRAY)}   Back to main menu\n")

    choice = input(f"  {clr('▶', C.BLUE)} ").strip()

    if choice == "1":
        _run_apktool(apk, static_dir)
    elif choice == "2":
        _run_jadx(apk, static_dir)
    elif choice == "3":
        _analyze_manifest(static_dir)
    elif choice == "4":
        _scan_uri_schemes(static_dir)
    elif choice == "5":
        _sdk_fingerprint(static_dir)
    elif choice == "6":
        _size_delta(apk)
    elif choice == "7":
        _list_native_libs(static_dir)
    elif choice == "8":
        _run_apktool(apk, static_dir)
        _analyze_manifest(static_dir)
        _scan_uri_schemes(static_dir)
        _sdk_fingerprint(static_dir)
        _size_delta(apk)
        _list_native_libs(static_dir)
    elif choice == "0":
        return

    session["phase"] = max(session["phase"], 2)
    save_session()
    input("\n  Press enter to continue...")

def _run_apktool(apk, static_dir):
    sep()
    print(f"\n  {bold('APKTOOL — DECOMPILATION')}")

    # Check apktool is available before attempting anything
    apktool_bin = shutil.which("apktool")
    if not apktool_bin:
        err("apktool not found in PATH.")
        info("Install: https://apktool.org  |  apt install apktool  |  brew install apktool")
        info(f"Current PATH: {__import__('os').environ.get('PATH','(empty)')}")
        return

    info(f"apktool: {apktool_bin}")
    info(f"APK:     {apk}  ({round(apk.stat().st_size/1024/1024,1)} MB)")

    out_dir = static_dir / "apktool_out"
    if out_dir.exists():
        overwrite = input(f"  Output already exists. Overwrite? {clr('[y/N]', C.GRAY)}: ").strip().lower()
        if overwrite not in ('y', 'Y'):
            info("Operation skipped.")
            return
        shutil.rmtree(out_dir)

    info("Decompiling — this may take 30-120 seconds for large APKs...")
    try:
        result = subprocess.run(
            [apktool_bin, "d", str(apk), "-o", str(out_dir), "-f", "--no-debug-info"],
            capture_output=True, text=True, timeout=300
        )
    except FileNotFoundError:
        err(f"apktool binary not executable: {apktool_bin}")
        return
    except subprocess.TimeoutExpired:
        err("apktool timed out after 5 minutes.")
        return

    if result.returncode == 0:
        ok(f"Output: {out_dir}")
        smali_count = len(list(out_dir.rglob("*.smali")))
        ok(f"Smali files extracted: {bold(str(smali_count))}")
        if smali_count == 0:
            warn("0 smali files — APK may be corrupt or heavily obfuscated.")
            warn(f"Try: apktool d \"{apk}\" -o {out_dir} -f")
    else:
        err("apktool failed:")
        print(f"  {clr(result.stderr[:600], C.RED)}")
        if result.stdout:
            print(f"  stdout: {result.stdout[:200]}")

def _run_jadx(apk, static_dir):
    sep()
    print(f"\n  {bold('JADX — JAVA SOURCE')}")

    jadx_bin = shutil.which("jadx")
    if not jadx_bin:
        err("jadx not found in PATH.")
        info("Install: https://github.com/skylot/jadx/releases  |  brew install jadx")
        return

    info(f"jadx: {jadx_bin}")
    out_dir = static_dir / "jadx_out"
    if out_dir.exists():
        overwrite = input(f"  Output already exists. Overwrite? {clr('[y/N]', C.GRAY)}: ").strip().lower()
        if overwrite not in ('y', 'Y'):
            info("Operation skipped.")
            return
        shutil.rmtree(out_dir)

    info("Recovering Java source — this may take 60-180 seconds...")
    try:
        result = subprocess.run(
            [jadx_bin, "-d", str(out_dir), "--no-res", "--show-bad-code", str(apk)],
            capture_output=True, text=True, timeout=600
        )
    except FileNotFoundError:
        err(f"jadx binary not executable: {jadx_bin}")
        return
    except subprocess.TimeoutExpired:
        err("jadx timed out after 10 minutes.")
        return

    java_count = len(list(out_dir.rglob("*.java"))) if out_dir.exists() else 0
    if java_count > 0:
        ok(f"Java files recovered: {bold(str(java_count))}")
        ok(f"Output: {out_dir}")
    else:
        warn("jadx completed with 0 Java files.")
        if result.stderr:
            print(f"  stderr: {clr(result.stderr[:400], C.YELLOW)}")

def _analyze_manifest(static_dir):
    sep()
    print(f"\n  {bold('ANDROIDMANIFEST.XML — ANALYSIS')}")
    manifest = static_dir / "apktool_out" / "AndroidManifest.xml"
    if not manifest.exists():
        warn("Manifest not found. Run apktool first (option 1).")
        return

    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        findings = {
            "permissions": [],
            "exported_components": [],
            "intent_filters": [],
            "custom_schemes": [],
            "meta_data": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        # permissions
        for perm in root.findall(".//uses-permission"):
            name = perm.get("{http://schemas.android.com/apk/res/android}name", "")
            findings["permissions"].append(name)

        # componenti esportati
        for tag in ["activity", "service", "receiver", "provider"]:
            for el in root.findall(f".//{tag}"):
                exported = el.get("{http://schemas.android.com/apk/res/android}exported", "")
                name     = el.get("{http://schemas.android.com/apk/res/android}name", "")
                if tag == "service":   findings["services"].append(name)
                if tag == "receiver":  findings["receivers"].append(name)
                if tag == "provider":  findings["providers"].append(name)
                if exported == "true":
                    findings["exported_components"].append({"tag": tag, "name": name})

                # intent filters con scheme custom
                for intent_filter in el.findall(".//intent-filter"):
                    for data in intent_filter.findall(".//data"):
                        scheme = data.get("{http://schemas.android.com/apk/res/android}scheme", "")
                        if scheme and scheme not in ["http", "https", "ftp", "content", "file", "android"]:
                            findings["custom_schemes"].append({
                                "scheme": scheme,
                                "component": name,
                                "component_type": tag
                            })

        # meta-data
        for meta in root.findall(".//meta-data"):
            mname  = meta.get("{http://schemas.android.com/apk/res/android}name", "")
            mvalue = meta.get("{http://schemas.android.com/apk/res/android}value", "")
            if mname:
                findings["meta_data"].append({"name": mname, "value": mvalue})

        # output
        print(f"\n  {clr('DECLARED PERMISSIONS', C.BOLD)} ({len(findings['permissions'])})")
        dangerous = ["READ_CONTACTS","READ_PHONE_STATE","ACCESS_FINE_LOCATION",
                     "RECORD_AUDIO","READ_CALL_LOG","GET_ACCOUNTS","CAMERA",
                     "READ_SMS","QUERY_ALL_PACKAGES","PACKAGE_USAGE_STATS"]
        for p in findings["permissions"]:
            short = p.replace("android.permission.", "")
            if any(d in p for d in dangerous):
                print(f"    {clr('!', C.YELLOW)} {bold(short)}")
            else:
                print(f"    {clr('·', C.GRAY)} {short}")

        print(f"\n  {clr('EXPORTED COMPONENTS', C.BOLD)} ({len(findings['exported_components'])})")
        for c in findings["exported_components"]:
            print(f"    {clr('!', C.YELLOW)} [{c['tag']}] {c['name']}")

        print(f"\n  {clr('CUSTOM URI SCHEMES', C.BOLD)} ({len(findings['custom_schemes'])})")
        for s in findings["custom_schemes"]:
            print(f"    {clr('!!!', C.RED)} {bold(s['scheme'] + '://')}  [{s['component_type']}] {s['component']}")
            # auto-finding
            add_finding(
                phase=1,
                technique="GAMA-T001",
                description=f"URI scheme custom registrato: {s['scheme']}://",
                evidence=f"AndroidManifest.xml — {s['component_type']}: {s['component']}",
                classification="hypothesis"
            )

        print(f"\n  {clr('META-DATA', C.BOLD)} ({len(findings['meta_data'])})")
        for m in findings["meta_data"][:20]:
            val_display = m['value'][:60] if m['value'] else clr("(no value)", C.GRAY)
            print(f"    {clr('·', C.GRAY)} {m['name'][:50]}  =  {val_display}")

        # save output
        out_path = static_dir / "manifest_analysis.json"
        with open(out_path, "w") as f:
            json.dump(findings, f, indent=2)
        ok(f"\n  Analysis saved: {out_path.name}")

    except ET.ParseError as e:
        err(f"XML parse error: {e}")

def _scan_uri_schemes(static_dir):
    """
    Universal URI scheme scanner.
    Cerca QUALSIASI pattern ://  — non firme note.
    La logica classifica per contesto, non per nome.
    Questo trova le mutazioni sconosciute, non solo i casi documentati.
    """
    sep()
    print(f"\n  {bold('URI SCHEME SCANNER — LOGIC, NOT SIGNATURES')}")
    print(f"  {clr('Scans every :// in code. Classification by context, not by name.', C.DIM)}\n")

    smali_dir = static_dir / "apktool_out"
    if not smali_dir.exists():
        warn("Directory apktool_out non trovata. Run apktool first.")
        return

    import re

    # ── cosa consideriamo "noto e benigno" ───────────────────────
    # These are not removed — kept separate to avoid pollutirati to avoid
    # polluting l'output. L'analyst can still view them.
    SYSTEM_SCHEMES = {
        "http", "https", "ftp", "ftps", "content", "file",
        "android", "intent", "market", "mailto", "tel", "sms",
        "geo", "mms", "voicemail", "xmpp", "rtsp", "blob",
        "data", "javascript", "about", "ws", "wss",
    }

    # ── pattern: cattura scheme://qualcosa ───────────────────────
    # Searches strings, smali annotations, constant values.
    # Not limited to quoted strings — also checks .field, const-string etc.
    SCHEME_RE = re.compile(
        r'(?:const-string[^"]*"|["\']|[=\(,\s])'
        r'([a-zA-Z][a-zA-Z0-9+\-._]{1,30})'   # underscore added: wv_hybrid, fb_sdk etc.
        r'://'
        r'([^\s"\'\\<>]{0,120})',
        re.MULTILINE
    )

    # ── pattern: metodi che gestiscono URL/scheme ────────────────
    HANDLER_RE = re.compile(
        r'(shouldOverrideUrlLoading|shouldInterceptRequest'
        r'|loadUrl|evaluateJavascript|addJavascriptInterface'
        r'|handleIntent|parseUri|Uri\.parse|Uri\.fromString'
        r'|Intent\.parseUri|startActivity|getScheme\(\))',
        re.IGNORECASE
    )

    # ── counters and collectors ─────────────────────────────────
    all_schemes   = {}   # scheme -> [{file, line, context, full_match}]
    handler_hits  = []   # file con metodi di gestione URL
    base64_schemes = []  # scheme trovati dopo decode base64 (se presenti)

    smali_files = list(smali_dir.rglob("*.smali"))
    info(f"Universal scan of {bold(str(len(smali_files)))} smali files...")

    for sf in smali_files:
        try:
            text  = sf.read_text(errors="ignore")
            lines = text.splitlines()
            rel   = str(sf.relative_to(static_dir))

            # ── cerca ://  ───────────────────────────────────────
            for match in SCHEME_RE.finditer(text):
                scheme   = match.group(1).lower()
                path_ctx = match.group(2)[:60] if match.group(2) else ""
                full     = match.group(0)[:80]

                # trova numero di riga approssimativo
                pos  = match.start()
                line_no = text[:pos].count("\n") + 1

                entry = {
                    "file":    rel,
                    "line":    line_no,
                    "context": path_ctx,
                    "snippet": full.strip(),
                }
                if scheme not in all_schemes:
                    all_schemes[scheme] = []
                all_schemes[scheme].append(entry)

            # ── cerca handler methods ────────────────────────────
            for match in HANDLER_RE.finditer(text):
                line_no = text[:match.start()].count("\n") + 1
                handler_hits.append({
                    "method": match.group(1),
                    "file":   rel,
                    "line":   line_no,
                })

            # ── cerca stringhe Base64 che contengono :// ─────────
            import base64 as b64mod
            b64_re = re.compile(r'[A-Za-z0-9+/]{16,}={0,3}')  # fixed: 16 min, include ==
            for b64match in b64_re.finditer(text):
                raw = b64match.group(0)
                decoded = None
                for attempt in [raw, raw + "=", raw + "=="]:
                    try:
                        decoded = b64mod.b64decode(attempt).decode("utf-8", errors="ignore")
                        break
                    except Exception:
                        continue
                if decoded and "://" in decoded:
                    line_no = text[:b64match.start()].count("\n") + 1
                    base64_schemes.append({
                        "file":    rel,
                        "line":    line_no,
                        "decoded": decoded[:120],
                        "raw":     raw[:40] + "...",
                    })

        except Exception:
            pass

    # ── logic-based classification ───────────────────────────────
    # Non "is mv://" — ma "these properties make it suspicious"
    def suspicion_score(scheme, occurrences):
        score  = 0
        notes  = []

        # 1. Non è un sistema noto → sospetto base
        if scheme not in SYSTEM_SCHEMES:
            score += 3
            notes.append("schema non-standard")

        # 2. Molto corto (2-4 char) → probabilmente custom SDK
        if len(scheme) <= 4 and scheme not in SYSTEM_SCHEMES:
            score += 2
            notes.append(f"short name ({len(scheme)} chars) — typical custom SDK")

        # 3. Appare in file sotto percorsi di SDK noti
        sdk_paths = ["mbridge","mintegral","unity","adjust","appsflyer",
                     "firebase","moloco","bytedance","pangle","ironsource",
                     "applovin","vungle","inmobi","tapjoy","chartboost"]
        sdk_files = [o["file"] for o in occurrences
                     if any(s in o["file"].lower() for s in sdk_paths)]
        if sdk_files:
            score += 3
            notes.append(f"found in SDK path ({sdk_files[0].split('/')[1] if '/' in sdk_files[0] else sdk_files[0]})")

        # 4. Alta frequenza in distinct files → usato come canale
        n_files = len(set(o["file"] for o in occurrences))
        if n_files >= 5:
            score += 2
            notes.append(f"found in {n_files} distinct files")
        elif n_files >= 2:
            score += 1

        # 5. Il contesto contiene termini di tracking/ad
        tracking_terms = ["uid","did","device","track","click","install",
                          "event","session","user","ad","impression","bid"]
        ctx_blob = " ".join(o.get("context","") for o in occurrences).lower()
        matched_terms = [t for t in tracking_terms if t in ctx_blob]
        if matched_terms:
            score += len(matched_terms)
            notes.append(f"tracking context: {', '.join(matched_terms[:3])}")

        # 6. Appare vicino a handler methods (WebView ecc.)
        scheme_files = set(o["file"] for o in occurrences)
        handler_files = set(h["file"] for h in handler_hits)
        overlap = scheme_files & handler_files
        if overlap:
            score += 3
            notes.append("co-located with WebView/Intent handler")

        return score, notes

    # ── separation: system / unknown / suspicious ───────────────
    system_found   = {}
    unknown_found  = {}
    suspicious     = {}

    for scheme, occs in all_schemes.items():
        score, notes = suspicion_score(scheme, occs)
        entry = {"occurrences": occs, "score": score, "notes": notes}
        if scheme in SYSTEM_SCHEMES:
            system_found[scheme] = entry
        elif score >= 5:
            suspicious[scheme] = entry
        else:
            unknown_found[scheme] = entry

    # ── output ───────────────────────────────────────────────────
    print(f"  {clr('SUSPICIOUS SCHEMES (score ≥ 5)', C.RED)}  "
          f"{clr('— GAMA-T001 candidates', C.DIM)}\n")

    if not suspicious:
        ok("No high-score schemes. Check the 'unknown' section.")
    else:
        for scheme, data in sorted(suspicious.items(),
                                   key=lambda x: x[1]["score"], reverse=True):
            score = data["score"]
            notes = data["notes"]
            occs  = data["occurrences"]
            n_files = len(set(o["file"] for o in occs))
            print(f"  {clr('!!!', C.RED)} {bold(scheme + '://')}  "
                  f"{clr(f'score={score}', C.RED)}  "
                  f"{clr(f'{len(occs)} occurrences in {n_files} file', C.GRAY)}")
            for note in notes:
                print(f"       {clr('→', C.YELLOW)} {note}")
            # mostra prime more occurrences con snippet
            for occ in occs[:2]:
                print(f"       {clr(occ['file'][:65], C.GRAY)}:{occ['line']}")
                if occ.get("snippet"):
                    print(f"         {clr(occ['snippet'], C.DIM)}")
            if len(occs) > 2:
                print(f"       {clr(f'... and {len(occs)-2} more occurrences', C.GRAY)}")
            print()

            # auto-finding for very high score
            if score >= 7:
                add_finding(
                    phase=1,
                    technique="GAMA-T001",
                    description=f"High-suspicion URI scheme: {scheme}://  (score={score})",
                    evidence=f"{len(occs)} occurrences in {n_files} file — signals: {'; '.join(notes)}",
                    classification="hypothesis"
                )

    print(f"  {clr('UNCLASSIFIED SCHEMES (score < 5)', C.YELLOW)}  "
          f"{clr('— review manually', C.DIM)}\n")
    for scheme, data in sorted(unknown_found.items(),
                               key=lambda x: x[1]["score"], reverse=True):
        occs   = data["occurrences"]
        score  = data["score"]
        n_files = len(set(o["file"] for o in occs))
        print(f"  {clr('?', C.YELLOW)} {scheme + '://':<25}  "
              f"score={score}  "
              f"{clr(f'{len(occs)}x / {n_files} file', C.GRAY)}")

    print(f"\n  {clr('SYSTEM SCHEMES FOUND', C.GRAY)}  "
          f"{clr('(count only)', C.DIM)}")
    for scheme in sorted(system_found.keys()):
        n = len(system_found[scheme]["occurrences"])
        print(f"  {clr('·', C.GRAY)} {scheme + '://':<20} {n}x")

    # ── Base64 encoded schemes ───────────────────────────────────
    if base64_schemes:
        print(f"\n  {clr('SCHEMES FOUND IN BASE64 STRINGS', C.RED)}  "
              f"{clr('— obfuscation active', C.DIM)}\n")
        for item in base64_schemes[:10]:
            print(f"  {clr('!!!', C.RED)} {item['file']}:{item['line']}")
            print(f"       decoded: {clr(item['decoded'][:100], C.YELLOW)}")
            add_finding(
                phase=1,
                technique="GAMA-T001",
                description=f"URI scheme found in Base64 string — possible obfuscation",
                evidence=f"{item['file']}:{item['line']} — decoded: {item['decoded'][:80]}",
                classification="hypothesis"
            )

    # ── WebView/Intent handler hits ──────────────────────────────
    print(f"\n  {clr('HANDLER METHODS (WebView/Intent)', C.BOLD)}\n")
    seen_handlers = set()
    for h in handler_hits:
        key = f"{h['method']}::{h['file']}"
        if key not in seen_handlers:
            seen_handlers.add(key)
            print(f"  {clr('!', C.YELLOW)} {h['method']:<35}  "
                  f"{clr(h['file'][:60], C.GRAY)}:{h['line']}")

    # ── save all results ──────────────────────────────────────────────
    results = {
        "scan_type":      "universal_logic_based",
        "total_schemes":  len(all_schemes),
        "suspicious":     {k: {**v, "occurrences": v["occurrences"][:10]}
                           for k, v in suspicious.items()},
        "unknown":        {k: {"score": v["score"], "count": len(v["occurrences"])}
                           for k, v in unknown_found.items()},
        "system":         {k: len(v["occurrences"]) for k, v in system_found.items()},
        "base64_encoded": base64_schemes[:20],
        "handler_methods": handler_hits[:50],
    }
    out_path = static_dir / "uri_scheme_scan.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    ok(f"\n  Results saved: {out_path.name}")
    info(f"Total schemes found: {len(all_schemes)}  "
         f"(suspicious: {len(suspicious)}, unclassified: {len(unknown_found)}, system: {len(system_found)})")

def _sdk_fingerprint(static_dir):
    sep()
    print(f"\n  {bold('SDK FINGERPRINT')}")
    smali_dir = static_dir / "apktool_out"
    if not smali_dir.exists():
        warn("Directory apktool_out non trovata. Run apktool first.")
        return

    SDK_SIGNATURES = {
        "Mintegral / MBridge":  ["com/mbridge", "com/mobvista"],
        "Unity Ads":             ["com/unity3d/ads", "unity3d/services"],
        "Adjust":                ["com/adjust/sdk"],
        "AppsFlyer":             ["com/appsflyer"],
        "Firebase / Google":     ["com/google/firebase", "com/google/android/gms"],
        "Moloco":                ["com/moloco"],
        "IronSource":            ["com/ironsource"],
        "AppLovin":              ["com/applovin"],
        "Chartboost":            ["com/chartboost"],
        "AdColony":              ["com/adcolony"],
        "Vungle / Liftoff":      ["com/vungle"],
        "InMobi":                ["com/inmobi"],
        "Smaato":                ["com/smaato"],
        "Tapjoy":                ["com/tapjoy"],
        "Fyber":                 ["com/fyber"],
        "MoPub":                 ["com/mopub"],
        "TikTok / Pangle":       ["com/bytedance/sdk", "com/pangle"],
        "Yandex Metrica":        ["com/yandex/metrica"],
        "Amplitude":             ["com/amplitude"],
        "Mixpanel":              ["com/mixpanel"],
        "Branch":                ["io/branch"],
        "Leanplum":              ["com/leanplum"],
        "OneSignal":             ["com/onesignal"],
        "Crashlytics":           ["com/crashlytics"],
        "Sentry":                ["io/sentry"],
    }

    found_sdks = {}
    smali_paths = [str(p) for p in (static_dir / "apktool_out").rglob("*.smali")]
    path_blob   = "\n".join(smali_paths)

    for sdk_name, patterns in SDK_SIGNATURES.items():
        hits = []
        for pat in patterns:
            if pat in path_blob:
                hits.append(pat)
        if hits:
            found_sdks[sdk_name] = hits

    print(f"\n  {clr('IDENTIFIED SDKs', C.BOLD)} ({len(found_sdks)})\n")
    ad_sdks     = ["Mintegral / MBridge","Unity Ads","Moloco","IronSource","AppLovin",
                   "Chartboost","AdColony","Vungle / Liftoff","InMobi","Smaato",
                   "Tapjoy","Fyber","MoPub","TikTok / Pangle"]
    tracking    = ["Adjust","AppsFlyer","Yandex Metrica","Amplitude","Mixpanel",
                   "Branch","Leanplum"]

    for sdk, patterns in sorted(found_sdks.items()):
        if sdk in ad_sdks:
            icon = clr("AD ", C.RED)
        elif sdk in tracking:
            icon = clr("TRK", C.YELLOW)
        else:
            icon = clr("LIB", C.GRAY)
        print(f"    {icon}  {bold(sdk)}")
        for p in patterns:
            print(f"         {clr(p, C.GRAY)}")

    out_path = static_dir / "sdk_fingerprint.json"
    with open(out_path, "w") as f:
        json.dump(found_sdks, f, indent=2)
    ok(f"\n  Results saved: {out_path.name}")

def _size_delta(apk):
    sep()
    print(f"\n  {bold('SIZE DELTA ANALYSIS')}")
    actual_mb = round(apk.stat().st_size / 1024 / 1024, 2)
    print(f"  Actual APK: {bold(str(actual_mb))} MB")
    declared = input(f"  Declared size on Play Store (MB, enter to skip): ").strip()
    if declared:
        try:
            dec_mb = float(declared)
            delta  = actual_mb - dec_mb
            pct    = (delta / dec_mb) * 100 if dec_mb > 0 else 0
            print(f"  Delta: {bold(str(round(delta, 2)))} MB  ({round(pct, 1)}%)")
            if pct > 20:
                warn(f"Delta > 20% — GAMA-T002 candidate (post-install payload)")
                add_finding(
                    phase=1,
                    technique="GAMA-T002",
                    description=f"Anomalous size delta: {round(pct,1)}% above declared",
                    evidence=f"APK: {actual_mb}MB, declared: {dec_mb}MB, delta: {round(delta,2)}MB",
                    classification="hypothesis"
                )
        except ValueError:
            warn("Non-numeric value.")

def _list_native_libs(static_dir):
    sep()
    print(f"\n  {bold('NATIVE LIBRARIES (.so)')}")
    lib_dir = static_dir / "apktool_out" / "lib"
    if not lib_dir.exists():
        warn("lib/ directory not found.")
        return
    so_files = list(lib_dir.rglob("*.so"))
    print(f"  {bold(str(len(so_files)))} native libraries found:\n")
    for so in sorted(so_files):
        size_kb = round(so.stat().st_size / 1024, 1)
        arch    = so.parent.name
        print(f"  {clr(arch, C.GRAY):12}  {so.name:50}  {size_kb:8.1f} KB")
    info("For deeper analysis use gama-native (Rust) or strings/readelf manually.")

# ─── PHASE 2: URI Schemes and IPC ──────────────────────────────────────────
def phase2_ipc():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 2 — URI SCHEMES AND IPC CHANNELS')}\n")
    print(f"  {clr('GAMA original contribution. Channels invisible to the network stack.', C.DIM)}\n")

    static_dir = session["workspace"] / "static"

    print(f"  {clr('1', C.CYAN)}  URI scheme summary (from Phase 1)")
    print(f"  {clr('2', C.CYAN)}  Search WebView bridge patterns in code")
    print(f"  {clr('3', C.PURPLE)}  Search cross-SDK ContentProviders")
    print(f"  {clr('4', C.PURPLE)}  Intent chain mapper")
    print(f"  {clr('5', C.YELLOW)}  Add manual finding URI/IPC")
    print(f"  {clr('0', C.GRAY)}   Back to menu\n")

    choice = input(f"  {clr('▶', C.BLUE)} ").strip()

    if choice == "1":
        _show_uri_summary(static_dir)
    elif choice == "2":
        _webview_bridge_scan(static_dir)
    elif choice == "3":
        _content_provider_scan(static_dir)
    elif choice == "4":
        _intent_chain_mapper(static_dir)
    elif choice == "5":
        _add_ipc_finding()

    session["phase"] = max(session["phase"], 3)
    save_session()
    input("\n  Press enter to continue...")

def _show_uri_summary(static_dir):
    uri_file = static_dir / "uri_scheme_scan.json"
    manifest_file = static_dir / "manifest_analysis.json"
    sep()
    print(f"\n  {bold('URI SCHEME SUMMARY')}\n")
    for f, label in [(uri_file, "From smali"), (manifest_file, "From manifest")]:
        if f.exists():
            data = json.loads(f.read_text())
            schemes = data.get("schemes_found", data.get("custom_schemes", {}))
            print(f"  {bold(label)}")
            if isinstance(schemes, dict):
                for s in schemes: print(f"    {clr('!!!', C.RED)} {bold(s+'://')}")
            elif isinstance(schemes, list):
                for s in schemes: print(f"    {clr('!!!', C.RED)} {bold(s.get('scheme','')+'://')}  — {s.get('component','')}")
        else:
            warn(f"{f.name} not found — run Phase 1 first.")

def _webview_bridge_scan(static_dir):
    sep()
    print(f"\n  {bold('WEBVIEW BRIDGE SCAN')}")
    smali_dir = static_dir / "apktool_out"
    if not smali_dir.exists():
        warn("Run apktool first (Phase 1).")
        return
    import re
    patterns = [
        (r'addJavascriptInterface', "JS Interface injection"),
        (r'evaluateJavascript',     "JS evaluation"),
        (r'loadUrl.*javascript:',   "javascript: protocol"),
        (r'setWebContentsDebuggingEnabled.*true', "WebView debug enabled"),
        (r'setAllowFileAccess.*true', "File access enabled"),
    ]
    for smali_file in smali_dir.rglob("*.smali"):
        try:
            text = smali_file.read_text(errors="ignore")
            for pattern, label in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    print(f"  {clr('!', C.YELLOW)} {bold(label)}")
                    print(f"    {clr(str(smali_file.relative_to(static_dir)), C.GRAY)}")
        except Exception:
            pass

def _content_provider_scan(static_dir):
    sep()
    print(f"\n  {bold('CROSS-SDK CONTENT PROVIDER')}")
    manifest_file = static_dir / "manifest_analysis.json"
    if not manifest_file.exists():
        warn("Run manifest analysis first (Phase 1 → option 3).")
        return
    data = json.loads(manifest_file.read_text())
    providers = data.get("providers", [])
    if providers:
        print(f"  {bold(str(len(providers)))} providers found:")
        for p in providers:
            print(f"    {clr('·', C.CYAN)} {p}")
    else:
        ok("No ContentProvider detected.")

def _intent_chain_mapper(static_dir):
    sep()
    print(f"\n  {bold('INTENT CHAIN MAPPER')}")
    info("Searches intent chains between SDK components.")
    smali_dir = static_dir / "apktool_out"
    if not smali_dir.exists():
        warn("Run apktool first.")
        return
    import re
    intent_starts = re.compile(r'new-instance.*Intent|invoke.*startActivity|invoke.*startService|invoke.*sendBroadcast')
    chains = []
    for sf in smali_dir.rglob("*.smali"):
        try:
            text = sf.read_text(errors="ignore")
            matches = intent_starts.findall(text)
            if matches:
                chains.append({"file": str(sf.relative_to(static_dir)), "count": len(matches)})
        except Exception:
            pass
    chains.sort(key=lambda x: x["count"], reverse=True)
    print(f"\n  Top 15 files by Intent invocations:")
    for c in chains[:15]:
        print(f"  {clr(str(c['count']).rjust(4), C.YELLOW)}x  {clr(c['file'], C.GRAY)}")

def _add_ipc_finding():
    sep()
    print(f"\n  {bold('ADD MANUAL IPC/URI FINDING')}\n")
    technique = input(f"  GAMA Technique {clr('[e.g. GAMA-T001]', C.GRAY)}: ").strip() or "GAMA-T001"
    description = input(f"  Description: ").strip()
    evidence    = input(f"  Evidence (file:line or note): ").strip()
    cls         = input(f"  Class {clr('[hypothesis/confirmed/Class-C/Class-D]', C.GRAY)}: ").strip() or "hypothesis"
    if description:
        add_finding(2, technique, description, evidence, cls)
        ok("Finding added.")

# ─── PHASE 3: Dynamic Setup ──────────────────────────────────────
def phase3_dynamic():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 3 — DYNAMIC ANALYSIS (SETUP AND CHECKLIST)')}\n")
    print(f"  {clr('This phase supports manual work. No forced automation.', C.DIM)}\n")

    dynamic_dir = session["workspace"] / "dynamic"

    print(f"  {clr('1', C.CYAN)}  Environment setup checklist")
    print(f"  {clr('2', C.CYAN)}  Generate Frida scripts for this workspace")
    print(f"  {clr('3', C.PURPLE)}  Manual observation log (timestamped note)")
    print(f"  {clr('4', C.PURPLE)}  Post-termination test checklist")
    print(f"  {clr('5', C.YELLOW)}  Add finding from dynamic analysis")
    print(f"  {clr('0', C.GRAY)}   Back to menu\n")

    choice = input(f"  {clr('▶', C.BLUE)} ").strip()

    if choice == "1":
        _dynamic_checklist()
    elif choice == "2":
        _generate_frida_scripts(dynamic_dir)
    elif choice == "3":
        _manual_observation_log(dynamic_dir)
    elif choice == "4":
        _termination_test_checklist()
    elif choice == "5":
        _add_dynamic_finding()

    session["phase"] = max(session["phase"], 4)
    save_session()
    input("\n  Press enter to continue...")

def _dynamic_checklist():
    sep()
    items = [
        ("Physical device with Magisk root", "Do NOT use emulator only — SDKs test the environment"),
        ("Frida server installed on device (version matching frida-tools)", "adb push frida-server /data/local/tmp/"),
        ("Dedicated AP with packet capture on all interfaces", "tcpdump -i any -w capture.pcap"),
        ("CA certificate installed for SSL inspection", "note: PIN bypass ONLY AFTER baseline capture"),
        ("Wireshark/Zeek ready for pcap analysis", ""),
        ("Full device state backup before analysis", "avoid contamination from previous analyses"),
        ("ADB authorised and stable", "adb devices"),
        ("Package name identified", f"adb shell pm list packages | grep [nome]"),
    ]
    print(f"\n  {bold('DYNAMIC ENVIRONMENT SETUP CHECKLIST')}\n")
    for item, note in items:
        done = input(f"  [ ] {bold(item)}\n      {clr(note, C.GRAY) if note else ''}\n      {clr('Completed? [y/N]', C.GRAY)}: ").strip().lower()
        if done == "s": ok("OK")
        else: warn("Pending")
        print()

def _generate_frida_scripts(dynamic_dir):
    sep()
    print(f"\n  {bold('FRIDA SCRIPT GENERATION')}\n")
    pkg = input(f"  Package name {clr('[e.g. com.example.game]', C.GRAY)}: ").strip()
    if not pkg:
        warn("Package name required.")
        return

    script_uri = f"""// GAMA Frida Script — URI Scheme Logger
// Package: {pkg}
// CenturiaLabs / ClickSafe UAE

Java.perform(function() {{
    // Hook shouldOverrideUrlLoading
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.shouldOverrideUrlLoading.overload(
        'android.webkit.WebView', 'java.lang.String'
    ).implementation = function(view, url) {{
        if (url && url.indexOf('://') !== -1) {{
            var scheme = url.split('://')[0];
            if (['http','https','ftp','content','file'].indexOf(scheme) === -1) {{
                console.log('[GAMA-T001] URI custom: ' + url);
                console.log('[GAMA-T001] Thread: ' + Java.use('java.lang.Thread').currentThread().getName());
            }}
        }}
        return this.shouldOverrideUrlLoading(view, url);
    }};

    // Hook loadUrl
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {{
        if (url && url.startsWith('javascript:')) {{
            console.log('[GAMA] WebView.loadUrl javascript: ' + url.substring(0, 200));
        }}
        return this.loadUrl(url);
    }};

    console.log('[GAMA] URI/WebView hooks attivi su {pkg}');
}});
"""

    script_ids = f"""// GAMA Frida Script — Device Identifier Collection Logger
// Package: {pkg}
// CenturiaLabs / ClickSafe UAE

Java.perform(function() {{
    var TM = Java.use('android.telephony.TelephonyManager');
    ['getDeviceId','getImei','getMeid','getSubscriberId',
     'getSimSerialNumber','getLine1Number'].forEach(function(method) {{
        try {{
            TM[method].implementation = function() {{
                var result = this[method]();
                var stack = Java.use('android.util.Log')
                    .getStackTraceString(Java.use('java.lang.Exception').$new());
                console.log('[GAMA-ID] ' + method + '() -> ' + result);
                console.log('[GAMA-ID] Chiamante: ' + stack.split('\\n')[3]);
                return result;
            }};
        }} catch(e) {{ }}
    }});

    // Settings.Secure (ANDROID_ID)
    var Settings = Java.use('android.provider.Settings$Secure');
    Settings.getString.implementation = function(resolver, name) {{
        var result = this.getString(resolver, name);
        if (name === 'android_id') {{
            console.log('[GAMA-ID] Settings.Secure.ANDROID_ID -> ' + result);
        }}
        return result;
    }};

    console.log('[GAMA] Device ID hooks attivi su {pkg}');
}});
"""

    script_persistence = f"""// GAMA Frida Script — Background Persistence Monitor
// Package: {pkg}
// CenturiaLabs / ClickSafe UAE
// Monitora WorkManager e JobScheduler per GAMA-T003

Java.perform(function() {{
    // WorkManager
    try {{
        var WorkManager = Java.use('androidx.work.WorkManager');
        var PeriodicWorkRequest = Java.use('androidx.work.PeriodicWorkRequest');
        var OneTimeWorkRequest  = Java.use('androidx.work.OneTimeWorkRequest');
        console.log('[GAMA-T003] WorkManager classes trovate — hooking enqueue...');

        WorkManager.enqueue.overload('androidx.work.WorkRequest').implementation = function(req) {{
            console.log('[GAMA-T003] WorkManager.enqueue() -> ' + req.toString());
            return this.enqueue(req);
        }};
    }} catch(e) {{
        console.log('[GAMA-T003] WorkManager not found: ' + e);
    }}

    // JobScheduler
    try {{
        var JobScheduler = Java.use('android.app.JobScheduler');
        JobScheduler.schedule.implementation = function(jobInfo) {{
            console.log('[GAMA-T003] JobScheduler.schedule() job id=' + jobInfo.getId());
            return this.schedule(jobInfo);
        }};
    }} catch(e) {{
        console.log('[GAMA-T003] JobScheduler hook: ' + e);
    }}

    console.log('[GAMA] Persistence hooks attivi su {pkg}');
}});
"""

    scripts = {
        f"gama_uri_{pkg}.js":         script_uri,
        f"gama_ids_{pkg}.js":         script_ids,
        f"gama_persist_{pkg}.js":     script_persistence,
    }

    for fname, content in scripts.items():
        out = dynamic_dir / fname
        out.write_text(content)
        ok(f"Written: {fname}")

    print(f"\n  {bold('USO:')}")
    info(f"frida -U -f {pkg} -l {dynamic_dir}/gama_uri_{pkg}.js --no-pause")
    info(f"frida -U -f {pkg} -l {dynamic_dir}/gama_ids_{pkg}.js --no-pause")
    info(f"frida -U -f {pkg} -l {dynamic_dir}/gama_persist_{pkg}.js --no-pause")

def _manual_observation_log(dynamic_dir):
    sep()
    print(f"\n  {bold('MANUAL OBSERVATION LOG')}\n")
    note = input(f"  Observation: ").strip()
    if note:
        log_path = dynamic_dir / "observations.log"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a") as f:
            f.write(f"[{ts}] {note}\n")
        ok(f"Note saved to observations.log")

def _termination_test_checklist():
    sep()
    print(f"\n  {bold('POST-TERMINATION TEST CHECKLIST')}\n")
    pkg = session.get("apk_name", "").replace(".apk", "") or "[package]"
    steps = [
        f"1. Launch app and use normally for 3-5 minutes",
        f"2. Verify pcap capture is active: tcpdump su AP",
        f"3. Force-stop: adb shell am force-stop {pkg}",
        f"4. Do NOT touch the device for 10 minutes",
        f"5. When done: analyse pcap with Zeek",
        f"6. Search DNS queries after force-stop timestamp",
        f"7. If SDK endpoint queries present: GAMA-T003 finding confirmed",
    ]
    for s in steps:
        input(f"  {clr('[ ]', C.YELLOW)} {s}\n      {clr('Press enter when complete...', C.GRAY)}")
        ok("Completed")

def _add_dynamic_finding():
    sep()
    print(f"\n  {bold('FINDING FROM DYNAMIC ANALYSIS')}\n")
    technique   = input(f"  Technique: ").strip() or "GAMA-T003"
    description = input(f"  Description: ").strip()
    evidence    = input(f"  Evidence (Frida output / pcap ref): ").strip()
    cls         = input(f"  Class [hypothesis/confirmed/Class-A/B/C/D]: ").strip() or "confirmed"
    if description:
        add_finding(3, technique, description, evidence, cls)
        ok("Finding added.")

# ─── PHASE 4: Network ───────────────────────────────────────────────
def phase4_network():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 4 — NETWORK ANALYSIS')}\n")

    network_dir = session["workspace"] / "network"

    print(f"  {clr('1', C.CYAN)}  Import and analyse pcap/Zeek logs")
    print(f"  {clr('2', C.CYAN)}  DNS classifier (sinkhole list check)")
    print(f"  {clr('3', C.PURPLE)}  Post-termination delta (search traffic after force-stop)")
    print(f"  {clr('4', C.PURPLE)}  Domain fronting detector")
    print(f"  {clr('5', C.YELLOW)}  Add manual network finding")
    print(f"  {clr('0', C.GRAY)}   Back to menu\n")

    choice = input(f"  {clr('▶', C.BLUE)} ").strip()

    if choice == "1":
        _import_zeek(network_dir)
    elif choice == "2":
        _dns_classifier(network_dir)
    elif choice == "3":
        _termination_delta(network_dir)
    elif choice == "4":
        _domain_fronting_check(network_dir)
    elif choice == "5":
        _add_network_finding()

    session["phase"] = max(session["phase"], 5)
    save_session()
    input("\n  Press enter to continue...")

def _import_zeek(network_dir):
    sep()
    print(f"\n  {bold('IMPORT ZEEK / PCAP')}\n")
    path = input(f"  Zeek file path (dns.log, conn.log) or pcap: ").strip().strip("'\"")
    if not path or not Path(path).exists():
        warn("File not found.")
        return
    dest = network_dir / Path(path).name
    shutil.copy2(path, dest)
    ok(f"Copied to: {dest}")
    info("Analyse using options 2-4 of this phase.")

def _dns_classifier(network_dir):
    sep()
    print(f"\n  {bold('DNS CLASSIFIER')}\n")
    dns_log = input(f"  Zeek dns.log path: ").strip().strip("'\"")
    if not dns_log:
        dns_log = str(network_dir / "dns.log")
    if not Path(dns_log).exists():
        warn("dns.log not found.")
        return

    AD_TRACKING_PATTERNS = [
        "mbridge", "mintegral", "mobvista", "adjust.com", "appsflyer",
        "firebase", "moloco", "ironsource", "applovin", "chartboost",
        "adcolony", "vungle", "inmobi", "unity3d.com", "unityads",
        "bytedance", "pangle", "yandex", "amplitude", "mixpanel",
        "branch.io", "onesignal", "tapjoy", "fyber", "mopub",
        "doubleclick", "googlesyndication", "googletagmanager",
        "facebook.net", "graph.facebook", "analytics",
    ]

    queries = {}
    with open(dns_log) as f:
        for line in f:
            if line.startswith("#"): continue
            parts = line.strip().split("\t")
            if len(parts) > 9:
                domain = parts[9]
                queries[domain] = queries.get(domain, 0) + 1

    classified = {"tracking": [], "unknown": [], "system": []}
    system_domains = ["google.com","googleapis.com","android.com","gstatic.com","cloudflare.com"]

    for domain, count in sorted(queries.items(), key=lambda x: x[1], reverse=True):
        is_tracking = any(p in domain.lower() for p in AD_TRACKING_PATTERNS)
        is_system   = any(s in domain.lower() for s in system_domains)
        if is_tracking:
            classified["tracking"].append((domain, count))
        elif is_system:
            classified["system"].append((domain, count))
        else:
            classified["unknown"].append((domain, count))

    print(f"  {clr('TRACKING / AD DOMAINS', C.RED)} ({len(classified['tracking'])})")
    for d, c in classified["tracking"][:20]:
        print(f"    {clr('!!!', C.RED)} {str(c).rjust(5)}x  {d}")

    print(f"\n  {clr('UNCLASSIFIED DOMAINS', C.YELLOW)} ({len(classified['unknown'])})")
    for d, c in classified["unknown"][:15]:
        print(f"    {clr('?', C.YELLOW)} {str(c).rjust(5)}x  {d}")

    out = network_dir / "dns_classification.json"
    with open(out, "w") as f:
        json.dump(classified, f, indent=2)
    ok(f"\n  Saved: {out.name}")

def _termination_delta(network_dir):
    sep()
    print(f"\n  {bold('POST-TERMINATION DELTA')}\n")
    ts = input(f"  Force-stop timestamp {clr('[YYYY-MM-DD HH:MM:SS]', C.GRAY)}: ").strip()
    if not ts:
        warn("Timestamp required for delta.")
        return
    info(f"Search dns.log for queries with timestamp > {ts}")
    info("If SDK endpoint queries found after force-stop: GAMA-T003 confirmed.")
    note = input(f"  Observation note (leave empty if none): ").strip()
    if note:
        add_finding(4, "GAMA-T003",
            f"Post-termination activity detected after {ts}",
            note, "confirmed")
        ok("GAMA-T003 finding added.")

def _domain_fronting_check(network_dir):
    sep()
    print(f"\n  {bold('DOMAIN FRONTING DETECTOR')}\n")
    info("Technique: compare SSL SNI with actual destination IP.")
    info("In Zeek: ssl.log (field 'server_name') vs conn.log (field 'id.resp_h')")
    info("")
    info("If SNI = *.google.com but IP not in Google AS15169 range: suspected fronting.")
    info("If SNI = *.cloudfront.net but final destination is another entity: suspected fronting.")
    print()
    note = input(f"  Mismatch found? Describe: ").strip()
    if note:
        add_finding(4, "GAMA-T004",
            "Domain fronting detected: SNI/destination mismatch",
            note, "confirmed")
        ok("GAMA-T004 finding added.")

def _add_network_finding():
    sep()
    technique   = input(f"  Technique: ").strip() or "GAMA-T004"
    description = input(f"  Description: ").strip()
    evidence    = input(f"  Evidence: ").strip()
    cls         = input(f"  Class: ").strip() or "confirmed"
    if description:
        add_finding(4, technique, description, evidence, cls)
        ok("Finding added.")

# ─── PHASE 5: Correlation ────────────────────────────────────────
def phase5_correlation():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 5 — CORRELATION AND CLASSIFICATION')}\n")
    findings = load_findings()
    if not findings:
        warn("No findings yet. Complete phases 1-4.")
        input("  Press enter to continue...")
        return

    print(f"  {bold(str(len(findings)))} findings to classify.\n")
    sep()
    for i, f in enumerate(findings):
        ts    = f.get("timestamp","")[:16]
        phase = f.get("phase", "?")
        tech  = f.get("gama_technique","?")
        desc  = f.get("description","")[:70]
        cls   = f.get("classification","hypothesis")
        cls_color = C.RED if "Class-D" in cls or "Class-C" in cls else \
                    C.YELLOW if "confirmed" in cls else C.GRAY
        print(f"  {clr(str(i+1).rjust(2), C.CYAN)}  {clr(ts, C.GRAY)}  "
              f"{clr(tech, C.PURPLE):15}  {clr(cls, cls_color):15}  {desc}")

    sep()
    print(f"\n  {clr('1', C.CYAN)}  Classify a finding")
    print(f"  {clr('2', C.CYAN)}  Add analyst note to finding")
    print(f"  {clr('3', C.PURPLE)}  Map ATT&CK Mobile for all findings")
    print(f"  {clr('0', C.GRAY)}   Back to menu\n")

    choice = input(f"  {clr('▶', C.BLUE)} ").strip()

    if choice == "1":
        num = input(f"  Finding number to classify: ").strip()
        try:
            idx = int(num) - 1
            f = findings[idx]
            print(f"\n  Finding: {f.get('description','')}")
            print(f"  Evidence: {f.get('evidence','')}")
            print(f"\n  Classes: A (operational) / B (disproportionate) / C (concealed) / D (deceptive)")
            new_cls = input(f"  New classification: ").strip()
            if new_cls:
                findings[idx]["classification"] = f"Class-{new_cls.upper()}"
                # riscrivi jsonl
                with open(findings_path(), "w") as fh:
                    for fin in findings:
                        fh.write(json.dumps(fin) + "\n")
                ok(f"Classified as Class-{new_cls.upper()}")
        except (ValueError, IndexError):
            err("Invalid index.")

    elif choice == "2":
        num = input(f"  Finding number: ").strip()
        try:
            idx = int(num) - 1
            note = input(f"  Analyst note: ").strip()
            findings[idx]["analyst_note"] = note
            with open(findings_path(), "w") as fh:
                for fin in findings:
                    fh.write(json.dumps(fin) + "\n")
            ok("Note saved.")
        except (ValueError, IndexError):
            err("Invalid index.")

    elif choice == "3":
        _attck_mapping(findings)

    session["phase"] = max(session["phase"], 6)
    save_session()
    input("\n  Press enter to continue...")

ATTCK_MAP = {
    "GAMA-T001": ("T1637.002", "Exfiltration Over Alternative Protocol — URI Scheme"),
    "GAMA-T002": ("T1407",     "Download New Code at Runtime"),
    "GAMA-T003": ("T1624.003", "Scheduled Background Task Persistence (proposed)"),
    "GAMA-T004": ("T1665",     "Hide Infrastructure — Domain Fronting"),
    "GAMA-T005": ("proposed",  "JNI Policy Bypass (new technique candidate)"),
    "GAMA-T006": ("proposed",  "Visual Privacy Illusion — Premium Tier Deception"),
}

def _attck_mapping(findings):
    sep()
    print(f"\n  {bold('MITRE ATT&CK MOBILE MAPPING')}\n")
    seen = set()
    for f in findings:
        tech = f.get("gama_technique","")
        if tech and tech not in seen:
            seen.add(tech)
            attck = ATTCK_MAP.get(tech, ("unknown",""))
            print(f"  {clr(tech, C.PURPLE):15}  →  {bold(attck[0]):20}  {attck[1]}")

# ─── PHASE 6: Rules ──────────────────────────────────────────────
def phase6_rules():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 6 — ENFORCEMENT RULE GENERATION')}\n")

    findings = [f for f in load_findings()
                if f.get("classification","").startswith("Class-C")
                or f.get("classification","").startswith("Class-D")
                or f.get("classification") == "confirmed"]

    if not findings:
        warn("No confirmed findings (Class-C/D). Classify findings in Phase 5.")
        input("  Press enter to continue...")
        return

    rules_dir = session["workspace"] / "rules"
    print(f"  {bold(str(len(findings)))} confirmed findings → rule generation\n")
    print(f"  {clr('1', C.CYAN)}  Generate DNS sinkhole list")
    print(f"  {clr('2', C.CYAN)}  Generate Zeek signatures")
    print(f"  {clr('3', C.PURPLE)}  Generate IPS rules (Snort/Suricata)")
    print(f"  {clr('4', C.YELLOW)}  Generate all")
    print(f"  {clr('0', C.GRAY)}   Back to menu\n")

    choice = input(f"  {clr('▶', C.BLUE)} ").strip()

    if choice in ("1","4"):
        _gen_dns_sinkhole(findings, rules_dir)
    if choice in ("2","4"):
        _gen_zeek_signatures(findings, rules_dir)
    if choice in ("3","4"):
        _gen_ips_rules(findings, rules_dir)

    session["phase"] = max(session["phase"], 7)
    save_session()
    input("\n  Press enter to continue...")

def _gen_dns_sinkhole(findings, rules_dir):
    domains = set()
    for f in findings:
        ev = f.get("evidence","").lower()
        for part in ev.split():
            if "." in part and len(part) > 4 and not part.startswith("/"):
                cleaned = part.strip(".,;:()[]")
                if "." in cleaned:
                    domains.add(cleaned)
    out = rules_dir / "dns_sinkhole.txt"
    with open(out, "w") as f:
        f.write(f"# GAMA DNS Sinkhole List\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Workspace: {session['workspace'].name}\n\n")
        for d in sorted(domains):
            f.write(f"0.0.0.0 {d}\n")
    ok(f"DNS sinkhole: {out.name} ({len(domains)} domains)")

def _gen_zeek_signatures(findings, rules_dir):
    out = rules_dir / "gama.zeek"
    with open(out, "w") as f:
        f.write("# GAMA Zeek Signatures\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for i, finding in enumerate(findings):
            tech = finding.get("gama_technique","GAMA-T000")
            desc = finding.get("description","")[:60]
            f.write(f"# {tech} — {desc}\n")
            f.write(f"signature gama-{i+1:03d} {{\n")
            f.write(f'  ip-proto == tcp\n')
            f.write(f'  event "{tech}: {desc}"\n')
            f.write(f"}}\n\n")
    ok(f"Zeek signatures: {out.name}")

def _gen_ips_rules(findings, rules_dir):
    out = rules_dir / "gama.rules"
    with open(out, "w") as f:
        f.write("# GAMA IPS Rules (Snort/Suricata compatible)\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for i, finding in enumerate(findings):
            tech  = finding.get("gama_technique","GAMA-T000")
            desc  = finding.get("description","")[:60].replace('"',"'")
            sid   = 9000000 + i
            f.write(f'alert tcp any any -> any any (msg:"{tech}: {desc}"; ')
            f.write(f'sid:{sid}; rev:1; metadata:gama_technique {tech};)\n')
    ok(f"IPS rules: {out.name}")

# ─── PHASE 7: Report ──────────────────────────────────────────────
def phase7_report():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('PHASE 7 — REPORT AND DISCLOSURE')}\n")

    findings  = load_findings()
    report_dir = session["workspace"] / "report"
    ws_name    = session["workspace"].name
    apk_name   = session["apk_name"] or "unknown"
    hypothesis = session.get("hypothesis","Non documentata")
    ts         = datetime.now().strftime("%Y-%m-%d %H:%M")

    # statistiche
    classes = {}
    for f in findings:
        c = f.get("classification","hypothesis")
        classes[c] = classes.get(c, 0) + 1

    report = {
        "report_metadata": {
            "generated":  ts,
            "lab":        "CenturiaLabs / ClickSafe UAE",
            "workspace":  ws_name,
            "apk":        apk_name,
            "methodology": "GAMA v1.0",
        },
        "executive_summary": {
            "hypothesis":      hypothesis,
            "total_findings":  len(findings),
            "by_class":        classes,
            "attck_techniques": list({
                ATTCK_MAP.get(f.get("gama_technique",""),("",""))[0]
                for f in findings if f.get("gama_technique") in ATTCK_MAP
            }),
        },
        "findings": findings,
        "attck_mapping": {
            f.get("gama_technique",""): ATTCK_MAP.get(f.get("gama_technique",""),{})
            for f in findings if f.get("gama_technique")
        }
    }

    out = report_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)

    ok(f"JSON report: {out}")
    sep()
    print(f"\n  {bold('EXECUTIVE SUMMARY')}\n")
    print(f"  APK:        {bold(apk_name)}")
    print(f"  Findings:   {bold(str(len(findings)))}")
    print(f"  By class: {classes}")
    print(f"\n  {bold('MAPPED ATT&CK TECHNIQUES')}")
    for f in findings:
        tech = f.get("gama_technique","")
        if tech in ATTCK_MAP:
            attck = ATTCK_MAP[tech]
            print(f"  {clr(tech, C.PURPLE):15}  {bold(attck[0]):20}  {attck[1]}")

    sep()
    print(f"\n  {bold('DISCLOSURE TIMELINE')}")
    print(f"  Day  0: internal report complete")
    print(f"  Day 30: notify developer and SDK vendor")
    print(f"  Day 60: notify Google Play Security (if no response)")
    print(f"  Day 60+: publish on audit.centurialabs.pl")
    print(f"             MITRE ATT&CK Mobile submission")

    input("\n  Press enter to continue...")

# ─── 12. View findings ─────────────────────────────────────
def view_findings():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('FINDINGS — CURRENT WORKSPACE')}\n")
    findings = load_findings()
    if not findings:
        warn("No findings yet.")
        input("  Press enter to continue...")
        return

    for i, f in enumerate(findings, 1):
        ts    = f.get("timestamp","")[:16]
        tech  = f.get("gama_technique","?")
        desc  = f.get("description","")
        ev    = f.get("evidence","")
        cls   = f.get("classification","hypothesis")
        note  = f.get("analyst_note","")
        cls_color = C.RED if "Class-D" in cls or "Class-C" in cls else \
                    C.YELLOW if "confirmed" in cls else C.GRAY
        sep()
        print(f"  {clr(str(i), C.CYAN)}  {clr(ts, C.GRAY)}  {clr(tech, C.PURPLE)}  {clr(cls, cls_color)}")
        print(f"     {bold('Desc:')}  {desc}")
        print(f"     {bold('Ev:')}    {ev}")
        if note: print(f"     {bold('Nota:')} {note}")

    input("\n  Press enter to continue...")

# ─── 13. Add manual finding ────────────────────────────────
def add_manual_finding():
    if not require_workspace(): return
    print_banner()
    print(f"  {bold('ADD MANUAL FINDING')}\n")
    phase_n = input(f"  Phase (1-7): ").strip()
    technique   = input(f"  GAMA Technique: ").strip()
    description = input(f"  Description: ").strip()
    evidence    = input(f"  Evidence: ").strip()
    cls         = input(f"  Class [hypothesis/confirmed/Class-A/B/C/D]: ").strip() or "hypothesis"
    if description:
        add_finding(int(phase_n or 1), technique, description, evidence, cls)
        ok("Finding added.")
    input("  Press enter to continue...")

# ─── MAIN LOOP ───────────────────────────────────────────────────
def main():
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    dispatch = {
        "1":  new_workspace,
        "2":  open_workspace,
        "3":  list_workspaces,
        "4":  phase0_intake,
        "5":  phase1_static,
        "6":  phase2_ipc,
        "7":  phase3_dynamic,
        "8":  phase4_network,
        "9":  phase5_correlation,
        "10": phase6_rules,
        "11": phase7_report,
        "12": view_findings,
        "13": add_manual_finding,
        "14": add_manual_finding,
    }

    while True:
        choice = main_menu()
        if choice == "0":
            print(f"\n  {clr('CenturiaLabs / ClickSafe UAE — GAMA v1.0', C.DIM)}\n")
            sys.exit(0)
        handler = dispatch.get(choice)
        if handler:
            handler()
        else:
            print_banner()
            warn("Invalid choice.")
            import time; time.sleep(0.8)

if __name__ == "__main__":
    main()
