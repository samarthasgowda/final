# main.py  -- cross-platform driver for acquisition + analysis
import argparse
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime

from analysis.volatility_runner import VolatilityRunner
from remediation.remediation import generate_taskkill_commands, generate_quarantine_instructions

# Helper: detect OS
def get_os():
    return platform.system().lower()   # 'windows', 'linux', 'darwin' (macOS)

# Helper: check for an executable in PATH
def which(exe):
    return shutil.which(exe)

# Acquisition wrappers (call external tools if present).
# Each returns path to created dump on success or None.

def run_dumpit_on_windows(out_dir):
    exe = which("DumpIt.exe") or which("DumpIt") or which("dumpit")
    if not exe:
        print("[!] DumpIt not found in PATH. Please run DumpIt on the Windows target and pass --dump <path>")
        return None
    # DumpIt prompts interactively; running may require user interaction
    print(f"[*] Running DumpIt at {exe} (you may need to confirm on the Windows host)...")
    try:
        proc = subprocess.run([exe], check=True)
        print("[*] DumpIt finished. Locate the produced .dmp file and pass its path with --dump.")
    except Exception as e:
        print("[!] Error running DumpIt:", e)
    return None

def run_avml_on_linux(out_dir):
    exe = which("avml")
    if not exe:
        print("[!] avml not found. Install it from https://github.com/microsoft/avml/releases and put in PATH.")
        return None
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    outpath = os.path.join(out_dir, f"memory_avml_{ts}.lime")
    cmd = [exe, "-o", outpath]
    print("[*] Running avml to create:", outpath)
    try:
        subprocess.run(cmd, check=True)
        return outpath
    except Exception as e:
        print("[!] avml failed:", e)
        return None

def run_lime_if_available(out_dir):
    exe = which("lime") or which("lime-collector")
    if not exe:
        return None
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    outpath = os.path.join(out_dir, f"memory_lime_{ts}.lime")
    cmd = [exe, "-o", outpath]
    try:
        subprocess.run(cmd, check=True)
        return outpath
    except Exception as e:
        print("[!] LiME runner failed:", e)
        return None

def run_osxpmem_on_mac(out_dir):
    exe = which("osxpmem") or which("pmem")  # try typical names
    if not exe:
        print("[!] osxpmem not found in PATH. Building/installing osxpmem may be required. See Rekall/osxpmem resources.")
        return None
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    outpath = os.path.join(out_dir, f"memory_osxpmem_{ts}.raw")
    cmd = [exe, "-o", outpath]
    print("[*] Running osxpmem to create:", outpath)
    try:
        subprocess.run(cmd, check=True)
        return outpath
    except Exception as e:
        print("[!] osxpmem failed:", e)
        return None

# Basic heuristic to extract suspicious PIDs from malfind (reuse earlier heuristic)
import re
def heuristics_find_suspicious_from_malfind(file_path: str):
    suspicious = set()
    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
        txt = fh.read()
    for m in re.finditer(r"PID:\s*(\d+)", txt):
        suspicious.add(int(m.group(1)))
    for m in re.finditer(r"PID\)\s+(\d+)", txt):
        suspicious.add(int(m.group(1)))
    return sorted(list(suspicious))

def parse_args():
    p = argparse.ArgumentParser(description="Cross-platform RAM forensic pipeline (acquire + analyze)")
    p.add_argument("--acquire", action="store_true", help="Attempt on-host acquisition using the OS-appropriate tool (if available in PATH).")
    p.add_argument("--dump", help="Path to existing memory dump (required if --acquire isn't used or acquisition fails).")
    p.add_argument("--out", default="logs", help="Output directory")
    p.add_argument("--volcmd", default="volatility3", help="Volatility3 CLI executable name (default: volatility3)")
    p.add_argument("--auto-remediate", action="store_true", help="(Dangerous) attempt remediation (simulated by default).")
    return p.parse_args()

def main():
    args = parse_args()
    os_name = get_os()
    print("[*] Detected OS:", os_name)
    os.makedirs(args.out, exist_ok=True)

    dump_path = None
    if args.acquire:
        # Try per-platform acquisition
        if os_name == "windows":
            # On Windows this script likely won't be run; prefer user to run DumpIt on the target
            print("[*] Attempting Windows acquisition with DumpIt (best to run DumpIt interactively on the target).")
            dump_path = run_dumpit_on_windows(args.out)
        elif os_name == "linux":
            print("[*] Attempting Linux acquisition via avml (or fallback to LiME)")
            dump_path = run_avml_on_linux(args.out)
            if not dump_path:
                dump_path = run_lime_if_available(args.out)
        elif os_name == "darwin":
            print("[*] Attempting macOS acquisition via osxpmem (Intel only; may fail on modern macs/T2/Apple Silicon).")
            dump_path = run_osxpmem_on_mac(args.out)
            if not dump_path:
                print("[!] Full physical RAM acquisition may not be possible on this macOS. Consider alternative artifact collection (ps, netstat, lsof, kernel logs) or use dedicated hardware/commercial tools.")
        else:
            print("[!] Unsupported OS for automated acquisition:", os_name)

    # If we didn't acquire, use provided --dump
    if not dump_path:
        if args.dump:
            dump_path = args.dump
        else:
            print("[ERROR] No memory dump available. Either run with --acquire (requires tool in PATH) or pass --dump <path_to_dump>.")
            sys.exit(1)

    print("[*] Using memory image:", dump_path)

    # Run analysis (Volatility)
    vr = VolatilityRunner(volatility_cmd=args.volcmd)
    outdir = args.out
    print("[*] Running volatility plugins (pslist, pstree, malfind, netscan)...")
    ps = vr.pslist(dump_path, outdir)
    pt = vr.pstree(dump_path, outdir)
    mal = vr.malfind(dump_path, outdir)
    nets = vr.netscan(dump_path, outdir)
    print("[*] Analysis complete. Parsing malfind for suspicious PIDs (heuristic).")
    suspicious_pids = heuristics_find_suspicious_from_malfind(mal)
    print("[*] Suspicious PIDs:", suspicious_pids)

    dumped_files = []
    for pid in suspicious_pids:
        pid_outdir = os.path.join(outdir, f"pid_{pid}")
        os.makedirs(pid_outdir, exist_ok=True)
        dumpres = vr.memmap_dump(dump_path, pid, pid_outdir)
        # collect dumped files (Volatility will write them into the output dir)
        for f in os.listdir(pid_outdir):
            if f.endswith(".dmp") or f.endswith(".bin") or f.startswith("proc."):
                dumped_files.append(os.path.join(pid_outdir, f))

    remediation_cmds = generate_taskkill_commands(suspicious_pids)
    quarantine_instructions = generate_quarantine_instructions(dumped_files, quarantine_dir=os.path.join(outdir, "quarantine"))

    # Save summary
    import json
    summary = {
        "dump_used": dump_path,
        "pslist": ps,
        "pstree": pt,
        "malfind": mal,
        "netscan": nets,
        "suspicious_pids": suspicious_pids,
        "dumped_files": dumped_files,
        "remediation_cmds": remediation_cmds,
        "quarantine_instructions": quarantine_instructions,
    }
    summary_file = os.path.join(outdir, f"summary_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json")
    with open(summary_file, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print("[+] Summary written to", summary_file)

    # Note: we DO NOT execute remediation commands by default
    print("[*] Remediation suggestions (not executed):")
    for c in remediation_cmds:
        print("   ", c)
    print("[*] Quarantine instructions:")
    for q in quarantine_instructions:
        print("   ", q)

    if args.auto_remediate:
        print("[!] auto-remediate flag set. This script will only simulate execution. To actually execute, review and run the commands on the target host yourself.")

    print("[*] Done. Review output directory:", outdir)

if __name__ == "__main__":
    main()