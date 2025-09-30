#!/usr/bin/env python3
"""
ram_forensic_pipeline.py

Usage:
  python ram_forensic_pipeline.py --out reports --volcmd /path/to/vol.py /path/to/ram1.raw /path/to/ram2.raw
"""

import argparse
import os
import sys
import hashlib
import json
import datetime
import math
import subprocess
import shlex
from pathlib import Path
from malware_scan import analyze_image  


# -----------------------
# Configuration / helpers
# -----------------------

# Default plugins to run on macOS (change as you like)
DEFAULT_PLUGINS = [
    "mac.pslist",
    "mac.pstree",
    "mac.malfind",
    "mac.netstat",
    "mac.list_files"
]

# Fake yara rule signature used for example/dummy malware
TEST_SIGNATURE = b"MALWARE_TEST_SIGNATURE"
REPLACEMENT = b"SAFE_CLEANED_DATA_______"

def utc_now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0]*256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c/length
            entropy -= p * math.log2(p)
    return entropy

def fake_yara_scan(data: bytes):
    """Return list of fake rule names found in data."""
    matches = []
    if TEST_SIGNATURE in data:
        matches.append("FakeMalwareRule")
    return matches

def remediate_bytes(data: bytes) -> (bytes, int):
    """
    Replace all occurrences of TEST_SIGNATURE with REPLACEMENT.
    Returns (cleaned_data, replacements_count)
    """
    count = data.count(TEST_SIGNATURE)
    if count == 0:
        return data, 0
    cleaned = data.replace(TEST_SIGNATURE, REPLACEMENT)
    return cleaned, count

# -----------------------
# Volatility integration
# -----------------------

def build_vol_cmd(volcmd_raw):
    """
    volcmd_raw: user input like:
      - '/path/to/vol.py'
      - 'vol.py' (on PATH)
      - '/usr/bin/python3 /path/to/vol.py' (rare)
    Returns a list for subprocess invocation, e.g. ['python3','/path/to/vol.py'] or ['vol.py']
    """
    if not volcmd_raw:
        # try to find vol.py on PATH
        found = shutil_which("vol.py")
        if found:
            return [found]
        # fallback to just 'vol.py' and hope user's environment finds it
        return ["vol.py"]

    # if it contains spaces (user may have passed "python /path/vol.py")
    parts = shlex.split(volcmd_raw)
    return parts

def shutil_which(name):
    # tiny wrapper to avoid importing shutil at top if not needed
    from shutil import which
    return which(name)

def run_vol_plugin(vol_cmd_prefix, plugin, image_path, capture_dir, renderer="json"):
    """
    Run volatility plugin and capture stdout/stderr.
    vol_cmd_prefix: list, e.g. ['python3','/path/to/vol.py'] or ['vol.py']
    plugin: plugin name string (e.g. 'mac.pslist')
    image_path: path to raw file
    capture_dir: where to write plugin output file(s)
    renderer: 'json' or 'pretty' etc.
    Returns dict with keys: 'success'(bool),'outfile'(path or None),'stderr'(str),'stdout'(str)
    """
    cap = {}
    # build command
    cmd = vol_cmd_prefix[:]  # copy
    # vol.py supports -f IMAGE and plugin name; we will ask vol.py to render json to stdout (-r json)
    cmd += ["-f", str(image_path), "-r", renderer, plugin]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except FileNotFoundError as e:
        cap['success'] = False
        cap['stderr'] = str(e)
        cap['stdout'] = ""
        cap['outfile'] = None
        return cap

    # build a safe filename for plugin output
    plugin_safe = plugin.replace(".", "_")
    out_fname = Path(capture_dir) / f"vol_{plugin_safe}.txt"
    try:
        with open(out_fname, "w", encoding="utf-8") as fh:
            # write both stdout and stderr (stderr appended) so user can inspect
            fh.write("=== STDOUT ===\n")
            fh.write(p.stdout or "")
            fh.write("\n\n=== STDERR ===\n")
            fh.write(p.stderr or "")
    except Exception as e:
        cap['success'] = False
        cap['stderr'] = f"Failed to write output file: {e}"
        cap['stdout'] = p.stdout if 'p' in locals() else ""
        cap['outfile'] = None
        return cap

    cap['success'] = (p.returncode == 0)
    cap['stderr'] = p.stderr
    cap['stdout'] = p.stdout
    cap['outfile'] = str(out_fname)
    cap['returncode'] = p.returncode
    return cap

# -----------------------
# Core scanning pipeline
# -----------------------

def analyze_image(image_path: str, outdir: str, volcmd_raw: str = None, plugins=None, auto_remediate=True):
    image_p = Path(image_path).expanduser()
    if not image_p.exists():
        raise FileNotFoundError(f"Image not found: {image_p}")

    # prepare output dir per image
    image_outdir = Path(outdir) / (image_p.stem + "_" + datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
    image_outdir.mkdir(parents=True, exist_ok=True)

    # read bytes (beware large files — this script keeps in memory for demonstration)
    with open(image_p, "rb") as f:
        data = f.read()

    sha256 = sha256_file(str(image_p))
    entropy = calculate_entropy(data)
    yara_matches = fake_yara_scan(data)

    features = {
        "malfind_hits": bool(yara_matches),
        "process_count": 0,            # placeholder (requires real volatility parsing)
        "dll_count_approx": 0,         # placeholder
        "net_entries": 0,              # placeholder
        "sample_entropy": entropy,
        "rwx_estimate": 1 if yara_matches else 0
    }

    suspicious_files = []
    remediation_info = {"status": "not_needed", "output_file": None, "details": None}

    # if matches -> record offsets and attempt remediation (simple byte-replace)
    if yara_matches:
        offset = data.find(TEST_SIGNATURE)
        suspicious_files.append({"offset": offset, "signature": TEST_SIGNATURE.decode(errors="ignore")})

        if auto_remediate:
            cleaned_data, replaced = remediate_bytes(data)
            cleaned_path = str(image_outdir / (image_p.name.replace(".raw","") + "_cleaned.raw"))
            with open(cleaned_path, "wb") as cf:
                cf.write(cleaned_data)
            remediation_info = {
                "status": "success" if replaced>0 else "failed",
                "output_file": cleaned_path if replaced>0 else None,
                "replacements": replaced,
                "replaced_with": REPLACEMENT.decode(errors="ignore")
            }
        else:
            remediation_info["details"] = "Remediation disabled"

    # Prepare vol command prefix
    vol_cmd_prefix = build_vol_cmd(volcmd_raw)

    # run plugins
    vol_outputs_index = {}
    plugin_results = {}
    plugins = plugins or DEFAULT_PLUGINS
    for plugin in plugins:
        # run plugin and capture
        try:
            result = run_vol_plugin(vol_cmd_prefix, plugin, image_p, image_outdir, renderer="json")
            plugin_results[plugin] = result
            if result.get("outfile"):
                vol_outputs_index[plugin] = os.path.relpath(result["outfile"], start=str(image_outdir))
            else:
                vol_outputs_index[plugin] = {"error": result.get("stderr") or "unknown error", "returncode": result.get("returncode")}
        except Exception as e:
            vol_outputs_index[plugin] = {"error": str(e)}

    # Construct explanation (human-friendly)
    if yara_matches:
        explanation = (
            f"Malware signature(s) found: {', '.join(yara_matches)}. "
            f"Located at offset(s): {', '.join(str(s['offset']) for s in suspicious_files)}. "
            f"Entropy: {entropy:.4f}. Remediation attempted: {remediation_info['status']}."
        )
    else:
        explanation = (
            f"No test malware signatures found. Entropy: {entropy:.4f}. "
            "No remediation necessary."
        )

    # Build final record matching your requested shape
    record = {
        "meta": {
            "image": str(image_p),
            "sha256": sha256,
            "analyzed_at": utc_now_iso(),
            "tool": "ram_forensic_pipeline.py"
        },
        "features": features,
        "yara_matches": yara_matches,
        "suspicious_files": suspicious_files,
        "remediation": remediation_info,
        "vol_outputs_index": vol_outputs_index,
        "explanation": explanation,
        "internal_plugin_results": plugin_results  # optional full outputs for debugging
    }

    # Write per-image report file
    out_report = image_outdir / f"{image_p.name}.analysis.json"
    with open(out_report, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=4)

    # return path to report and the record
    return str(out_report), record

# -----------------------
# CLI
# -----------------------

def main():
    parser = argparse.ArgumentParser(description="Simple RAM forensic pipeline (dummy YARA, volatility plugin capture, remediation)")
    parser.add_argument("images", nargs="+", help="One or more RAM image file paths (raw)")
    parser.add_argument("--out", "-o", required=True, help="Output directory to store reports and volatility outputs")
    parser.add_argument("--volcmd", "-v", default=None, help="Command to run volatility (e.g. 'python /path/to/vol.py' or 'vol.py')")
    parser.add_argument("--plugins", "-p", default=",".join(DEFAULT_PLUGINS),
                        help=f"Comma-separated plugin list to run (default: {','.join(DEFAULT_PLUGINS)})")
    parser.add_argument("--no-remediate", action="store_true", help="Do not perform the automated remediation step")
    args = parser.parse_args()

    outdir = Path(args.out).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)
    plugins = [p.strip() for p in args.plugins.split(",") if p.strip()]

    final_results = {}
    for img in args.images:
        try:
            report_path, rec = analyze_image(img, str(outdir), volcmd_raw=args.volcmd, plugins=plugins, auto_remediate=(not args.no_remediate))
        except Exception as e:
            rec = {"error": str(e)}
            report_path = None
        final_results[img] = rec
        # also write top-level mapping file in the main outdir
    final_summary_file = outdir / f"ram_pipeline_summary_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    with open(final_summary_file, "w", encoding="utf-8") as fh:
        json.dump(final_results, fh, indent=4)

    print(f"Reports written to: {outdir}")
    print(f"Summary file: {final_summary_file}")

if __name__ == "__main__":
    main()
