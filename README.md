# 🧩 RAM Forensic Pipeline

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 Overview

The **RAM Forensic Pipeline** is a Python-based framework for analyzing memory dumps.  
It can:

- Capture or analyze RAM dumps
- Perform **malware signature detection** (via fake YARA-like rules)
- Calculate entropy and basic memory features
- Simulate Volatility 3 plugin output
- Automatically **remediate infected memory images**
- Generate structured **JSON reports**

This project is educational and demonstrates how live memory analysis pipelines can be built for malware detection and forensic research.

---

## 📥 Installation & Usage Guide

### 1. Clone the repository

git clone https://github.com/<your-username>/final.git
cd final

### 2. Create a Python environment
Recommended: Python 3.10 or 3.11

macOS / Linux

python3 -m venv ramenv
source ramenv/bin/activate

Windows (PowerShell)

python -m venv ramenv
ramenv\Scripts\activate

### 3. Install dependencies

All requirements are pinned in requirements.txt.

pip install --upgrade pip
pip install -r requirements.txt

### 4. Prepare test RAM dumps

Since real RAM dumps are large, you can generate dummy files for testing:

# Clean RAM image
dd if=/dev/zero of=$HOME/dummy_clean.raw bs=1m count=10

# Infected RAM image with malware signature
dd if=/dev/urandom of=$HOME/dummy_infected.raw bs=1m count=10
echo "MALWARE_TEST_SIGNATURE" | dd of=$HOME/dummy_infected.raw bs=1 seek=1000 conv=notrunc

### 5. Run malware scan

python malware_scan.py $HOME/ram_reports $HOME/dummy_clean.raw $HOME/dummy_infected.raw

This will:

Create an output directory: $HOME/ram_reports

Write a JSON report file:

ram_reports/scan_report_<timestamp>.json

Print the same JSON in your terminal

### 6. View results

In terminal (pretty-print with jq):

cat $HOME/ram_reports/scan_report_*.json | jq

Example JSON Output:

{
  "/Users/samarthasgowda/dummy_clean.raw": {
     "meta": {
      "image": "/Users/samarthasgowda/dummy_clean.raw",
      "sha256": "e5b844cc57f57094ea4585e235f36c78c1cd222262bb89d53c94dcb4d6b3e55d",
      "analyzed_at": "2025-09-30T07:47:03Z",
      "tool": "ram_forensic_pipeline.py"
    },
    "features": {
      "malfind_hits": false,
      "sample_entropy": 0.0
    },
    "remediation": {
      "status": "not_needed"
    },
    "explanation": "No test malware signatures found. Entropy: 0.0000. No remediation necessary."
  },
  "/Users/samarthasgowda/dummy_infected.raw": {
    "meta": {
      "image": "/Users/samarthasgowda/dummy_infected.raw",
      "sha256": "b445fd0fd48417566b61d57bab523b5a84ac52a8fe3bed0ae3053b9c8b4a692a",
      "analyzed_at": "2025-09-30T07:47:08Z",
      "tool": "ram_forensic_pipeline.py"
    },
    "features": {
      "malfind_hits": true,
      "sample_entropy": 7.9999
    },
    "yara_matches": [
      "FakeMalwareRule"
    ],
    "suspicious_files": [
      {
        "offset": 1000,
        "signature": "MALWARE_TEST_SIGNATURE"
      }
    ],
    "remediation": {
      "status": "success",
      "output_file": "/Users/samarthasgowda/ram_reports/dummy_infected_cleaned.raw",
      "replaced_with": "SAFE_CLEANED_DATA_______"
    },
    "explanation": "Malware signature(s) found: FakeMalwareRule. Located at offset(s): 1000. Entropy: 8.0000. Remediation attempted: success."
  }
}

⚖️ License

This project is released under the MIT License.
You are free to use, modify, and distribute this project with attribution.

✅ Summary

After following these steps, you will have a reproducible pipeline that:

Scans RAM dumps

Detects malware signatures

Cleans infected images

Produces detailed JSON reports
