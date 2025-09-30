# 🧩 RAM Forensic Pipeline

A cross-platform memory forensics and malware remediation pipeline.  
This project simulates memory analysis workflows using [Volatility 3](https://github.com/volatilityfoundation/volatility3), YARA rules, and custom remediation logic.  

It supports analyzing memory dumps (real or dummy), detecting suspicious patterns, remediating known malware signatures, and generating detailed JSON reports.

---

## 🚀 Features

- 📦 **Acquire & analyze memory dumps**  
- 🕵️ **Malware detection using YARA signatures**  
- 🧹 **Automatic remediation** of infected dumps (replace malicious signatures with safe placeholders)  
- 📊 **Detailed JSON reports** (per dump and summary) with:
  - Metadata (hash, tool, timestamp)
  - Extracted features (entropy, process count, dll estimates, etc.)
  - YARA matches
  - Suspicious offsets
  - Remediation results
  - Volatility output index (if available)

---

## ⚙️ Installation

### 1. Clone the repository

git clone https://github.com/samarthasgowda/final.git
cd final
2. Set up Python environment (recommended)
On macOS / Linux
bash
Copy code
python3 -m venv ~/ramenv
source ~/ramenv/bin/activate
On Windows (PowerShell)
powershell
Copy code
python -m venv ramenv
.\ramenv\Scripts\activate
3. Install dependencies
bash
Copy code
pip install --upgrade pip
pip install -r requirements.txt
If requirements.txt is missing, you can manually install:

bash
Copy code
pip install volatility3 yara-python pefile capstone
4. Install Volatility 3 (optional but recommended)
bash
Copy code
# Inside your environment
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .
🖥️ Usage
Create dummy memory dumps (for testing)
bash
Copy code
# Clean dummy (safe)
dd if=/dev/zero of=$HOME/dummy_clean.raw bs=1m count=10

# Infected dummy (with fake malware signature)
dd if=/dev/urandom of=$HOME/dummy_infected.raw bs=1m count=10
echo "MALWARE_TEST_SIGNATURE" | dd of=$HOME/dummy_infected.raw bs=1 seek=1000 conv=notrunc
Run malware scan directly
bash
Copy code
python malware_scan.py $HOME/dummy_clean.raw $HOME/dummy_infected.raw
Run full forensic pipeline
bash
Copy code
python ram_forensic_pipeline.py \
  --out $HOME/ram_reports \
  --volcmd "python /path/to/volatility3/vol.py" \
  $HOME/dummy_clean.raw $HOME/dummy_infected.raw
📂 Output
The pipeline produces:

Per-dump JSON reports:

dummy_clean.raw.analysis.json

dummy_infected.raw.analysis.json

Summary file:

ram_pipeline_summary_20250930T120000Z.json

Remediated dumps (if malware found):

dummy_infected_cleaned.raw

Example JSON (infected)
json
Copy code
{
  "meta": {
    "image": "/Users/user/dummy_infected.raw",
    "sha256": "51c2a8e0d2da7138dd6156a0ec31a03d02079150470718b54ec2a73626464b51",
    "analyzed_at": "2025-09-30T07:25:11.953614Z",
    "tool": "malware_scan.py"
  },
  "features": {
    "malfind_hits": true,
    "process_count": 0,
    "dll_count_approx": 0,
    "net_entries": 0,
    "sample_entropy": 7.9999817398587245,
    "rwx_estimate": 1
  },
  "yara_matches": ["FakeMalwareRule"],
  "suspicious_files": [
    { "offset": 1000, "signature": "MALWARE_TEST_SIGNATURE" }
  ],
  "remediation": {
    "status": "success",
    "output_file": "/Users/user/dummy_infected_cleaned.raw",
    "replaced_with": "SAFE_CLEANED_DATA_______"
  },
  "vol_outputs_index": {}
}
🏗️ Project Structure
php
Copy code
final/
├── analysis/                 # Volatility integration
│   └── volatility_runner.py
├── remediation/              # Remediation logic
│   └── remediation.py
├── main.py                   # CLI entry point
├── malware_scan.py           # Malware scanner + remediation
├── ram_forensic_pipeline.py  # Multi-dump pipeline & reporting
├── scan_results.json         # Example result
└── README.md                 # This file
📜 License
This project is licensed under the MIT License.
You are free to use, modify, and distribute it with attribution.

See the LICENSE file for details.

🙏 Acknowledgements
Volatility Foundation for Volatility 3

YARA for malware pattern matching

Open source contributors & researchers in memory forensics
