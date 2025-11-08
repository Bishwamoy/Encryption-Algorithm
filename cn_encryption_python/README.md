# CN Encryption Project (Python)

A clean, ready-to-run Python project mirroring your Java version. It benchmarks and compares modern authenticated encryption algorithms and a legacy construction, and produces Markdown reports and JSON artifacts under `out/`.

## Algorithms
- **AES-GCM** (128/256-bit keys, 12-byte nonce, AEAD tag embedded)
- **ChaCha20-Poly1305** (256-bit key, 12-byte nonce, AEAD tag embedded)
- **AES-CTR + HMAC-SHA256** (encrypt-then-MAC; 128-bit AES, 16-byte IV, 32-byte HMAC)

## Quick start (Windows PowerShell)
```powershell
cd .\cn_encryption_python
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt

python -m src.bench --iters 7 --sizes 64 256 1024 4096
python -m src.analyze --scenario web --repeat 12 --msg "Encrypt THIS exact message"
python -m src.compare --scenario web --repeat 15 --msg "Encrypt THIS exact message" --title "CN Project: Side-by-Side (Web)"
python -m src.compare_multi --scenarios web wifi --repeat 15 --msg "Encrypt THIS exact message" --title "CN: Web vs WiFi"
python -m src.apply --problem "Protect chat over public internet" --scenario web --repeat 15 --msg "hello team" --title "CN Project: Secure Chat"
python -m src.compare_from_summaries --files out\analysis_..._web_summary.json out\analysis_..._wifi_summary.json --title "CN: WEB vs WIFI (Saved)"
```

## macOS / Linux
```bash
cd ./cn_encryption_python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt

python -m src.bench --iters 7 --sizes 64 256 1024 4096
python -m src.analyze --scenario web --repeat 12 --msg "Encrypt THIS exact message"
python -m src.compare --scenario web --repeat 15 --msg "Encrypt THIS exact message" --title "CN Project: Side-by-Side (Web)"
python -m src.compare_multi --scenarios web wifi --repeat 15 --msg "Encrypt THIS exact message" --title "CN: Web vs WiFi"
python -m src.apply --problem "Protect chat over public internet" --scenario web --repeat 15 --msg "hello team"
python -m src.compare_from_summaries --files out/analysis_..._web_summary.json out/analysis_..._wifi_summary.json --title "CN: WEB vs WIFI (Saved)"
```


---

## Interactive mode (user input driven)

Run an interactive assistant that asks for your **message/file**, **scenario(s)**, **repeat count**, and the **mode** you want (Analyze / Compare / Compare-Multi / Apply / Quick Encrypt).

### Windows PowerShell
```powershell
cd .\cn_encryption_python
.\.venv\Scripts\Activate.ps1   # after creating venv and installing requirements
python -m src.ui
```

### macOS / Linux
```bash
cd ./cn_encryption_python
source .venv/bin/activate
python -m src.ui
```

Outputs are saved under `out/` with `ui_*.md` or `quick_*.json` filenames.


---

## Web Frontend (Flask)

A minimal Tailwind‑styled UI to run everything in the browser.

### Run
```powershell
cd .\cn_encryption_python
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000/

### Modes in UI
- Analyze (one scenario)
- Compare‑Multi (WEB vs WIFI vs VPN…)
- Apply (problem → recommendation)
- Quick Encrypt (show artifacts + timings)
