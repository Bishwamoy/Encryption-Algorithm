# Encryption-Algorithm

CN Encryption Workbench — with URL-Aware Traceroute + Geo Map

A complete, presentation-ready Computer Networks project that lets you:
Benchmark modern crypto (AES-GCM, ChaCha20-Poly1305, AES-CTR+HMAC, RSA, X25519)
Analyze encryption performance on your own input (text or file)

Generate side-by-side comparisons across scenarios (e.g., Web vs Wi-Fi)
Apply results to a problem statement (auto-recommend the best AEAD)
Traceroute any URL/host/IP, enrich hops with country/city/ISP, and plot them on a world map (Leaflet)
All features are available via a clean Flask web UI and via CLI.

Table of Contents :-
Key Features
Algorithms & Concepts
Scenarios
Project Structure
Quick Start (Windows)
Quick Start (Linuxmacos)
Web UI Walkthrough
CLI Usage
Outputs & Files

How It Works (Under the Hood):-
Security Notes:-
Troubleshooting
License
Key Features
Benchmark suite: Timed runs across message sizes and iterations, producing CSV/JSON summaries.
Per-message Analysis: Encrypts your input (text/file) with multiple algorithms, reports mean & p95 latencies, and shows ciphertext previews/base64 artifacts.
Side-by-Side Compare: Visual comparison of algorithms within a scenario (chart + table).
Multi-Scenario Compare: Aggregate results across multiple scenarios (e.g., web, wifi) in one chart.
Applied Recommendation: Given a problem statement (e.g., secure chat over public internet), recommends the best AEAD based on your measured data.

Traceroute (URL/Host/IP):
Accept full URLs (e.g., https://example.com/path?x=1) or host/IP (example.com, 8.8.8.8)
Optional geo-enrichment (country, city, ISP, lat/lon) via ip-api.com (no key)
World map with hop markers + polyline (Leaflet + OpenStreetMap tiles)
Clean UI: Dark theme, charts (Chart.js), copy buttons, drag-and-drop file upload.

Algorithms & Concepts
Algorithm	Type	AEAD?	What it is / Why it matters
AES-GCM (128/256)	Symmetric	✅	Authenticated encryption; fast on CPUs with AES-NI; widely used for TLS. Protects confidentiality + integrity in one pass.
ChaCha20-Poly1305	Symmetric	✅	Stream cipher + MAC; great on devices without AES-NI; standardized for TLS/QUIC; robust & fast on general hardware.
AES-CTR + HMAC	Symmetric (+ MAC)	✳️ (Enc+MAC)	Encrypt-then-MAC construction (separate steps). Educational baseline; correct but less convenient than AEADs.
X25519 (handshake)	Asymmetric (KX)	—	Key exchange primitive used in TLS 1.3 for ephemeral shared secrets.
RSA-2048	Asymmetric	—	Used for legacy key exchange/signature. We time keygen/sign/verify to compare asym. costs.

AEAD vs Enc+MAC
AEAD (e.g., GCM, ChaCha20-Poly1305) gives you encryption + integrity together with Associated Data (AAD) support (headers, context). Enc+MAC is two steps; educational but more error-prone in real systems.

Scenarios
Scenarios let you label where/how you measured (e.g., web, wifi, lan, vpn, etc.).
They’re used to produce separate summaries and multi-scenario comparisons.

Project Structure
cn_encryption_python/
├─ app.py                       # Flask app (web UI)
├─ requirements.txt             # Python dependencies
├─ src/
│  ├─ crypto_algs.py            # AES-GCM, ChaCha20-Poly1305, AES-CTR+HMAC, RSA, X25519
│  ├─ bench.py                  # Size/iters benchmark → CSV/JSON
│  ├─ analyze.py                # Encrypt+measure on user input (single scenario)
│  ├─ compare.py                # Side-by-side compare within a scenario
│  ├─ compare_multi.py          # Compare multiple scenarios together
│  ├─ apply.py                  # Problem → recommend best AEAD (with evidence)
│  ├─ jsonio.py, util.py        # Helpers (b64, timing, summaries)
│  ├─ net_tools.py              # Traceroute (+ URL/host parsing, geo-enrichment)
│  ├─ traceroute.py             # CLI entrypoint for traceroute (+geo)
│  └─ __init__.py
├─ templates/
│  ├─ base.html                 # Layout + header nav
│  ├─ index.html                # Mode picker form
│  ├─ analyze.html              # Results table + chart
│  ├─ compare_multi.html        # Multi-scenario chart/table
│  ├─ quick.html                # Quick encrypt cards with copy buttons
│  ├─ apply.html                # Recommendation + evidence table
│  └─ traceroute.html           # Hop table + Leaflet map
└─ static/
   ├─ app.css                   # Dark UI styles (no Tailwind build needed)
   └─ app.js                    # Small UX helpers (tabs, counters)

Quick Start (Windows)
# 0) Enter folder
cd .\cn_encryption_python

# 1) Virtual env + deps
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt

# 2) Ensure package path
ni .\src\__init__.py -ItemType File -Force
$env:PYTHONPATH = (Get-Location).Path

# 3) Run Flask (preferred)
$env:FLASK_APP = "app:app"
$env:FLASK_RUN_PORT = "5000"
python -m flask run --debug

# Open http://127.0.0.1:5000/

Quick Start (Linux/macOS)
cd ./cn_encryption_python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt

export PYTHONPATH=$(pwd)
export FLASK_APP="app:app"
export FLASK_RUN_PORT=5000
python -m flask run --debug
# open http://127.0.0.1:5000/

Web UI Walkthrough
Modes (tabs)
Analyze: Encrypt your message/file for one scenario; see mean/p95 and ciphertext previews.
Compare-Multi: Select multiple scenarios (checkboxes) to compare in one chart.
Apply: Enter a problem statement; it recommends the best AEAD with evidence.
Quick Encrypt: Get ciphertext + keys/nonces fast; copy buttons included.
Traceroute (top bar → “Traceroute”)
Input URL / Host / IP (e.g., https://example.com/login?x=1, example.com, 8.8.8.8)
Optional Geo: country/city/ISP + world map (Leaflet).
Table lists hop #, IP, RTT (ms) and location where available.

Charts
Analyze: Bar chart for mean and p95 latencies across algos.
Compare-Multi: Stacked bars across scenarios.
CLI Usage
Run these from the project root with venv active.
Benchmark (sizes in KB)
python -m src.bench --iters 7 --sizes 64 256 1024 4096

Analyze (one scenario)
python -m src.analyze --scenario web --repeat 12 --msg "Encrypt THIS exact message"

Compare (algos side-by-side in one scenario)
python -m src.compare --scenario web --repeat 15 --msg "Encrypt THIS exact message" --title "CN Project: Side-by-Side (Web)"

Compare-Multi (e.g., WEB vs WIFI)
python -m src.compare_multi --scenarios web wifi --repeat 15 --msg "Encrypt THIS exact message" --title "CN: Web vs WiFi"

Apply (problem → recommendation)
python -m src.apply --problem "Protect chat over public internet" --scenario web --repeat 15 --msg "hello team" --title "CN: Secure Chat"

Traceroute (URL/Host/IP) + Geo + Save JSON
python -m src.traceroute --target https://www.wikipedia.org/ --max-hops 25 --geo --out out/tr_wiki.json
python -m src.traceroute --target 8.8.8.8 --max-hops 20 --geo --out out/tr_8.8.8.8.json

Outputs & Files :-
Bench
out/results.csv, out/results.json — per-size, per-algo throughput & timing.
Analyze / Compare / Apply
out/analysis_<timestamp>_<scenario>_summary.json — mean/p95, artifacts (base64).
Optional markdown report (depending on mode).

Traceroute
CLI with --out: saves JSON containing hops and (if enabled) geo fields.
How It Works (Under the Hood)
Timing: Each algorithm encrypts your input N times (repeat) and collects per-run ms. We compute mean and p95 to capture typical latency and tail behavior.
AEADs: AES-GCM and ChaCha20-Poly1305 are used with unique nonces per run (never reused); AAD is optionally included (e.g., "CN-Java-analysis" style tag in earlier runs).
Apply mode: Filters to AEAD results and picks the fastest mean (with p95 shown) for your input & scenario.

Traceroute:
We normalize any URL to a hostname (strip scheme, port).
Run tracert (Windows) or traceroute (Linux/macOS).
Parse hops; if Geo is enabled, call ip-api.com per hop (polite delay).
Render table + Leaflet map with markers and a polyline.

Security Notes
Randomness: Keys & nonces generated with cryptographically secure RNG for demos; do not reuse nonces, especially with GCM/CTR.
Key Management: This project displays keys/nonces for educational visibility. In production, never log or expose secrets.
Enc+MAC vs AEAD: Prefer AEAD (GCM, ChaCha20-Poly1305) to avoid misuse.
Traceroute/Geo Privacy: Traceroute paths and IPs may reveal network topology; geo lookups query a third-party service (ip-api.com).

Troubleshooting
Web UI doesn’t start
ni .\src\__init__.py -ItemType File -Force
$env:PYTHONPATH = (Get-Location).Path
$env:FLASK_APP = "app:app"
$env:FLASK_RUN_PORT = "5000"
python -m flask run --debug


ModuleNotFoundError: src
$env:PYTHONPATH = (Get-Location).Path
Port in use
$env:FLASK_RUN_PORT = "5050"
python -m flask run --debug


cryptography import/build issues
pip install --upgrade cryptography
Traceroute blocked / no output
Run terminal as Administrator (Windows) or ensure traceroute is installed (Linux/macOS).

UI shows ‘typing invisible’
Hard refresh (Ctrl+F5). Ensure static/app.css is loaded (dark theme with visible text).
License

This project is for educational and academic use (CN coursework).
If you plan to publish or redistribute, add your preferred open-source license (e.g., MIT) and attribute any third-party content (Leaflet, OpenStreetMap).

If you want, I can also add:
Export to PDF (charts + tables + traceroute map snapshot)
Ping panel with latency charts

RTT-colored map markers and route elevation graph-style legend
Just say the word, and I’ll wire them in
