# ML-Based Detection of Deauthentication Attacks in Edge-Computing Wi-Fi

A complete, runnable **defensive** Intrusion Detection System (IDS) that spots
Wi-Fi **deauthentication (deauth) attacks** in real time using a **Random Forest**
classifier. Built end-to-end for the project *"Machine Learning-Based
Detection of Deauthentication Attacks in Edge Computing Environments."*

> **Scope & ethics.** Every component here is **passive and defensive**: it only
> *listens* to traffic and classifies it as *Normal* or *Attack*. It never
> transmits, injects, or deauthenticates anything. Only run live capture on a
> network you own or are authorised to test. See
> [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md#12-ethics-legality-and-scope).

---

## What it does (the 30-second version)

```
Wi-Fi traffic ─▶ Scapy sniffer ─▶ Feature extraction (per 2s window)
             ─▶ Random Forest model ─▶ Prediction ─▶ Normal / ALERT!
```

A deauth attack floods the air with tiny 802.11 *deauth* management frames to
kick clients off an access point. That pattern — a burst of deauth frames, a
spike in packet rate, small uniform frame sizes, a few repeated (spoofed) MAC
addresses — is what the model learns to recognise.

## Results (on the included synthetic dataset)

| Model              | Accuracy | Precision | Recall | F1     |
|--------------------|----------|-----------|--------|--------|
| **Random Forest**  | **0.98** | **0.98**  | **0.97** | **0.98** |
| Decision Tree      | 0.96     | 0.95      | 0.94   | 0.95   |
| SVM (RBF)          | 0.98     | 0.98      | 0.97   | 0.98   |

Random Forest is the chosen model: it matches the best accuracy, is far more
robust than a single Decision Tree, and reports **feature importance** so the
detection is explainable. See `outputs/` for the generated plots.

---

## Fastest way to see it work

The trained model, the dataset and a demo capture are all included, so there is
nothing to train before you can watch it run:

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

bash run_gui.sh                      # Windows: python src/webgui.py
```

That opens the dashboard in your browser. Press **Start monitoring** — the
detector classifies 20 two-second windows of synthetic traffic and flags the
deauth flood in windows 8–12. No Wi-Fi hardware needed.

Prefer the terminal? `python src/realtime_detector.py --mode sim`

---

## Quick start

```bash
# 1. Create an environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Generate the dataset  (stands in for AWID — see docs)
python src/generate_dataset.py

# 3. Preprocess + train + evaluate + save model.pkl
python src/train_model.py

# 4a. Watch the detector run WITHOUT special hardware (synthetic demo)
python src/realtime_detector.py --mode sim

# 4b. Or replay a capture file
python src/make_demo_pcap.py
python src/realtime_detector.py --mode pcap --pcap data/demo_capture.pcap

# 4c. Or sniff a REAL monitor-mode interface (Linux + capable Wi-Fi card + root)
sudo python src/realtime_detector.py --mode live --iface wlan0mon
```

One-shot: `bash run_all.sh` runs steps 2–4a in order.

### Or use the dashboard

```bash
bash run_gui.sh          # same as: python src/webgui.py
```

This starts a small local web server and opens a dashboard in your browser.
**Nothing to install** — it is Python's standard library (`http.server` plus
Server-Sent Events) with plain HTML/CSS/JS, and it makes no external requests,
so it works fully offline. Three tabs:

- **Live Detection** — pick simulation / PCAP / live capture, press *Start*, and
  watch the status banner turn red the moment the Random Forest flags a window,
  with running counters, a rolling deauth-vs-packet-rate chart, and a table of
  every per-window verdict. Set *windows* to `0` to monitor until you press Stop.
- **Model & Dataset** — the saved accuracy/precision/recall/F1, an artefact
  inventory, buttons to regenerate the dataset or retrain, and a viewer for the
  plots in `outputs/`.
- **Console Log** — the same text the CLI prints, plus pipeline output.

No detection logic lives in the dashboard: `src/webgui.py` supplies an
`on_result` callback to `realtime_detector.py` and renders what comes back, so
the CLI and the dashboard can never disagree about a verdict.

The server binds to `127.0.0.1` only. This tool reports attacks on your
network; it is not something to expose to one.

---

## Repository layout

```
deauth-ids/
├── README.md                    ← you are here
├── requirements.txt             ← Python dependencies
├── run_all.sh                   ← generate → train → demo, in one command
├── run_gui.sh                   ← open the browser dashboard
│
├── src/
│   ├── config.py                ← paths + the canonical 7-feature schema
│   ├── generate_dataset.py      ← synthetic AWID-like labelled dataset
│   ├── dataset_preprocessing.py ← load/clean/split/scale/visualise
│   ├── train_model.py           ← train RF, compare DT/SVM, save model
│   ├── realtime_detector.py     ← Scapy IDS: sniff→features→predict→alert
│   ├── webgui.py                ← browser dashboard over the same pipeline
│   └── make_demo_pcap.py        ← craft a test .pcap so pcap mode is demoable
│
├── data/                        ← generated dataset + demo capture
├── models/                      ← model.pkl, scaler.pkl, model_meta.json
├── outputs/                     ← histograms, correlation & confusion matrices…
│
└── docs/
    ├── DOCUMENTATION.md          ← FULL explanation of every concept & file
    ├── ARCHITECTURE.md           ← flowchart + data-flow
    └── slides/                   ← 10-slide project presentation
```

## Where to read next

- **Understand the whole thing, concept by concept** →
  [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md). It explains networking &
  Wi-Fi basics, how the deauth attack works, edge computing, the ML theory,
  every feature, and every line of the pipeline.
- **The architecture & flowchart** →
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- **Slides for the presentation** → `docs/slides/` (run
  `python src/make_slides.py` to regenerate the `.pptx`).

## Project components

| Area                               | Where it lives |
|------------------------------------|----------------|
| Networking, Wi-Fi & edge-computing background | `docs/DOCUMENTATION.md` §1–§4 |
| The deauthentication attack & defences | `docs/DOCUMENTATION.md` §5–§6 |
| ML fundamentals, Random Forest     | `docs/DOCUMENTATION.md` §7 |
| Dataset + feature engineering      | `src/generate_dataset.py`, `src/dataset_preprocessing.py` |
| Model training & comparison        | `src/train_model.py` |
| Real-time detection with Scapy     | `src/realtime_detector.py` |
| Browser dashboard                  | `src/webgui.py` |
| Architecture, docs & slides        | `docs/ARCHITECTURE.md`, `docs/DOCUMENTATION.md`, `docs/slides/` |

