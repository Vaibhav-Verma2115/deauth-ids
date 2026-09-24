# Full Documentation — ML-Based Detection of Deauthentication Attacks in Edge-Computing Wi-Fi

This document explains **everything**: the background theory (networking, Wi-Fi,
the deauth attack, edge computing, machine learning), the system design, every
Python file, how to run each stage, how to read the results, and the project's
limitations and ethics. It is written so that someone who has never seen the
project can understand both *what* it does and *why* each decision was made —
enough to defend it in a DRDO internship review or expand it into an IEEE paper.

### Table of contents
1. [The problem in one paragraph](#1-the-problem-in-one-paragraph)
2. [Networking refresher](#2-networking-refresher)
3. [How Wi-Fi (802.11) actually works](#3-how-wi-fi-80211-actually-works)
4. [Edge computing and why it raises the stakes](#4-edge-computing-and-why-it-raises-the-stakes)
5. [The deauthentication attack, step by step](#5-the-deauthentication-attack-step-by-step)
6. [Existing defences and why we add ML](#6-existing-defences-and-why-we-add-ml)
7. [Machine-learning fundamentals used here](#7-machine-learning-fundamentals-used-here)
8. [System architecture](#8-system-architecture)
9. [The feature set — what the model actually looks at](#9-the-feature-set--what-the-model-actually-looks-at)
10. [Code walkthrough, file by file](#10-code-walkthrough-file-by-file)
11. [Running the project and reading the results](#11-running-the-project-and-reading-the-results)
12. [Ethics, legality and scope](#12-ethics-legality-and-scope)
13. [Limitations and future work](#13-limitations-and-future-work)
14. [Glossary](#14-glossary)

---

## 1. The problem in one paragraph

Wi-Fi management frames (the messages that set up and tear down connections) are
**not authenticated or encrypted** in classic 802.11. That means anyone nearby
can forge a "deauthentication" frame that tells a device *"you are now
disconnected."* The device believes it and drops off the network. Spammed
continuously, this becomes a **denial-of-service (DoS)** attack that can knock
cameras, sensors, and controllers offline — a serious problem in **edge-computing**
deployments where those devices are doing real work locally. This project builds
a system that **watches the airwaves, extracts statistical features from the
traffic, and uses a trained machine-learning model to raise an alert the moment a
deauth attack starts** — without any human staring at Wireshark.

---

## 2. Networking refresher

*(The vocabulary the rest of the project assumes.)*

**The OSI model** is a 7-layer mental map of how data moves across a network:

| Layer | Name         | Example thing living there              |
|-------|--------------|-----------------------------------------|
| 7     | Application  | HTTP, DNS                               |
| 6     | Presentation | TLS encryption, encoding                |
| 5     | Session      | connection state                        |
| 4     | Transport    | **TCP / UDP** (ports, reliability)      |
| 3     | Network      | **IP** addresses, routing               |
| 2     | Data Link    | **MAC** addresses, **Wi-Fi 802.11**, Ethernet |
| 1     | Physical     | radio waves, cables                     |

**TCP/IP model** is the practical 4-layer version everyone actually uses
(Application / Transport / Internet / Link). The key takeaway for us: **Wi-Fi
lives at Layer 2 (Data Link)**, and the deauth attack happens *there* — below IP,
below TCP, below any application. That is why an IP firewall can't see it and why
we must sniff raw 802.11 frames.

Two kinds of address matter:
- **IP address** (Layer 3): logical, routable, e.g. `192.168.1.20`. Can change.
- **MAC address** (Layer 2): a 48-bit hardware address burned into the Wi-Fi
  chip, e.g. `aa:bb:cc:dd:ee:ff`. Every 802.11 frame carries MAC addresses, and
  the attack **spoofs** them.

**Router vs Switch vs Access Point:**
- *Switch* — forwards frames between wired devices using MAC addresses (Layer 2).
- *Router* — forwards packets between different networks using IP (Layer 3).
- *Access Point (AP)* — the radio that bridges wireless clients onto the wired
  network. **This is what a deauth attack targets the connection to.** In home
  gear, all three are often the same physical box.

---

## 3. How Wi-Fi (802.11) actually works

*(This is the heart of what we monitor.)*

**IEEE 802.11** is the family of standards for wireless LANs (Wi-Fi). Core terms:

- **Access Point (AP)** — the base station clients connect to.
- **Station (STA) / Client** — a laptop, phone, IoT sensor, etc.
- **SSID** — the human-readable network name (e.g. `DRDO-Lab`).
- **BSSID** — the MAC address of the AP's radio; the machine-level identity of
  the network. The attacker forges frames *as if from this BSSID*.

**802.11 frames come in three types.** Understanding these is essential, because
the attack lives entirely in the first type:

1. **Management frames** — set up and manage the connection: *beacon*
   (AP advertising itself), *probe*, *authentication*, *association*, and
   crucially **deauthentication** and *disassociation*. In classic Wi-Fi these
   are **unencrypted and unauthenticated** — the fatal flaw.
2. **Control frames** — coordinate access to the channel: *RTS/CTS*, *ACK*.
3. **Data frames** — carry the actual payload (your IP packets).

Each frame's header has a **type** (2 bits) and **subtype** (4 bits). A
deauthentication frame is **type = 0 (management), subtype = 12**. Remember that
pair `(0, 12)` — the detector counts exactly these frames.

**How a client connects (the normal handshake):**
```
Client  ──probe──▶  AP           "who's out there?"
Client  ◀─beacon──  AP           "I'm SSID=DRDO-Lab, BSSID=aa:bb:.."
Client  ──auth───▶  AP           low-level 802.11 authentication
Client  ◀─auth────  AP
Client  ──assoc──▶  AP           association request
Client  ◀─assoc───  AP           "you're connected"
        (4-way WPA2 handshake establishes encryption keys)
```
The **4-way handshake** is where the encryption keys are derived. An attacker who
forces a client to reconnect (by deauthing it) can **capture that handshake** and
try to crack the Wi-Fi password offline — one reason deauth attacks are dangerous
beyond mere disconnection.

---

## 4. Edge computing and why it raises the stakes

*(The deployment context, and the "Edge Computing Environments" in the
paper title.)*

**Edge computing** pushes computation *close to where data is produced* instead
of sending everything to a distant cloud. Three layers:

```
┌─────────────┐   ┌────────────────┐   ┌───────────────┐
│ Device Layer│──▶│   Edge Layer   │──▶│  Cloud Layer  │
│ IoT sensors,│   │ local gateway/ │   │ heavy storage,│
│ cameras     │   │ edge node does │   │ training, BI  │
│             │   │ real-time work │   │               │
└─────────────┘   └────────────────┘   └───────────────┘
```

- **Device layer** — sensors, cameras, actuators (often Wi-Fi connected).
- **Edge layer** — a nearby node (gateway, micro-server) that processes data
  *locally* for **low latency** and to reduce bandwidth to the cloud.
- **Cloud layer** — long-term storage, model training, dashboards.

**Why use edge instead of cloud?** Latency (a safety controller can't wait for a
round trip to a data centre), bandwidth (don't ship raw video 24/7), privacy, and
resilience if the internet link drops.

**Why this matters for security:** edge nodes and their sensors usually talk over
**Wi-Fi**, are physically distributed (a factory floor, a border post, a field
deployment), and are exactly the devices a deauth attack can silence. Knocking an
edge camera or sensor offline can blind a monitoring system. So an IDS that runs
*at the edge*, detecting the attack locally and instantly, is a natural fit — and
it can itself run on the edge node, needing only a cheap Wi-Fi adapter.

---

## 5. The deauthentication attack, step by step

*(Understanding the attack completely.)*

Normal disconnect vs. attack:
```
NORMAL:   Client decides to leave ─▶ sends its own deauth ─▶ clean disconnect
ATTACK:   Attacker forges a deauth "from the AP" ─▶ Client is tricked ─▶ drops
```

**The mechanism:**
1. The attacker puts a Wi-Fi card into **monitor mode** so it can see and craft
   raw 802.11 frames.
2. They build a **deauthentication frame** (type 0, subtype 12) with the
   **source MAC spoofed to the AP's BSSID** and the destination set to a specific
   client (or `ff:ff:ff:ff:ff:ff` broadcast to hit everyone).
3. Because management frames aren't authenticated, the client **can't tell the
   forgery from a real message** and disconnects.
4. Sending these **continuously** = a **denial-of-service**: the client keeps
   getting kicked and can never stay connected.

**Related attacks that ride on top of it:**
- **Handshake capture** — deauth a client, watch it reconnect, capture the 4-way
  handshake, then brute-force the password offline.
- **Evil Twin** — stand up a fake AP with the same SSID; deauth clients off the
  real AP so they reconnect to *yours*, letting you intercept traffic.

**What the attack looks like on the wire (the signal our model learns):**
- a **surge in deauth frames** (`deauth_count` ↑↑) — the direct fingerprint;
- a **high packet rate** (`packet_rate` ↑) — floods are fast;
- **small, uniform frames** (`frame_length` ≈ 26–40 bytes) — deauth frames are tiny;
- **duration field ≈ 0** — deauth frames don't reserve airtime;
- **a few repeated MAC addresses** (`src/dst_mac_freq` ↑) — the spoofed BSSID and
  broadcast address dominate.

No single one of these is proof on its own (a client legitimately roaming between
APs produces *some* deauths). It is the **combination** that betrays an attack —
which is precisely why a machine-learning classifier, which weighs many features
together, beats a naive "if deauth_count > N" rule.

---

## 6. Existing defences and why we add ML

*(Security measures.)*

- **IEEE 802.11w (Protected Management Frames, PMF)** — cryptographically
  protects management frames so forged deauths are rejected. The real fix — but
  it requires *both* AP and client to support and enable it, and a huge installed
  base of IoT/edge devices doesn't.
- **WPA3** — the modern security suite; mandates PMF, so it closes the classic
  deauth hole. Again, adoption across cheap edge hardware is slow.
- **IDS (Intrusion Detection System)** — instead of *preventing* the forged
  frame, *detect* the attack and alert/respond. Works even with legacy devices
  that can't do 802.11w, because it only needs to *observe*.
- **ML-based detection** — a learned IDS that classifies traffic from statistical
  features. It generalises better than hand-written thresholds, adapts to
  different environments by retraining, and can catch *stealthy, low-rate* attacks
  that a fixed threshold would miss.

**This project is that last item:** an ML-based IDS. It complements (does not
replace) 802.11w/WPA3 — useful precisely where those can't be deployed.

---

## 7. Machine-learning fundamentals used here

*(Only the ML theory this project actually relies on.)*

**Classification** is teaching a model to assign an input to one of a fixed set
of categories. Here it's **binary**: `Normal (0)` vs `Attack (1)`.

- **Features** — the numeric inputs describing each example (our 7 traffic
  statistics). Collected into a matrix `X`.
- **Label** — the correct answer for each example (`0`/`1`). The vector `y`.
- **Training data** — examples *with* labels the model learns from.
- **Testing data** — held-out labelled examples the model has **never seen**,
  used to measure honest performance. We use an 80/20 split.

**Evaluation metrics** (computed on the test set). With TP/TN = correct
attack/normal calls and FP/FN = wrong ones:

- **Accuracy** = (TP+TN) / all — fraction correct overall. Misleading if classes
  are imbalanced, so we never rely on it alone.
- **Precision** = TP / (TP+FP) — of everything we *flagged as attack*, how much
  really was? Low precision ⇒ noisy false alarms.
- **Recall** = TP / (TP+FN) — of the *real attacks*, how many did we catch? Low
  recall ⇒ attacks slip through. **For an IDS this is the metric we protect most:
  a missed attack is worse than a false alarm.**
- **F1** = harmonic mean of precision and recall — one balanced number.
- **Confusion matrix** — the 2×2 table of TP/TN/FP/FN, so you see exactly *which*
  mistakes the model makes.

**Random Forest** (our chosen algorithm):
- A **decision tree** asks a sequence of yes/no questions on features
  (`deauth_count > 20?`, `packet_rate > 150?`) to reach a leaf that predicts a
  class. One tree is easy to read but **overfits** — it memorises noise.
- **Ensemble learning** fixes this: train **many** trees, each on a random subset
  of rows and features (this randomness is the "forest"), and have them **vote**.
  Averaging many decorrelated trees cancels out individual mistakes.
- Result: a model that captures the non-linear "combination of signals" logic a
  deauth attack shows, resists noise and outliers, needs little tuning, trains in
  seconds, and exposes **feature importance** so we can explain *why* it fired.

We also train a lone **Decision Tree** and an **SVM** for comparison, so the
choice of Random Forest is demonstrated rather than asserted.

---

## 8. System architecture

*(The system architecture. See also `docs/ARCHITECTURE.md`.)*

```
   ┌────────────┐   ┌────────────────┐   ┌───────────────────┐   ┌───────────────┐
   │  Wi-Fi     │   │  Scapy packet  │   │ Feature extraction│   │ Random Forest │
   │  traffic   │──▶│  sniffer       │──▶│ (per 2s window →  │──▶│ model         │
   │ (802.11)   │   │ (monitor mode) │   │  7-feature vector)│   │ (model.pkl)   │
   └────────────┘   └────────────────┘   └───────────────────┘   └───────┬───────┘
                                                                         │
                                            ┌────────────────────────────▼───────┐
                                            │  Prediction  →  Normal  /  ALERT!   │
                                            └────────────────────────────────────┘
```

The pipeline has an **offline training half** (generate → preprocess → train →
save `model.pkl`) and an **online detection half** (sniff → extract → load model
→ predict → alert). They meet at two saved artefacts: `model.pkl` (the trained
forest) and `scaler.pkl` (the feature scaler). The **feature schema in
`config.py` is the contract** that keeps both halves in sync.

---

## 9. The feature set — what the model actually looks at

*(Features — defined once in `src/config.py` as `FEATURE_COLUMNS`.)*

Each row/window is summarised by **7 numbers**:

| Feature          | Meaning                                             | Normal        | Under attack        |
|------------------|-----------------------------------------------------|---------------|---------------------|
| `frame_length`   | avg 802.11 frame size (bytes)                       | large & varied| ~26–40, uniform     |
| `rssi`           | avg received signal strength (dBm, negative)        | spread out    | strong & steady     |
| `packet_rate`    | frames per second in the window                     | low–moderate  | very high           |
| `duration`       | avg 802.11 duration/ID field (µs)                   | non-zero      | ~0                  |
| `src_mac_freq`   | repeat count of the busiest source MAC              | low           | high (spoofed BSSID)|
| `dst_mac_freq`   | repeat count of the busiest destination MAC         | low           | high (broadcast)    |
| `deauth_count`   | number of deauth frames (type 0, subtype 12)        | ~0            | large burst         |

**Why windows, not single packets?** A lone deauth frame is normal (clients leave
networks all the time). An *attack* is a **pattern over time**. So we aggregate
all frames seen in a short **time window** (default **2 seconds**) into these 7
statistics and classify the *window*. This is the single most important design
decision in the detector.

---

## 10. Code walkthrough, file by file

### `src/config.py` — the contract
Defines all file paths and, most importantly, `FEATURE_COLUMNS` — the exact list
and **order** of features. Training and detection both import it, so they can
never disagree about what feature vector the model expects. Reordering this list
without retraining would silently break predictions; centralising it prevents
that.

### `src/generate_dataset.py` — the data
Produces `data/wifi_deauth_dataset.csv`, a labelled stand-in for the **AWID**
dataset. It samples *Normal* and *Attack* rows from different distributions that
encode the real differences from §5. To keep the problem **honestly hard** (so
results aren't a fake 100%), it deliberately adds overlap:
- ~12% of *Normal* windows are **"busy"** — a client roaming or a device
  power-cycling produces some legitimate deauths and a packet burst.
- ~20% of *Attack* windows are **"stealthy"** — a low-and-slow deauth that mimics
  that busy-normal profile.
- ~2% **label noise** — a few mislabeled windows, as any real capture has.

> **Swapping in real AWID:** register at the AWID site, extract the same 7 columns
> plus a `label` (0/1) to `data/wifi_deauth_dataset.csv`, and **skip this script**.
> Everything downstream is unchanged.

### `src/dataset_preprocessing.py` — clean & prepare
1. **Load** the CSV and print `df.head()`, `df.info()`, `df.isnull().sum()` — the
   exact pandas checks the plan lists.
2. **Clean** — drop duplicates, fill any missing values with the column *median*
   (robust to the outliers an attack injects).
3. **Split** — separate `X`/`y`, then 80/20 train/test with `stratify=y` so the
   class ratio is preserved in both halves.
4. **Scale** — `StandardScaler` **fit on train only**, then applied to test. This
   avoids **data leakage** (letting the scaler peek at test data would inflate the
   score dishonestly). Tree models don't need scaling but the SVM comparison does.
5. **Visualise** — saves `outputs/histograms.png` (per-feature distributions,
   Normal vs Attack) and `outputs/correlation_matrix.png`.

Its `get_preprocessed()` is imported by the trainer, so there's exactly **one**
definition of "prepare the data" — no train/serve skew.

### `src/train_model.py` — build the detector
1. Calls `get_preprocessed()`.
2. `compare_models()` trains **Random Forest, Decision Tree, SVM** and prints a
   metrics table (the plan's "Try Other Models / Compare accuracy" step).
3. Trains the primary **Random Forest** (`n_estimators=200`,
   `class_weight="balanced"`).
4. `evaluate()` prints accuracy/precision/recall/F1 + `classification_report`,
   and saves `outputs/confusion_matrix.png`.
5. Saves `outputs/feature_importance.png` — which features drive the model.
6. Persists `models/model.pkl`, `models/scaler.pkl`, and `models/model_meta.json`
   (feature order + metrics). The scaler is saved **because live features must be
   scaled with the same statistics used in training**.

### `src/realtime_detector.py` — the live IDS
The online half. Key pieces:
- `WindowFeatureExtractor` — accumulates per-frame observations and, every
  window, computes the 7-feature vector (same order as `config.py`) then resets.
- `parse_dot11()` — turns a raw Scapy 802.11 packet into
  `(frame_length, rssi, duration, is_deauth, src_mac, dst_mac)`. A frame is a
  deauth iff `type == 0 and subtype == 12`.
- `classify_and_alert()` — scales the vector with the saved scaler, runs
  `model.predict`, and prints either `Normal traffic` or
  `*** ALERT! Deauthentication Attack Detected ***` with a confidence.
- **Three run modes** so it's demonstrable anywhere:
  - `--mode live --iface wlan0mon` — sniff a real monitor-mode NIC (Linux + root).
  - `--mode pcap --pcap file` — replay a capture file offline.
  - `--mode sim` — fabricate frames (no hardware) to show the full pipeline.

### `src/make_demo_pcap.py` — a test capture
Crafts `data/demo_capture.pcap` (normal frames, then a deauth burst, then normal
again) so `--mode pcap` can be exercised without a Wi-Fi card. It only *writes a
file*; it never transmits.

---

## 11. Running the project and reading the results

```bash
source .venv/bin/activate
python src/generate_dataset.py     # → data/wifi_deauth_dataset.csv
python src/train_model.py          # → models/*.pkl, outputs/*.png, metrics table
python src/realtime_detector.py --mode sim
```

**What you should see:**
- Training prints a comparison table where **Random Forest ≈ 0.98 F1** and beats
  the lone Decision Tree; a `classification_report`; and "saved" lines for the
  model and plots.
- `outputs/histograms.png` — Attack curves (orange) clearly separated from Normal
  (teal) on `deauth_count`, `packet_rate`, `frame_length`, with overlap on the
  hard cases.
- `outputs/correlation_matrix.png` — `deauth_count`, `packet_rate` most correlated
  with `label`.
- `outputs/confusion_matrix.png` — mostly on the diagonal; the few off-diagonal
  cells are the stealthy/busy overlap cases.
- `outputs/feature_importance.png` — `deauth_count` and `packet_rate` dominate,
  matching the theory in §5.
- Detector: silent (`Normal traffic`) on quiet windows, `*** ALERT! ***` during
  the attack window — the end-to-end goal.

**Interpreting the metrics for a report:** quote **recall** prominently (fraction
of real attacks caught) and show the confusion matrix. ~98% with a handful of
errors on deliberately ambiguous windows is a *credible, defensible* result — a
perfect 100% would suggest a dataset too easy to be meaningful.

---

## 12. Ethics, legality and scope

- This project is **defensive**: it *detects* attacks. It contains **no code that
  performs, injects, or transmits** a deauth attack. `make_demo_pcap.py` only
  writes frames to a file on disk for offline testing; nothing is sent over the air.
- **Capturing traffic on networks you don't own or administer may be illegal**
  in your jurisdiction. Only run `--mode live` on your **own lab network** or one
  you have **written authorisation** to test.
- Monitor mode captures *headers and metadata*; treat any captured data as
  sensitive and don't retain it beyond what your testing needs.

---

## 13. Limitations and future work

- **Synthetic data.** The included dataset is generated from domain knowledge, not
  captured over the air. It is realistic in structure but the *exact* numbers are
  modelled. Retrain on **real AWID** or your own captures before quoting results
  as production performance.
- **Binary only.** It distinguishes Normal vs deauth Attack. Extending to
  multi-class (evil-twin, disassociation floods, beacon floods) is natural — add
  labels and retrain.
- **Windowing latency.** A 2-second window trades detection speed against
  stability. Tune `--window` for your environment.
- **Concept drift.** Traffic patterns change; schedule periodic retraining.
- **Live hardware.** `--mode live` needs a Wi-Fi adapter that supports monitor
  mode (e.g. Atheros AR9271) on Linux, plus root. On macOS/Windows use `sim`/`pcap`.
- **Future work:** on-device (edge) inference, online/streaming learning, XGBoost
  and deep models, integration with 802.11w-capable APs for automatic response.

### Setting up live capture (Linux)
```bash
sudo apt install aircrack-ng
sudo airmon-ng start wlan0            # creates monitor interface wlan0mon
sudo python src/realtime_detector.py --mode live --iface wlan0mon
sudo airmon-ng stop wlan0mon         # restore normal Wi-Fi when done
```

---

## 14. Glossary

- **802.11** — the IEEE Wi-Fi standard family.
- **AP / BSSID / SSID** — access point / its MAC / the network name.
- **Station (STA)** — a Wi-Fi client device.
- **Management/Control/Data frame** — the three 802.11 frame types; the attack
  uses a management frame.
- **Deauthentication frame** — 802.11 type 0, subtype 12; tells a client to
  disconnect. Forgeable in classic Wi-Fi.
- **Monitor mode** — a NIC mode that captures all raw 802.11 frames in range.
- **DoS** — denial of service.
- **RSSI** — received signal strength indicator (dBm; less negative = stronger).
- **AWID** — a public Wi-Fi intrusion dataset.
- **Feature / Label** — model inputs / the correct answer.
- **Random Forest** — an ensemble of decision trees that vote.
- **Precision / Recall / F1** — attack-detection quality metrics (see §7).
- **Data leakage** — accidentally letting test information influence training.
- **802.11w / WPA3 / PMF** — modern standards that protect management frames.
