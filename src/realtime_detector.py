"""
realtime_detector.py
====================
The live Intrusion Detection System (IDS): sniff, extract, predict, alert.

This is the live end of the project. It ties everything together following the
Day-7 architecture:

    Wi-Fi Traffic -> Scapy Packet Sniffer -> Feature Extraction
                  -> Pandas/NumPy vector -> Random Forest Model
                  -> Prediction -> Alert

HOW IT WORKS
------------
802.11 frames don't carry a "this is an attack" flag; the attack only shows up
as a *pattern over time*. So we can't classify one packet in isolation -- we
collect frames into a short time WINDOW (default 2 seconds), compute the same 7
features the model was trained on for that window, and classify the window.

  * A **deauthentication** frame is 802.11 type 0 (management), subtype 12.
    Counting these per window gives `deauth_count`, the strongest signal.
  * `packet_rate` = frames in the window / window length.
  * `frame_length`, `rssi`, `duration` are averaged over the window.
  * `src_mac_freq` / `dst_mac_freq` = how often the most-active MAC repeats,
    which spikes when an attacker spoofs one address and floods.

THREE RUN MODES (so you can demo it with or without special hardware)
---------------------------------------------------------------------
  --mode live  --iface wlan0mon   Sniff a real monitor-mode interface (needs
                                  a capable Wi-Fi card + root; see README).
  --mode pcap  --pcap file.pcap   Replay a capture file offline.
  --mode sim                      Generate synthetic frames (no hardware) so
                                  you can watch the full alert pipeline work.

Only `live` mode needs monitor mode / root. `pcap` and `sim` run anywhere,
which is what makes this script demonstrable on any laptop for the report.

SAFETY / SCOPE
--------------
This tool is passive and DEFENSIVE. It only *listens* and classifies traffic;
it never transmits, injects, or deauthenticates anything. Capturing traffic on
networks you don't own or administer may be illegal -- only run live mode on
your own lab network.
"""

import argparse
import time
import json
from collections import deque, Counter

import numpy as np
import joblib

from config import (
    FEATURE_COLUMNS, CLASS_NAMES, MODEL_PATH, SCALER_PATH, METADATA_PATH,
)

# Scapy is only needed for live/pcap modes. Import lazily so `sim` mode works
# even on a machine where scapy's runtime deps aren't fully set up.
try:
    from scapy.all import sniff, rdpcap, Dot11, RadioTap
    SCAPY_OK = True
except Exception as _e:            # pragma: no cover - environment dependent
    SCAPY_OK = False
    _SCAPY_ERR = _e


# 802.11 constants
DOT11_TYPE_MANAGEMENT = 0
DOT11_SUBTYPE_DEAUTH = 12


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------
def load_model():
    """Load the trained model + scaler produced by train_model.py."""
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        raise SystemExit(
            "[error] model.pkl / scaler.pkl not found. Run train_model.py first."
        )
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    meta = {}
    if METADATA_PATH.exists():
        meta = json.loads(METADATA_PATH.read_text())
    return model, scaler, meta


# ---------------------------------------------------------------------------
# Windowed feature extraction
# ---------------------------------------------------------------------------
class WindowFeatureExtractor:
    """Accumulates per-frame observations and turns a time window into one
    feature vector matching FEATURE_COLUMNS (same order as training)."""

    def __init__(self, window_seconds=2.0):
        self.window_seconds = window_seconds
        self._reset()

    def _reset(self):
        self.frame_lengths = []
        self.rssis = []
        self.durations = []
        self.deauth_count = 0
        self.src_macs = Counter()
        self.dst_macs = Counter()
        self.n_frames = 0
        self.window_start = time.time()

    def add(self, frame_length, rssi, duration, is_deauth, src_mac, dst_mac):
        """Record one observed frame."""
        self.frame_lengths.append(frame_length)
        self.rssis.append(rssi)
        self.durations.append(duration)
        self.deauth_count += int(is_deauth)
        if src_mac:
            self.src_macs[src_mac] += 1
        if dst_mac:
            self.dst_macs[dst_mac] += 1
        self.n_frames += 1

    def ready(self):
        """True once the window duration has elapsed."""
        return (time.time() - self.window_start) >= self.window_seconds

    def build_vector(self):
        """Compute the 7-feature vector for the current window, then reset.

        Returns None if the window was empty (nothing to classify)."""
        if self.n_frames == 0:
            self._reset()
            return None

        # packet_rate = frames per second. Use the nominal window length as the
        # denominator: in live mode ready() fires at ~window_seconds anyway, and
        # in sim/pcap mode (frames produced in a tight loop) real elapsed time
        # is ~0, which would blow the rate up to nonsense. Fall back to measured
        # elapsed only if no nominal window was set.
        denom = self.window_seconds if self.window_seconds > 0 else \
            max(time.time() - self.window_start, 1e-6)
        feats = {
            "frame_length": float(np.mean(self.frame_lengths)),
            "rssi": float(np.mean(self.rssis)),
            "packet_rate": self.n_frames / denom,
            "duration": float(np.mean(self.durations)),
            # "frequency" of the single most active MAC in the window.
            "src_mac_freq": self.src_macs.most_common(1)[0][1] if self.src_macs else 0,
            "dst_mac_freq": self.dst_macs.most_common(1)[0][1] if self.dst_macs else 0,
            "deauth_count": self.deauth_count,
        }
        vector = np.array([feats[c] for c in FEATURE_COLUMNS], dtype=float)
        n = self.n_frames
        self._reset()
        return vector, feats, n


# ---------------------------------------------------------------------------
# Classification + alerting
# ---------------------------------------------------------------------------
def classify_window(vector, feats, n_frames, model, scaler):
    """Scale one window's vector and predict. Pure computation, no output.

    Returns a result dict so callers can render it however they like (the CLI
    prints a line; webgui.py pushes it to the browser and draws a dashboard)."""
    scaled = scaler.transform(vector.reshape(1, -1))
    pred = int(model.predict(scaled)[0])
    # Probability of the predicted class, if the model exposes it.
    try:
        conf = float(model.predict_proba(scaled)[0][pred])
    except Exception:
        conf = float("nan")

    return {
        "time": time.strftime("%H:%M:%S"),
        "pred": pred,
        "label": CLASS_NAMES[pred],
        "conf": conf,
        "n_frames": n_frames,
        "feats": feats,
    }


def format_result(r):
    """Render a result dict as the one-line console message."""
    tail = (f"| frames={r['n_frames']} deauth={int(r['feats']['deauth_count'])} "
            f"rate={r['feats']['packet_rate']:.0f}/s")
    if r["pred"] == 1:
        return (f"[{r['time']}] *** ALERT! Deauthentication Attack Detected *** "
                f"(conf={r['conf']:.2f}) {tail}")
    return f"[{r['time']}] Normal traffic (conf={r['conf']:.2f}) {tail}"


def classify_and_alert(vector, feats, n_frames, model, scaler, on_result=None):
    """Classify a window and report it.

    `on_result` receives the result dict when given (used by the GUI); with no
    callback the behaviour is unchanged -- one printed line per window."""
    r = classify_window(vector, feats, n_frames, model, scaler)
    if on_result is not None:
        on_result(r)
    else:
        print(format_result(r))
    return r["pred"]


# ---------------------------------------------------------------------------
# Turning a raw scapy frame into the fields the extractor needs
# ---------------------------------------------------------------------------
def parse_dot11(pkt):
    """Extract (frame_length, rssi, duration, is_deauth, src, dst) from a
    scapy 802.11 packet. Returns None for non-802.11 frames."""
    if not pkt.haslayer(Dot11):
        return None
    dot11 = pkt.getlayer(Dot11)

    is_deauth = (dot11.type == DOT11_TYPE_MANAGEMENT
                 and dot11.subtype == DOT11_SUBTYPE_DEAUTH)

    # RSSI lives in the RadioTap header the monitor interface prepends.
    rssi = -70
    if pkt.haslayer(RadioTap):
        rssi = getattr(pkt.getlayer(RadioTap), "dBm_AntSignal", None)
        if rssi is None:
            rssi = -70

    duration = getattr(dot11, "ID", 0) or 0
    return (
        len(pkt),               # frame_length
        float(rssi),            # rssi
        float(duration),        # duration
        is_deauth,              # is_deauth
        dot11.addr2,            # source MAC
        dot11.addr1,            # destination MAC
    )


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------
def run_live(iface, window, model, scaler, on_result=None, should_stop=None):
    """Sniff a real monitor-mode interface indefinitely."""
    if not SCAPY_OK:
        raise SystemExit(f"[error] scapy unavailable: {_SCAPY_ERR}")
    extractor = WindowFeatureExtractor(window)
    print(f"[live] sniffing {iface} in {window:.0f}s windows. Ctrl-C to stop.\n")

    def on_packet(pkt):
        parsed = parse_dot11(pkt)
        if parsed:
            extractor.add(*parsed)
        if extractor.ready():
            built = extractor.build_vector()
            if built:
                classify_and_alert(*built, model, scaler, on_result=on_result)

    # stop_filter is consulted per packet, which lets the GUI's Stop button
    # break out of the sniff loop without killing the process.
    stop_filter = (lambda _pkt: should_stop()) if should_stop else None
    sniff(iface=iface, prn=on_packet, store=False, stop_filter=stop_filter)


def run_pcap(pcap_path, window, model, scaler, on_result=None, should_stop=None):
    """Replay a capture file, emitting a decision every `window` frames worth."""
    if not SCAPY_OK:
        raise SystemExit(f"[error] scapy unavailable: {_SCAPY_ERR}")
    print(f"[pcap] reading {pcap_path} ...")
    packets = rdpcap(pcap_path)
    # For offline replay we window by frame COUNT and flush manually; keep the
    # nominal `window` length so packet_rate is computed against a sane period.
    extractor = WindowFeatureExtractor(window)
    per_window = 200
    for i, pkt in enumerate(packets, 1):
        if should_stop and should_stop():
            return
        parsed = parse_dot11(pkt)
        if parsed:
            extractor.add(*parsed)
        if i % per_window == 0:
            built = extractor.build_vector()
            if built:
                classify_and_alert(*built, model, scaler, on_result=on_result)
    built = extractor.build_vector()
    if built:
        classify_and_alert(*built, model, scaler, on_result=on_result)


def run_sim(window, model, scaler, n_windows=20, attack_windows=None,
            on_result=None, should_stop=None, pause=0.15):
    """No hardware needed: fabricate frames for Normal and Attack windows so
    you can watch the full sniff->feature->predict->alert pipeline live.

    This reuses the SAME statistical model as generate_dataset.py, so the
    frames look like real captured traffic to the extractor.

    `n_windows=0` runs until `should_stop()` returns True (the GUI's continuous
    monitoring mode). `attack_windows` may be a set of window numbers or a
    predicate `f(window_number) -> bool` for recurring bursts."""
    rng = np.random.default_rng(7)
    if attack_windows is None:
        # Make windows 8..12 the "attack" window to show the transition.
        attack_windows = set(range(8, 13))

    if callable(attack_windows):
        is_attack = attack_windows
    else:
        is_attack = lambda w: w in attack_windows          # noqa: E731

    if on_result is None:
        where = (f"{n_windows} windows" if n_windows else "until stopped")
        print(f"[sim] simulating {where} of ~{window:.0f}s each "
              f"(attack during windows {sorted(attack_windows)}).\n"
              if not callable(attack_windows) else
              f"[sim] simulating {where} of ~{window:.0f}s each.\n")

    extractor = WindowFeatureExtractor(window)
    w = 0
    while True:
        w += 1
        if n_windows and w > n_windows:
            break
        if should_stop and should_stop():
            break
        attack = is_attack(w)
        # Number of frames this window: floods produce many more.
        n = int(rng.normal(600, 80)) if attack else int(rng.normal(90, 25))
        n = max(n, 5)
        for _ in range(n):
            if attack:
                fl = rng.normal(30, 6)
                rssi = rng.normal(-45, 6)
                dur = rng.normal(5, 5)
                is_deauth = rng.random() < 0.4     # ~40% of flood is deauth
                src = "aa:bb:cc:dd:ee:ff"           # spoofed AP MAC repeats
                dst = "ff:ff:ff:ff:ff:ff"           # broadcast deauth
            else:
                fl = rng.normal(560, 380)
                rssi = rng.normal(-62, 12)
                dur = rng.normal(120, 60)
                is_deauth = rng.random() < 0.003
                src = f"11:22:33:{rng.integers(0,255):02x}:{rng.integers(0,255):02x}:{rng.integers(0,255):02x}"
                dst = f"44:55:66:{rng.integers(0,255):02x}:{rng.integers(0,255):02x}:{rng.integers(0,255):02x}"
            extractor.add(max(fl, 24), rssi, max(dur, 0), is_deauth, src, dst)
        # Flush this window regardless of wall-clock time.
        built = extractor.build_vector()
        if built:
            classify_and_alert(*built, model, scaler, on_result=on_result)
        if pause:
            time.sleep(pause)  # tiny pause so output reads like a live stream


def main():
    parser = argparse.ArgumentParser(
        description="Real-time ML-based deauthentication attack detector (defensive IDS).")
    parser.add_argument("--mode", choices=["live", "pcap", "sim"], default="sim",
                        help="live=sniff NIC, pcap=replay file, sim=synthetic demo")
    parser.add_argument("--iface", default="wlan0mon", help="monitor-mode interface (live mode)")
    parser.add_argument("--pcap", help="path to a .pcap/.pcapng file (pcap mode)")
    parser.add_argument("--window", type=float, default=2.0, help="window length in seconds")
    args = parser.parse_args()

    model, scaler, meta = load_model()
    if meta.get("metrics"):
        m = meta["metrics"]
        print(f"[model] loaded RF  (test F1={m.get('f1', 0):.3f}, "
              f"recall={m.get('recall', 0):.3f})\n")

    if args.mode == "live":
        run_live(args.iface, args.window, model, scaler)
    elif args.mode == "pcap":
        if not args.pcap:
            raise SystemExit("[error] --pcap FILE is required in pcap mode")
        run_pcap(args.pcap, args.window, model, scaler)
    else:
        run_sim(args.window, model, scaler)


if __name__ == "__main__":
    main()
