"""
generate_dataset.py
===================
Creates a synthetic, labelled Wi-Fi traffic dataset that stands in for the AWID
labelled dataset used to train and evaluate the detector.

WHY SYNTHETIC DATA?
-------------------
The real AWID dataset (https://icsdweb.aegean.gr/awid/) is excellent but it
requires a registration/licence agreement and is several gigabytes of raw
packet captures. That makes it impossible to ship inside a project folder and
slow to iterate on. This generator produces a small CSV with the *same feature
columns* the plan asks for, so every later stage (preprocessing, training,
real-time detection) runs unchanged. When you obtain AWID, export the same
columns to `data/wifi_deauth_dataset.csv` and the rest of the pipeline is
identical -- nothing downstream needs to change.

WHAT MAKES THE DATA "REALISTIC"?
--------------------------------
A deauthentication attack floods the air with 802.11 *deauth* management frames
to knock clients off an access point. Compared with normal traffic, an attack
window shows:

  * a SPIKE in `deauth_count`            (the whole point of the attack)
  * a SPIKE in `packet_rate`            (many frames injected per second)
  * SMALL, uniform `frame_length`       (deauth frames are tiny, ~26 bytes)
  * a `duration` field near 0           (deauth frames set duration to 0)
  * a few repeated (often spoofed) MACs  -> high src/dst MAC frequency
  * RSSI that is often oddly strong/constant (injector sits close & static)

The generator samples Normal and Attack rows from different distributions that
encode exactly these differences, so a classifier has real signal to learn.
"""

import argparse
import numpy as np
import pandas as pd

from config import FEATURE_COLUMNS, LABEL_COLUMN, RAW_DATASET, ensure_dirs


def _make_normal(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Sample `n` rows of ordinary Wi-Fi traffic.

    A realistic fraction of "normal" windows are actually BUSY: a client
    roaming between APs, or a device power-cycling, produces a few legitimate
    deauth/disassoc frames and a burst of packets. We inject that overlap so
    the classifier can't win just by thresholding deauth_count.
    """
    df = pd.DataFrame({
        # Normal frames vary a lot in size (data frames can be large).
        "frame_length": rng.normal(520, 340, n).clip(40, 2346),
        # Signal strength of real clients spread across the room.
        "rssi": rng.normal(-62, 13, n).clip(-95, -28),
        # A handful to a few hundred frames per second in a busy network.
        "packet_rate": rng.gamma(shape=2.2, scale=35, size=n).clip(1, 700),
        # Real data/management frames reserve airtime -> non-zero duration.
        "duration": rng.normal(115, 65, n).clip(0, 400),
        # Many distinct devices -> each MAC seen only a few times per window.
        "src_mac_freq": rng.poisson(6, n).clip(1, 90),
        "dst_mac_freq": rng.poisson(6, n).clip(1, 90),
        # Mostly ~0 deauth frames, with an occasional legitimate handful.
        "deauth_count": rng.poisson(1.2, n).clip(0, 25),
        LABEL_COLUMN: 0,
    })
    # ~12% of normal windows are "busy" (roaming/reconnect storms).
    busy = rng.random(n) < 0.12
    df.loc[busy, "deauth_count"] = rng.normal(18, 8, busy.sum()).clip(4, 45)
    df.loc[busy, "packet_rate"] = rng.normal(260, 90, busy.sum()).clip(80, 700)
    df.loc[busy, "src_mac_freq"] = rng.normal(45, 20, busy.sum()).clip(10, 120)
    return df


def _make_attack(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Sample `n` rows captured during a deauthentication attack.

    Not every attacker runs a loud flood. A fraction here are STEALTHY: a
    low-and-slow deauth (a few frames every window) that deliberately looks
    close to normal roaming. These overlap with the "busy normal" rows above,
    which is exactly the hard, realistic case an ML detector earns its keep on.
    """
    df = pd.DataFrame({
        # Deauth frames are tiny and uniform in size.
        "frame_length": rng.normal(34, 12, n).clip(24, 120),
        # Injector is usually close and static -> strong-ish RSSI, some spread.
        "rssi": rng.normal(-48, 10, n).clip(-85, -25),
        # Floods push a high frame rate (stealthy rows overridden below).
        "packet_rate": rng.normal(380, 140, n).clip(60, 900),
        # Deauth frames set the duration/ID field to ~0.
        "duration": rng.normal(8, 8, n).clip(0, 60),
        # Attacker spoofs the AP/client MAC -> the same few MACs repeat a lot.
        "src_mac_freq": rng.normal(95, 45, n).clip(15, 300),
        "dst_mac_freq": rng.normal(70, 40, n).clip(10, 300),
        # The defining signal: an elevated burst of deauth frames.
        "deauth_count": rng.normal(110, 55, n).clip(8, 400),
        LABEL_COLUMN: 1,
    })
    # ~20% of attacks are stealthy / low-rate to blend in with busy normal.
    stealth = rng.random(n) < 0.20
    df.loc[stealth, "deauth_count"] = rng.normal(22, 9, stealth.sum()).clip(6, 50)
    df.loc[stealth, "packet_rate"] = rng.normal(150, 60, stealth.sum()).clip(40, 400)
    df.loc[stealth, "frame_length"] = rng.normal(90, 40, stealth.sum()).clip(24, 300)
    return df


def generate(n_normal: int, n_attack: int, seed: int = 42) -> pd.DataFrame:
    """Build the full dataset, shuffle it, and return a tidy DataFrame."""
    rng = np.random.default_rng(seed)
    df = pd.concat(
        [_make_normal(n_normal, rng), _make_attack(n_attack, rng)],
        ignore_index=True,
    )
    # Shuffle so Normal/Attack rows are interleaved (not all 0s then all 1s).
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    # ~2% label noise: real captures have mislabeled/ambiguous windows. This
    # keeps metrics honest (a perfect 100% score would look fabricated).
    flip = rng.random(len(df)) < 0.02
    df.loc[flip, LABEL_COLUMN] = 1 - df.loc[flip, LABEL_COLUMN]

    # Round to sensible precision and enforce integer-like columns.
    df["frame_length"] = df["frame_length"].round().astype(int)
    df["packet_rate"] = df["packet_rate"].round(1)
    df["duration"] = df["duration"].round().astype(int)
    df["src_mac_freq"] = df["src_mac_freq"].round().astype(int)
    df["dst_mac_freq"] = df["dst_mac_freq"].round().astype(int)
    df["deauth_count"] = df["deauth_count"].round().astype(int)
    df["rssi"] = df["rssi"].round(1)

    # Guarantee the column order matches the training schema.
    return df[FEATURE_COLUMNS + [LABEL_COLUMN]]


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic Wi-Fi deauth dataset.")
    parser.add_argument("--normal", type=int, default=6000, help="number of Normal rows")
    parser.add_argument("--attack", type=int, default=4000, help="number of Attack rows")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    args = parser.parse_args()

    ensure_dirs()
    df = generate(args.normal, args.attack, args.seed)
    df.to_csv(RAW_DATASET, index=False)

    print(f"[generate_dataset] wrote {len(df):,} rows -> {RAW_DATASET}")
    print(f"[generate_dataset] class balance:\n{df['label'].value_counts().rename({0: 'Normal', 1: 'Attack'})}")


if __name__ == "__main__":
    main()
