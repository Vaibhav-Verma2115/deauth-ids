"""
make_demo_pcap.py
=================
Helper: craft a small 802.11 capture file (`data/demo_capture.pcap`) that
contains a stretch of normal management/data frames followed by a burst of
deauthentication frames. This lets you exercise `realtime_detector.py --mode
pcap` without owning a monitor-mode Wi-Fi card.

Each packet is a real RadioTap + Dot11 frame, so scapy's parse_dot11() in the
detector reads them exactly as it would read live-captured traffic.

NOTE: this only *writes a file to disk*. It does not transmit anything.
"""

import numpy as np
from scapy.all import RadioTap, Dot11, Dot11Deauth, wrpcap, Raw

from config import DATA_DIR, ensure_dirs

AP = "aa:bb:cc:dd:ee:ff"        # (fake) access point MAC
BCAST = "ff:ff:ff:ff:ff:ff"     # broadcast


def normal_frame(rng):
    """A benign data frame between two random clients."""
    src = "11:22:33:%02x:%02x:%02x" % tuple(rng.integers(0, 255, 3))
    dst = "44:55:66:%02x:%02x:%02x" % tuple(rng.integers(0, 255, 3))
    # type=2 -> Data frame; pad with random bytes for a realistic length.
    pkt = RadioTap() / Dot11(type=2, subtype=0, addr1=dst, addr2=src, addr3=AP)
    pkt = pkt / Raw(load=bytes(rng.integers(0, 255, int(rng.integers(60, 400)))))
    return pkt


def deauth_frame():
    """A deauthentication frame from the (spoofed) AP to broadcast."""
    # type=0 subtype=12 is exactly what the detector counts as a deauth.
    return RadioTap() / Dot11(type=0, subtype=12, addr1=BCAST, addr2=AP, addr3=AP) / Dot11Deauth(reason=7)


def main():
    ensure_dirs()
    rng = np.random.default_rng(1)
    packets = []

    # ~800 normal frames
    for _ in range(800):
        packets.append(normal_frame(rng))

    # ~600 deauth frames (the attack burst)
    for _ in range(600):
        packets.append(deauth_frame())

    # ~400 more normal frames (attack stops, traffic recovers)
    for _ in range(400):
        packets.append(normal_frame(rng))

    out = DATA_DIR / "demo_capture.pcap"
    wrpcap(str(out), packets)
    print(f"[make_demo_pcap] wrote {len(packets)} frames -> {out}")


if __name__ == "__main__":
    main()
