# Architecture & Flowchart

*(Flowchart: Traffic → Feature Extraction → ML Model →
Attack Classification → Alert Generation".)*

## 1. End-to-end data flow (the required flowchart)

```mermaid
flowchart LR
    A[Wi-Fi Traffic<br/>802.11 frames] --> B[Scapy Packet Sniffer<br/>monitor mode]
    B --> C[Feature Extraction<br/>per 2-second window]
    C --> D[Feature Vector<br/>7 features - NumPy/pandas]
    D --> E[StandardScaler<br/>scaler.pkl]
    E --> F[Random Forest Model<br/>model.pkl]
    F --> G{Prediction}
    G -->|label = 0| H[Normal traffic]
    G -->|label = 1| I[ALERT!<br/>Deauthentication Attack Detected]
```

Plain-text version (for the report, if Mermaid isn't rendered):

```
Wi-Fi Traffic ─▶ Scapy Sniffer ─▶ Feature Extraction ─▶ 7-feature vector
             ─▶ StandardScaler ─▶ Random Forest ─▶ Prediction
             ─▶  0 = Normal traffic
                 1 = ALERT! Deauthentication Attack Detected
```

## 2. Two halves: offline training vs. online detection

```mermaid
flowchart TB
    subgraph OFFLINE[Offline — training half]
        A1[generate_dataset.py<br/>synthetic AWID-like CSV] --> A2[dataset_preprocessing.py<br/>clean / split / scale]
        A2 --> A3[train_model.py<br/>Random Forest + compare DT/SVM]
        A3 --> A4[(model.pkl)]
        A3 --> A5[(scaler.pkl)]
    end
    subgraph ONLINE[Online — detection half]
        B1[Wi-Fi frames] --> B2[realtime_detector.py<br/>sniff + window features]
        B2 --> B3[predict]
        B3 --> B4[Normal / ALERT]
    end
    A4 --> B3
    A5 --> B2
    CFG[config.py<br/>FEATURE_COLUMNS contract] -.governs.-> A2
    CFG -.governs.-> B2
```

The two halves are decoupled and communicate only through the saved artefacts
`model.pkl` and `scaler.pkl`. `config.py` is the shared contract guaranteeing the
feature vector built at detection time matches what the model was trained on.

## 3. Windowing (why the sniffer batches frames)

```
time ──▶
frames:  d . . d . . . . | D D D D D D D D D | . . d . . . .
         └── window 1 ───┘└─── window 2 ─────┘└── window 3 ──┘
              Normal            ATTACK             Normal
   (d = a stray deauth,  D = attack deauth flood)
```

Each window becomes one 7-feature vector → one prediction. A single deauth (`d`)
is normal; a *burst* (`D…D`) within a window is what tips `deauth_count`,
`packet_rate`, and the MAC-frequency features into the Attack region of the
model's decision boundary.

## 4. Component responsibilities

| Component                 | Input                     | Output                        |
|---------------------------|---------------------------|-------------------------------|
| `generate_dataset.py`     | parameters (row counts)   | labelled CSV                  |
| `dataset_preprocessing.py`| CSV                       | scaled train/test arrays + plots |
| `train_model.py`          | arrays                    | `model.pkl`, `scaler.pkl`, metrics, plots |
| `realtime_detector.py`    | live NIC / pcap / sim     | per-window Normal/ALERT lines |
| `config.py`               | —                         | shared paths + feature schema |
