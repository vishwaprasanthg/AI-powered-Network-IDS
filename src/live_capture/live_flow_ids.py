import csv
import os
import time
from datetime import datetime

import joblib
import pandas as pd
from scapy.all import IP, TCP, UDP, sniff

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

ALERTS_PATH = os.path.join(PROJECT_ROOT, "src", "realtime", "alerts_log.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "live_random_forest.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "models", "live_scaler.pkl")
FEATURE_PATH = os.path.join(PROJECT_ROOT, "models", "live_feature_names.pkl")

EXPECTED_HEADER = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Prediction",
]

FLOW_TIMEOUT = float(os.getenv("IDS_FLOW_TIMEOUT", "2.0"))
INTERFACE = os.getenv("IDS_INTERFACE", r"\Device\NPF_Loopback")
BPF_FILTER = os.getenv("IDS_BPF_FILTER", "tcp or udp")
SYN_FLOOD_SYN_THRESHOLD = int(os.getenv("IDS_SYN_THRESHOLD", "20"))
SYN_FLOOD_ACK_MAX = int(os.getenv("IDS_SYN_ACK_MAX", "1"))
MIN_PACKETS_FOR_SYN_RULE = int(os.getenv("IDS_SYN_MIN_PACKETS", "10"))
LOG_ATTACKS_ONLY = os.getenv("IDS_LOG_ATTACKS_ONLY", "false").lower() in {"1", "true", "yes"}

flows = {}
model = None
scaler = None
feature_names = None


def ensure_alert_log_header():
    os.makedirs(os.path.dirname(ALERTS_PATH), exist_ok=True)

    if not os.path.exists(ALERTS_PATH) or os.path.getsize(ALERTS_PATH) == 0:
        with open(ALERTS_PATH, "w", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow(EXPECTED_HEADER)
        return

    with open(ALERTS_PATH, "r", encoding="utf-8", errors="ignore") as file:
        first_line = file.readline().strip().lower().replace(" ", "")

    valid = (
        "timestamp" in first_line
        and "sourceip" in first_line
        and "destinationip" in first_line
        and "prediction" in first_line
    )

    if not valid:
        with open(ALERTS_PATH, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
        with open(ALERTS_PATH, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADER)
            file.write(content)


def load_components():
    global model, scaler, feature_names

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_names = joblib.load(FEATURE_PATH)


def classify_flow(flow_features):
    try:
        df = pd.DataFrame([flow_features], columns=feature_names)
        df_scaled = scaler.transform(df)
        prediction = int(model.predict(df_scaled)[0])

        confidence = None
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(df_scaled)[0]
            confidence = float(probs[prediction])

        return prediction, confidence
    except Exception as exc:
        print(f"[WARN] Flow classification failed: {exc}")
        return 0, None


def build_flow_features(flow, duration):
    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

    return [
        duration,
        flow["fwd_packets"],
        flow["bwd_packets"],
        flow["fwd_bytes"],
        flow["bwd_bytes"],
        (flow["fwd_bytes"] / flow["fwd_packets"]) if flow["fwd_packets"] > 0 else 0,
        (total_bytes / duration) if duration > 0 else 0,
        (total_packets / duration) if duration > 0 else 0,
        flow["syn_count"],
        flow["ack_count"],
        flow["rst_count"],
        flow["fin_count"],
    ]


def log_alert(flow_key, prediction):
    if LOG_ATTACKS_ONLY and prediction != 1:
        return

    with open(ALERTS_PATH, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            flow_key[0],
            flow_key[1],
            flow_key[2],
            flow_key[3],
            flow_key[4],
            "ATTACK" if prediction == 1 else "NORMAL",
        ])


def is_syn_flood_like(flow):
    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    return (
        flow["syn_count"] >= SYN_FLOOD_SYN_THRESHOLD
        and flow["ack_count"] <= SYN_FLOOD_ACK_MAX
        and total_packets >= MIN_PACKETS_FOR_SYN_RULE
    )


def finalize_flow(flow_key, reason=None):
    flow = flows.get(flow_key)
    if not flow:
        return

    duration = max(flow["last_seen"] - flow["start_time"], 1e-6)
    features = build_flow_features(flow, duration)
    prediction, confidence = classify_flow(features)

    if reason == "SYN_FLOOD" or is_syn_flood_like(flow):
        reason = "SYN_FLOOD"
        prediction = 1

    label = "ATTACK" if prediction == 1 else "NORMAL"
    conf_text = f" confidence={confidence:.3f}" if confidence is not None else ""
    reason_text = f" reason={reason}" if reason else ""

    print(
        f"[FLOW] {flow_key} duration={duration:.2f}s "
        f"packets={flow['fwd_packets'] + flow['bwd_packets']} label={label}{conf_text}{reason_text}"
    )

    log_alert(flow_key, prediction)
    del flows[flow_key]


def flush_expired_flows(now_ts):
    expired = [
        key for key, flow in flows.items() if now_ts - flow["last_seen"] >= FLOW_TIMEOUT
    ]
    for key in expired:
        finalize_flow(key)


def process_packet(packet):
    if IP not in packet:
        return

    if TCP in packet:
        proto = "TCP"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif UDP in packet:
        proto = "UDP"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    else:
        return

    flow_key = (packet[IP].src, packet[IP].dst, sport, dport, proto)
    reverse_key = (packet[IP].dst, packet[IP].src, dport, sport, proto)

    if reverse_key in flows:
        flow_key = reverse_key

    now_ts = time.time()

    if flow_key not in flows:
        flows[flow_key] = {
            "start_time": now_ts,
            "last_seen": now_ts,
            "fwd_packets": 0,
            "bwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "syn_count": 0,
            "ack_count": 0,
            "rst_count": 0,
            "fin_count": 0,
        }

    flow = flows[flow_key]
    flow["last_seen"] = now_ts

    if packet[IP].src == flow_key[0]:
        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += len(packet)
    else:
        flow["bwd_packets"] += 1
        flow["bwd_bytes"] += len(packet)

    if TCP in packet:
        flags = int(packet[TCP].flags)
        if flags & 0x02:
            flow["syn_count"] += 1
        if flags & 0x10:
            flow["ack_count"] += 1
        if flags & 0x04:
            flow["rst_count"] += 1
        if flags & 0x01:
            flow["fin_count"] += 1

    flush_expired_flows(now_ts)


def main():
    ensure_alert_log_header()
    load_components()

    print("Live AI IDS Running...")
    print(f"Interface: {INTERFACE}")
    print(f"BPF Filter: {BPF_FILTER}")
    print(f"Flow Timeout: {FLOW_TIMEOUT}s")

    try:
        sniff(
            iface=INTERFACE,
            filter=BPF_FILTER,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        for key in list(flows.keys()):
            finalize_flow(key)


if __name__ == "__main__":
    main()
