import csv
import os
import time
from datetime import datetime

import joblib
import pandas as pd

EXPECTED_HEADER = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Prediction",
]


def load_components():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))

    model = joblib.load(os.path.join(project_root, "models", "live_random_forest.pkl"))
    scaler = joblib.load(os.path.join(project_root, "models", "live_scaler.pkl"))
    feature_names = joblib.load(os.path.join(project_root, "models", "live_feature_names.pkl"))

    cleaned_path = os.path.join(project_root, "data", "processed", "cleaned_data.csv")
    df = pd.read_csv(cleaned_path)

    alerts_path = os.path.join(project_root, "src", "realtime", "alerts_log.csv")

    return model, scaler, feature_names, df, alerts_path


def ensure_alert_log_header(alerts_path):
    os.makedirs(os.path.dirname(alerts_path), exist_ok=True)

    if not os.path.exists(alerts_path) or os.path.getsize(alerts_path) == 0:
        with open(alerts_path, "w", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow(EXPECTED_HEADER)
        return

    with open(alerts_path, "r", encoding="utf-8", errors="ignore") as file:
        first_line = file.readline().strip().lower().replace(" ", "")

    valid = (
        "timestamp" in first_line
        and "sourceip" in first_line
        and "destinationip" in first_line
        and "prediction" in first_line
    )

    if not valid:
        with open(alerts_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
        with open(alerts_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADER)
            file.write(content)


def log_alert(alerts_path, prediction):
    with open(alerts_path, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "192.168.1.100",
            "10.0.0.5",
            "12345",
            "80",
            "TCP",
            "ATTACK" if int(prediction) == 1 else "NORMAL",
        ])


def simulate_realtime():
    model, scaler, feature_names, df, alerts_path = load_components()
    ensure_alert_log_header(alerts_path)

    print("Starting simulated real-time IDS...\n")

    delay = float(os.getenv("IDS_SIM_DELAY_SEC", "0.5"))

    for index, row in df.iterrows():
        if not set(feature_names).issubset(df.columns):
            missing = [name for name in feature_names if name not in df.columns]
            raise ValueError(f"Missing feature columns in cleaned_data.csv: {missing}")

        features = row[feature_names].values.reshape(1, -1)
        features_scaled = scaler.transform(features)
        prediction = int(model.predict(features_scaled)[0])

        log_alert(alerts_path, prediction)

        if prediction == 1:
            print(f"[ALERT] Attack detected at row {index}")
        else:
            print(f"[INFO] Normal traffic at row {index}")

        time.sleep(delay)


if __name__ == "__main__":
    simulate_realtime()
