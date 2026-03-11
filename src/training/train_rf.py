import json
import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

DATA_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "cleaned_data.csv")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")

MODEL_PATH = os.path.join(MODEL_DIR, "live_random_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "live_scaler.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "live_feature_names.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "live_model_metrics.json")

RANDOM_STATE = 42
SAMPLE_SIZE = int(os.getenv("IDS_TRAIN_SAMPLE_SIZE", "300000"))

SELECTED_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
]


def load_data():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()
    return df


def validate_columns(df):
    missing = [col for col in SELECTED_FEATURES if col not in df.columns]
    if "Label" not in df.columns:
        missing.append("Label")
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def sample_data(df):
    if len(df) <= SAMPLE_SIZE:
        return df

    # Preserve class distribution under hardware limits.
    return df.groupby("Label", group_keys=False).apply(
        lambda x: x.sample(
            n=max(1, int(round(SAMPLE_SIZE * (len(x) / len(df))))),
            random_state=RANDOM_STATE,
        )
    ).reset_index(drop=True)


def main():
    print("Loading cleaned dataset...")
    data = load_data()
    validate_columns(data)

    print(f"Original rows: {len(data):,}")
    data = sample_data(data)
    print(f"Training rows: {len(data):,}")

    x = data[SELECTED_FEATURES].copy()
    y = data["Label"].apply(lambda value: 0 if str(value).upper() == "BENIGN" else 1)

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    print("Training Random Forest...")
    model.fit(x_train_scaled, y_train)

    y_pred = model.predict(x_test_scaled)
    report = classification_report(y_test, y_pred, output_dict=True)
    matrix = confusion_matrix(y_test, y_pred)

    roc_auc = None
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(x_test_scaled)[:, 1]
        roc_auc = float(roc_auc_score(y_test, y_prob))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(SELECTED_FEATURES, FEATURE_PATH)

    metrics = {
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "rows_used": int(len(data)),
        "features": SELECTED_FEATURES,
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "roc_auc": roc_auc,
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(matrix)
    if roc_auc is not None:
        print(f"ROC-AUC: {roc_auc:.4f}")

    print("\nArtifacts saved:")
    print(f"- {MODEL_PATH}")
    print(f"- {SCALER_PATH}")
    print(f"- {FEATURE_PATH}")
    print(f"- {METRICS_PATH}")


if __name__ == "__main__":
    main()
