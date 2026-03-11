from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_FILE = os.path.join(BASE_DIR, "realtime", "alerts_log.csv")
EXPECTED_COLUMNS = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Prediction",
]


def _has_valid_header(first_line):
    normalized = first_line.lower().replace(" ", "")
    return (
        "timestamp" in normalized
        and "sourceip" in normalized
        and "destinationip" in normalized
        and "prediction" in normalized
    )


def _load_alert_df():
    if not os.path.exists(ALERT_FILE) or os.path.getsize(ALERT_FILE) == 0:
        return pd.DataFrame(columns=EXPECTED_COLUMNS)

    with open(ALERT_FILE, "r", encoding="utf-8", errors="ignore") as file:
        first_line = file.readline().strip()

    # Support both:
    # 1) CSV with a proper header row
    # 2) Headerless CSV where every line is raw alert data
    if _has_valid_header(first_line):
        df = pd.read_csv(ALERT_FILE)
    else:
        df = pd.read_csv(ALERT_FILE, header=None, names=EXPECTED_COLUMNS)

    df.columns = df.columns.astype(str).str.strip()

    # Recover from malformed header like "Prediction2026-..." caused by a missing newline.
    if "Prediction" not in df.columns:
        malformed_prediction = next(
            (col for col in df.columns if col.startswith("Prediction")),
            None,
        )
        if malformed_prediction:
            df = df.rename(columns={malformed_prediction: "Prediction"})

    # Keep only known columns and ensure all expected columns exist.
    df = df[[col for col in EXPECTED_COLUMNS if col in df.columns]]
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[EXPECTED_COLUMNS]

    # Convert NaN to None so Flask JSON serialization never fails.
    df = df.astype(object).where(pd.notnull(df), None)
    return df


def _apply_filters(df, apply_limit=True):
    filtered = df.copy()
    filtered["Prediction"] = filtered["Prediction"].astype(str).str.upper().str.strip()
    timestamps = pd.to_datetime(filtered["Timestamp"], errors="coerce")

    minutes = request.args.get("minutes", type=int)
    if minutes is not None and minutes > 0:
        cutoff = datetime.now() - timedelta(minutes=minutes)
        filtered = filtered[timestamps >= cutoff]
        timestamps = pd.to_datetime(filtered["Timestamp"], errors="coerce")

    prediction = request.args.get("prediction", type=str)
    if prediction:
        prediction = prediction.strip().upper()
        filtered = filtered[filtered["Prediction"] == prediction]
        timestamps = pd.to_datetime(filtered["Timestamp"], errors="coerce")

    filtered = filtered.assign(_timestamp=timestamps)
    filtered = filtered.sort_values(by="_timestamp", ascending=False, na_position="last")
    filtered = filtered.drop(columns=["_timestamp"])

    limit = request.args.get("limit", default=1000 if apply_limit else None, type=int)
    if apply_limit and limit is not None and limit > 0:
        filtered = filtered.head(min(limit, 5000))

    return filtered


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    try:
        df = _load_alert_df()
        df = _apply_filters(df, apply_limit=True)
        return jsonify(df.to_dict(orient="records"))
    except Exception as e:
        print("Error reading CSV:", e)
        return jsonify([])


@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        df = _load_alert_df()
        df = _apply_filters(df, apply_limit=False)

        if len(df) == 0:
            return jsonify({
                "total_alerts": 0,
                "attack_count": 0,
                "normal_count": 0,
            })

        total = len(df)
        attacks = len(df[df["Prediction"] == "ATTACK"])
        normal = len(df[df["Prediction"] == "NORMAL"])

        return jsonify({
            "total_alerts": total,
            "attack_count": attacks,
            "normal_count": normal,
        })

    except Exception as e:
        print("Error reading CSV:", e)
        return jsonify({
            "total_alerts": 0,
            "attack_count": 0,
            "normal_count": 0,
        })


@app.route("/api/analytics", methods=["GET"])
def get_analytics():
    try:
        df = _load_alert_df()
        df = _apply_filters(df, apply_limit=False)

        if len(df) == 0:
            return jsonify({
                "total_alerts": 0,
                "attack_rate_pct": 0.0,
                "top_source_ip": None,
                "top_protocol": None,
            })

        total = len(df)
        attacks = len(df[df["Prediction"] == "ATTACK"])
        attack_rate = round((attacks / total) * 100, 2) if total else 0.0

        src_counts = df["Source IP"].astype(str).value_counts()
        proto_counts = df["Protocol"].astype(str).value_counts()

        return jsonify({
            "total_alerts": total,
            "attack_rate_pct": attack_rate,
            "top_source_ip": None if src_counts.empty else src_counts.index[0],
            "top_protocol": None if proto_counts.empty else proto_counts.index[0],
        })
    except Exception as e:
        print("Error building analytics:", e)
        return jsonify({
            "total_alerts": 0,
            "attack_rate_pct": 0.0,
            "top_source_ip": None,
            "top_protocol": None,
        })


if __name__ == "__main__":
    app.run(debug=True)
