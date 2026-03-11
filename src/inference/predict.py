import os

import joblib
import numpy as np
import pandas as pd


def load_components():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))

    model_path = os.path.join(project_root, "models", "live_random_forest.pkl")
    scaler_path = os.path.join(project_root, "models", "live_scaler.pkl")
    feature_path = os.path.join(project_root, "models", "live_feature_names.pkl")

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    feature_names = joblib.load(feature_path)

    return model, scaler, feature_names


def predict_sample(sample_features):
    model, scaler, feature_names = load_components()

    if len(sample_features) != len(feature_names):
        raise ValueError(
            f"Expected {len(feature_names)} features, got {len(sample_features)}"
        )

    sample_df = pd.DataFrame([sample_features], columns=feature_names)
    sample_scaled = scaler.transform(sample_df)

    prediction = int(model.predict(sample_scaled)[0])
    label = "ATTACK" if prediction == 1 else "NORMAL"

    confidence = None
    if hasattr(model, "predict_proba"):
        confidence = float(model.predict_proba(sample_scaled)[0][prediction])

    return {
        "prediction": prediction,
        "label": label,
        "confidence": confidence,
    }


if __name__ == "__main__":
    _, _, live_features = load_components()
    dummy_input = [0.0] * len(live_features)
    result = predict_sample(dummy_input)
    print("Prediction Result:", result)
