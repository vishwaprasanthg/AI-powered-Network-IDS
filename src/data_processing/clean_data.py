import os
import pandas as pd
import numpy as np

def clean_dataset():

    # Locate processed combined dataset
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))
    combined_path = os.path.join(project_root, "data", "processed", "combined_data.csv")

    print("Loading combined dataset...")
    df = pd.read_csv(combined_path)

    print("Original Shape:", df.shape)

    # Remove leading/trailing spaces in column names
    df.columns = df.columns.str.strip()

    # Remove useless columns if present
    drop_cols = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
    for col in drop_cols:
        if col in df.columns:
            df.drop(columns=col, inplace=True)

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows with NaN
    df.dropna(inplace=True)

    print("After cleaning Shape:", df.shape)

    # Sample dataset (important for 8GB RAM)
    df = df.sample(n=300000, random_state=42)

    print("After sampling Shape:", df.shape)

    # Save cleaned dataset
    cleaned_path = os.path.join(project_root, "data", "processed", "cleaned_data.csv")
    df.to_csv(cleaned_path, index=False)

    print("Cleaned dataset saved successfully!")


if __name__ == "__main__":
    clean_dataset()
