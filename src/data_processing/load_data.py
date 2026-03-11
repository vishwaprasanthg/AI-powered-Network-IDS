import os
import pandas as pd

def load_and_combine_csv():
    # Get absolute path of current file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Go to project root
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))
    
    # Raw data folder path
    raw_data_path = os.path.join(project_root, "data", "raw")
    
    print("Looking for files in:", raw_data_path)
    
    all_files = [f for f in os.listdir(raw_data_path) if f.endswith('.csv')]
    
    dataframes = []
    
    for file in all_files:
        file_path = os.path.join(raw_data_path, file)
        print(f"Loading {file}...")
        df = pd.read_csv(file_path)
        dataframes.append(df)
    
    combined_df = pd.concat(dataframes, ignore_index=True)
    return combined_df


if __name__ == "__main__":
    data = load_and_combine_csv()
    print("Dataset Shape:", data.shape)

    # Save processed file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))
    processed_path = os.path.join(project_root, "data", "processed", "combined_data.csv")

    data.to_csv(processed_path, index=False)
    print("Combined dataset saved successfully!")
