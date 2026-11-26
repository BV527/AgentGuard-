import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.dataset_generator import generate_synthetic_dataset

if __name__ == "__main__":
    print("Generating synthetic action dataset (12,000 records)...")
    generate_synthetic_dataset()
