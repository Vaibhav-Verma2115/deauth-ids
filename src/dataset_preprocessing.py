"""
dataset_preprocessing.py
========================
Prepares the attack-detection dataset: load, clean, split, scale, visualise.

This script takes the raw CSV and turns it into clean, model-ready arrays. It
performs, in order:

  1. LOAD        - read the CSV, show head()/info()/isnull().sum()
  2. CLEAN       - drop/duplicate rows, fill any missing values
  3. SPLIT       - separate features (X) from the label (y), then train/test
  4. SCALE       - fit a StandardScaler on TRAIN ONLY, apply to both
  5. VISUALISE   - histograms + a correlation matrix saved to outputs/

The functions here are imported by `train_model.py`, so the exact same
preprocessing is reused at training time -- there is only one definition of
"clean the data", which prevents train/serve skew.

KEY IDEA: WHY SCALE, AND WHY "FIT ON TRAIN ONLY"?
-------------------------------------------------
Features live on wildly different scales: `rssi` is ~ -45, `packet_rate` can be
900, `deauth_count` up to 400. Tree models (Random Forest) don't strictly need
scaling, but distance-based models we also compare against (SVM) absolutely do.
We fit the scaler on the training set ONLY and then apply it to the test set,
because letting the scaler "see" the test data leaks information about data the
model is supposed to be evaluated on -- that inflates the score dishonestly.
"""

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # non-interactive backend: save figures to files, never pop a window
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from config import (
    FEATURE_COLUMNS, LABEL_COLUMN, RAW_DATASET, OUTPUT_DIR, ensure_dirs,
)


def load_data(path=RAW_DATASET) -> pd.DataFrame:
    """Load the CSV and print the three pandas summaries the plan lists."""
    df = pd.read_csv(path)

    print("=" * 70)
    print("df.head()  -- first 5 rows so we can eyeball the data")
    print("=" * 70)
    print(df.head(), "\n")

    print("=" * 70)
    print("df.info()  -- column dtypes and non-null counts")
    print("=" * 70)
    df.info()
    print()

    print("=" * 70)
    print("df.isnull().sum()  -- how many missing values per column")
    print("=" * 70)
    print(df.isnull().sum(), "\n")

    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicates and fill any missing numeric values with the median.

    Real packet captures often have gaps (a frame with no RSSI reading, etc.).
    We fill with the column median because it is robust to the heavy outliers
    an attack introduces -- the mean would get dragged around by the flood.
    """
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    removed = before - len(df)
    if removed:
        print(f"[clean] dropped {removed} duplicate rows")

    if df[FEATURE_COLUMNS].isnull().any().any():
        medians = df[FEATURE_COLUMNS].median()
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(medians)
        print("[clean] filled missing feature values with column medians")

    return df


def split_and_scale(df: pd.DataFrame, test_size=0.2, seed=42):
    """Split into train/test and standard-scale the features.

    Returns
    -------
    X_train, X_test : np.ndarray  (scaled)
    y_train, y_test : np.ndarray
    scaler          : fitted StandardScaler (needed later at inference time)
    """
    X = df[FEATURE_COLUMNS].values
    y = df[LABEL_COLUMN].values

    # `stratify=y` keeps the Normal/Attack ratio identical in train and test,
    # so the test score reflects real-world class balance.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)  # FIT on train
    X_test = scaler.transform(X_test)        # only TRANSFORM test (no leakage)

    print(f"[split] train={len(X_train)}  test={len(X_test)}  features={X_train.shape[1]}")
    return X_train, X_test, y_train, y_test, scaler


def visualise(df: pd.DataFrame):
    """Save a feature histogram grid and a correlation matrix to outputs/."""
    ensure_dirs()

    # --- Histograms: how each feature is distributed, split by class ---------
    fig, axes = plt.subplots(3, 3, figsize=(14, 10))
    axes = axes.ravel()
    for i, col in enumerate(FEATURE_COLUMNS):
        ax = axes[i]
        for label, name, color in [(0, "Normal", "#2a9d8f"), (1, "Attack", "#e76f51")]:
            ax.hist(df[df[LABEL_COLUMN] == label][col], bins=40, alpha=0.6,
                    label=name, color=color)
        ax.set_title(col)
        ax.legend()
    # Hide the two unused subplot cells (7 features in a 3x3 grid).
    for j in range(len(FEATURE_COLUMNS), len(axes)):
        axes[j].axis("off")
    fig.suptitle("Feature distributions: Normal vs Attack", fontsize=14)
    fig.tight_layout()
    hist_path = OUTPUT_DIR / "histograms.png"
    fig.savefig(hist_path, dpi=120)
    plt.close(fig)
    print(f"[viz] saved {hist_path}")

    # --- Correlation matrix: which features move together --------------------
    fig, ax = plt.subplots(figsize=(9, 7))
    corr = df[FEATURE_COLUMNS + [LABEL_COLUMN]].corr()
    sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", center=0, ax=ax)
    ax.set_title("Correlation matrix (note the 'label' row/column)")
    fig.tight_layout()
    corr_path = OUTPUT_DIR / "correlation_matrix.png"
    fig.savefig(corr_path, dpi=120)
    plt.close(fig)
    print(f"[viz] saved {corr_path}")


def get_preprocessed(path=RAW_DATASET, test_size=0.2, seed=42, make_plots=True):
    """Convenience wrapper used by train_model.py: load -> clean -> split/scale."""
    df = load_data(path)
    df = clean_data(df)
    if make_plots:
        visualise(df)
    return split_and_scale(df, test_size=test_size, seed=seed)


def main():
    ensure_dirs()
    if not RAW_DATASET.exists():
        raise SystemExit(
            f"[error] {RAW_DATASET} not found. Run generate_dataset.py first."
        )
    # Running this file directly just demonstrates the full preprocessing pass.
    X_train, X_test, y_train, y_test, scaler = get_preprocessed()
    print("\n[preprocessing] done. Arrays are ready for train_model.py")
    print(f"  X_train mean~0 check: {np.round(X_train.mean(axis=0), 3)}")


if __name__ == "__main__":
    main()
