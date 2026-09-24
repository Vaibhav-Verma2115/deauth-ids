"""
train_model.py
==============
Trains the detector and compares candidate classifiers.

Pipeline:
  1. Get preprocessed train/test arrays from dataset_preprocessing.py
  2. Train a Random Forest (the plan's primary algorithm)
  3. Train Decision Tree and SVM for comparison, print an accuracy table
  4. Evaluate the Random Forest: accuracy, precision, recall, F1,
     classification report, confusion matrix (saved as a PNG)
  5. Save model.pkl + scaler.pkl + model_meta.json so realtime_detector.py
     can load them later.

WHY RANDOM FOREST?
------------------
A Random Forest is an *ensemble* of many decision trees, each trained on a
random subset of rows and features. Every tree votes; the majority wins. This
matters for an IDS because:

  * It handles the non-linear, threshold-like rules that separate attacks
    ("deauth_count > ~20 AND packet_rate high") without any manual tuning.
  * Averaging many trees makes it robust to noise and outliers -- a single
    weird packet can't flip the decision.
  * It gives `feature_importances_`, so we can *explain* which signals drive
    the detection (great for a report).
  * It needs almost no feature scaling and trains in seconds on this data.
"""

import json
import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix,
)

from config import (
    FEATURE_COLUMNS, CLASS_NAMES, MODEL_PATH, SCALER_PATH, METADATA_PATH,
    OUTPUT_DIR, ensure_dirs,
)
from dataset_preprocessing import get_preprocessed


def train_random_forest(X_train, y_train) -> RandomForestClassifier:
    """Train the primary Random Forest detector.

    n_estimators=200 : number of trees. More trees = steadier votes, slower.
    max_depth=None    : let trees grow until pure; the ensemble controls overfit.
    class_weight="balanced": up-weight the rarer class so a dataset that is,
                             say, 60/40 doesn't bias the model toward "Normal".
    n_jobs=-1         : use all CPU cores.
    """
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    return rf


def compare_models(X_train, X_test, y_train, y_test):
    """Train RF / Decision Tree / SVM and print a side-by-side accuracy table.

    This is the plan's "Try Other Models / Compare accuracy" step. It shows
    *why* Random Forest is the right default rather than just asserting it.
    """
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", random_state=42),
        "SVM (RBF)": SVC(kernel="rbf", class_weight="balanced", random_state=42),
    }

    print("\n" + "=" * 55)
    print(f"{'Model':<18}{'Accuracy':>10}{'Precision':>11}{'Recall':>9}{'F1':>7}")
    print("=" * 55)
    results = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        acc = accuracy_score(y_test, pred)
        prec = precision_score(y_test, pred, zero_division=0)
        rec = recall_score(y_test, pred, zero_division=0)
        f1 = f1_score(y_test, pred, zero_division=0)
        results[name] = acc
        print(f"{name:<18}{acc:>10.4f}{prec:>11.4f}{rec:>9.4f}{f1:>7.4f}")
    print("=" * 55)
    return results


def evaluate(model, X_test, y_test):
    """Full evaluation of the chosen model + a saved confusion-matrix plot.

    METRICS EXPLAINED:
      accuracy  = fraction of ALL predictions that were correct.
      precision = of the frames we FLAGGED as attack, how many really were?
                  (low precision -> annoying false alarms)
      recall    = of the REAL attacks, how many did we catch?
                  (low recall -> attacks slip through: the dangerous kind of error)
      f1        = harmonic mean of precision & recall (one balanced number).
    For an IDS, recall is usually the metric you protect most: a missed attack
    is worse than a false alarm.
    """
    y_pred = model.predict(X_test)

    print("\n" + "=" * 70)
    print("RANDOM FOREST -- FINAL EVALUATION")
    print("=" * 70)
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"F1 score : {f1_score(y_test, y_pred, zero_division=0):.4f}\n")

    print("classification_report:")
    print(classification_report(
        y_test, y_pred, target_names=[CLASS_NAMES[0], CLASS_NAMES[1]], zero_division=0))

    # --- Confusion matrix figure --------------------------------------------
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=[CLASS_NAMES[0], CLASS_NAMES[1]],
                yticklabels=[CLASS_NAMES[0], CLASS_NAMES[1]], ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix -- Random Forest")
    fig.tight_layout()
    cm_path = OUTPUT_DIR / "confusion_matrix.png"
    fig.savefig(cm_path, dpi=120)
    plt.close(fig)
    print(f"[eval] saved {cm_path}")

    return {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }


def plot_feature_importance(model):
    """Bar chart of which features the forest relies on most."""
    importances = model.feature_importances_
    order = np.argsort(importances)[::-1]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar([FEATURE_COLUMNS[i] for i in order], importances[order], color="#264653")
    ax.set_title("Random Forest feature importance")
    ax.set_ylabel("importance")
    plt.setp(ax.get_xticklabels(), rotation=35, ha="right")
    fig.tight_layout()
    fi_path = OUTPUT_DIR / "feature_importance.png"
    fig.savefig(fi_path, dpi=120)
    plt.close(fig)
    print(f"[eval] saved {fi_path}")


def main():
    ensure_dirs()

    # 1. Preprocess (also writes histogram + correlation plots)
    X_train, X_test, y_train, y_test, scaler = get_preprocessed(make_plots=True)

    # 2. Compare candidate models (the "Try Other Models" step)
    compare_models(X_train, X_test, y_train, y_test)

    # 3. Train the primary Random Forest
    print("\n[train] fitting the primary Random Forest ...")
    rf = train_random_forest(X_train, y_train)

    # 4. Evaluate it thoroughly
    metrics = evaluate(rf, X_test, y_test)
    plot_feature_importance(rf)

    # 5. Persist everything the detector needs.
    #    We save the SCALER too, because at inference time the live features
    #    must be scaled with the *same* statistics the model was trained on.
    joblib.dump(rf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(METADATA_PATH, "w") as f:
        json.dump({
            "features": FEATURE_COLUMNS,
            "classes": CLASS_NAMES,
            "metrics": metrics,
            "model": "RandomForestClassifier(n_estimators=200)",
        }, f, indent=2)

    print(f"\n[save] model  -> {MODEL_PATH}")
    print(f"[save] scaler -> {SCALER_PATH}")
    print(f"[save] meta   -> {METADATA_PATH}")
    print("\n[done] training complete. Run realtime_detector.py next.")


if __name__ == "__main__":
    main()
