"""
Machine Learning Training & Comparative Evaluation Pipeline.
Trains Explainable Random Forest, Gradient Boosting, and Logistic Regression.
Evaluates classification metrics, confusion matrices, false negative rates,
and unseen obfuscation test sets. Serializes the optimal model and metadata.
"""

import os
import json
from typing import Dict, Any, List
import joblib
import numpy as np

from app.services.feature_extractor import FeatureExtractor, FEATURE_NAMES
from app.ml.training.dataset_builder import generate_curated_dataset
from app.ml.models import (
    ExplainableRandomForest,
    ExplainableGradientBoosting,
    ExplainableLogisticRegression,
    calculate_metrics,
)


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "trained_models")


# Requirement #14: Unseen Obfuscation Test Set (Generalization Benchmark)
UNSEEN_OBFUSCATION_TEST_SET = [
    # Novel typosquats & combosquats not in training
    {"url": "https://p-a-y-p-a-l-security.center/auth", "label": 1, "desc": "Hyphenated brand fragmentation"},
    {"url": "http://185.220.101.99/chase/verify.html", "label": 1, "desc": "Direct IP hosting bank login"},
    {"url": "https://appleid-apple-support-recovery.cfd/login", "label": 1, "desc": "Repetitive brand combosquat on .cfd"},
    {"url": "http://netflix.com.profile-update.buzz/signin", "label": 1, "desc": "Subdomain deception on .buzz"},
    {"url": "https://amaz0n-prime-member-renew.top/account", "label": 1, "desc": "Homoglyph '0' on .top"},
    {"url": "https://wellsfarg0-online-access.icu/signon", "label": 1, "desc": "Homoglyph '0' on .icu"},
    {"url": "http://bit.ly/bank-security-alert-2026", "label": 1, "desc": "Shortened URL with security keyword"},
    {"url": "https://xn--appl-coa.com/icloud", "label": 1, "desc": "IDN Punycode homograph attack"},
    # Legitimate modern URLs
    {"url": "https://github.com/features/actions", "label": 0, "desc": "Legitimate deep path"},
    {"url": "https://docs.docker.com/engine/install/", "label": 0, "desc": "Legitimate technical documentation"},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP", "label": 0, "desc": "Legitimate educational resource"},
    {"url": "https://openai.com/research", "label": 0, "desc": "Legitimate tech portal"},
    {"url": "https://cloud.google.com/security", "label": 0, "desc": "Legitimate cloud security page"},
    {"url": "https://www.bankofamerica.com/help", "label": 0, "desc": "Legitimate financial institution"},
]


def extract_features_for_sample(extractor: FeatureExtractor, item: Dict[str, Any]) -> List[float]:
    url = item["url"]
    override = item.get("html_override", {})
    threat = item.get("threat_score", 0.0)

    # Extract base features
    data = extractor.extract_all(url=url, threat_score=threat)
    features = data["features"]

    # Apply HTML overrides if provided by curated dataset
    for k, v in override.items():
        if k in features:
            features[k] = v

    # Produce ordered vector
    vector = [float(features[name]) for name in FEATURE_NAMES]
    return vector


def train_test_split_stratified(X: np.ndarray, y: np.ndarray, test_size: float = 0.20, random_state: int = 42):
    rng = np.random.RandomState(random_state)
    idx_0 = np.where(y == 0)[0]
    idx_1 = np.where(y == 1)[0]

    rng.shuffle(idx_0)
    rng.shuffle(idx_1)

    n_test_0 = int(len(idx_0) * test_size)
    n_test_1 = int(len(idx_1) * test_size)

    test_idx = np.concatenate([idx_0[:n_test_0], idx_1[:n_test_1]])
    train_idx = np.concatenate([idx_0[n_test_0:], idx_1[n_test_1:]])

    rng.shuffle(test_idx)
    rng.shuffle(train_idx)

    return X[train_idx], X[test_idx], y[train_idx], y[test_idx]


def run_training_pipeline() -> Dict[str, Any]:
    print("[*] Generating curated phishing & legitimate benchmark dataset...")
    raw_data = generate_curated_dataset()
    print(f"[+] Total samples generated: {len(raw_data)}")

    extractor = FeatureExtractor()

    print("[*] Extracting multi-signal feature vectors...")
    X_list = []
    y_list = []
    for item in raw_data:
        vec = extract_features_for_sample(extractor, item)
        X_list.append(vec)
        y_list.append(item["label"])

    X = np.array(X_list, dtype=float)
    y = np.array(y_list, dtype=int)

    print(f"[+] Feature matrix shape: {X.shape}, Class distribution: Legitimate={np.sum(y==0)}, Phishing={np.sum(y==1)}")

    # Stratified Train/Test Split (80/20)
    X_train, X_test, y_train, y_test = train_test_split_stratified(X, y, test_size=0.20, random_state=42)

    print(f"[+] Train set: {X_train.shape[0]} samples, Test set: {X_test.shape[0]} samples")

    # Define Candidate Models
    models = {
        "Random Forest": ExplainableRandomForest(
            n_estimators=60,
            max_depth=12,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features="sqrt",
            random_state=42
        ),
        "Gradient Boosting": ExplainableGradientBoosting(
            n_estimators=40,
            learning_rate=0.1,
            max_depth=4,
            random_state=42
        ),
        "Logistic Regression": ExplainableLogisticRegression(
            C=1.0,
            max_iter=400
        )
    }

    results = {}
    best_model_name = "Random Forest"
    best_f1 = -1.0

    print("\n[*] Evaluating Candidate Models on Test Set:")
    print("-" * 88)

    for name, model in models.items():
        print(f"[*] Training {name}...")
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        metrics = calculate_metrics(y_test, y_pred, y_proba)
        results[name] = metrics

        acc = metrics["accuracy"]
        prec = metrics["precision"]
        rec = metrics["recall"]
        f1 = metrics["f1_score"]
        auc = metrics["roc_auc"]
        fn = metrics["confusion_matrix"]["false_negative"]
        fn_rate = metrics["false_negative_rate"]

        print(f"| {name:<20} | Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f} | AUC: {auc:.4f} | FN: {fn} (FNR: {fn_rate:.2%}) |")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name

    print("-" * 88)
    print(f"[+] Champion Model Selected: {best_model_name} (F1 Score: {best_f1:.4f})")

    champion_model = models[best_model_name]

    # Evaluate Champion Model on Unseen Obfuscation Test Set (Requirement #14)
    print("\n[*] Evaluating on Unseen Obfuscation Generalization Benchmark (Requirement #14):")
    unseen_X = []
    unseen_y = []
    for item in UNSEEN_OBFUSCATION_TEST_SET:
        vec = extract_features_for_sample(extractor, item)
        unseen_X.append(vec)
        unseen_y.append(item["label"])

    unseen_X = np.array(unseen_X, dtype=float)
    unseen_y = np.array(unseen_y, dtype=int)
    unseen_pred = champion_model.predict(unseen_X)
    unseen_proba = champion_model.predict_proba(unseen_X)[:, 1]

    unseen_metrics = calculate_metrics(unseen_y, unseen_pred, unseen_proba)
    unseen_acc = unseen_metrics["accuracy"]
    unseen_rec = unseen_metrics["recall"]

    unseen_eval = {
        "total_samples": len(UNSEEN_OBFUSCATION_TEST_SET),
        "accuracy": unseen_acc,
        "recall": unseen_rec,
        "metrics": unseen_metrics,
        "sample_evaluations": [
            {
                "url": item["url"],
                "technique": item["desc"],
                "ground_truth": "phishing" if item["label"] == 1 else "legitimate",
                "predicted": "phishing" if int(pred) == 1 else "legitimate",
                "risk_probability": round(float(prob), 4),
                "correct": bool(pred == item["label"])
            }
            for item, pred, prob in zip(UNSEEN_OBFUSCATION_TEST_SET, unseen_pred, unseen_proba)
        ]
    }
    print(f"[+] Unseen Obfuscation Benchmark: Accuracy={unseen_acc:.4f}, Recall={unseen_rec:.4f}")

    # Compute Feature Importances (from Random Forest)
    rf_model = models["Random Forest"]
    importances = rf_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    feature_importance_list = [
        {
            "rank": int(i + 1),
            "feature": FEATURE_NAMES[idx],
            "importance": round(float(importances[idx]), 4)
        }
        for i, idx in enumerate(sorted_idx)
    ]

    print("\n[*] Top 10 Most Predictive Features:")
    for item in feature_importance_list[:10]:
        print(f"    {item['rank']}. {item['feature']:<26} (Weight: {item['importance']:.4f})")

    # Serialize Champion Model & Metadata
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, "model.joblib")
    metadata_path = os.path.join(MODEL_DIR, "model_metadata.json")
    benchmark_path = os.path.join(MODEL_DIR, "benchmark_results.json")

    joblib.dump(champion_model, model_path)
    print(f"\n[+] Serialized champion model to: {model_path}")

    metadata = {
        "model_version": "1.0.0",
        "feature_schema_version": "1.0.0",
        "algorithm": best_model_name,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "training_sample_count": int(X_train.shape[0]),
        "test_sample_count": int(X_test.shape[0]),
        "metrics": results[best_model_name],
        "top_features": feature_importance_list[:15],
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata to: {metadata_path}")

    benchmark_data = {
        "dataset_summary": {
            "total_samples": int(X.shape[0]),
            "train_samples": int(X_train.shape[0]),
            "test_samples": int(X_test.shape[0]),
            "class_distribution": {"legitimate": int(np.sum(y == 0)), "phishing": int(np.sum(y == 1))},
        },
        "model_comparisons": results,
        "generalization_benchmark": unseen_eval,
        "feature_importances": feature_importance_list,
    }

    with open(benchmark_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2)
    print(f"[+] Saved benchmark comparisons to: {benchmark_path}")

    return benchmark_data


if __name__ == "__main__":
    run_training_pipeline()
