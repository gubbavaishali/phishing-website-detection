"""
Explainable Machine Learning Algorithms (Random Forest, Logistic Regression, Gradient Boosting)
Engineered on NumPy and SciPy for transparent, defensible, and reliable inference.
Features full probability estimation, feature importance derivation, and serialization support.
"""

import math
import numpy as np
import scipy.optimize
from typing import List, Dict, Any, Optional, Tuple


class DecisionTreeNode:
    """Node in a classification decision tree."""
    def __init__(
        self,
        feature_idx: Optional[int] = None,
        threshold: Optional[float] = None,
        left: Optional['DecisionTreeNode'] = None,
        right: Optional['DecisionTreeNode'] = None,
        *,
        value: Optional[float] = None,
        impurity: float = 0.0,
        sample_count: int = 0
    ):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value  # Probability of class 1
        self.impurity = impurity
        self.sample_count = sample_count

    @property
    def is_leaf(self) -> bool:
        return self.value is not None


class DecisionTreeClassifier:
    """Binary CART Decision Tree using Gini Impurity with feature subspace sampling."""
    def __init__(
        self,
        max_depth: int = 12,
        min_samples_split: int = 4,
        min_samples_leaf: int = 2,
        max_features: Optional[str] = "sqrt",
        random_state: Optional[int] = None
    ):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.rng = np.random.RandomState(random_state)
        self.root: Optional[DecisionTreeNode] = None
        self.n_features_: int = 0
        self.feature_importances_: np.ndarray = np.array([])

    def _gini(self, y: np.ndarray) -> float:
        if len(y) == 0:
            return 0.0
        p1 = np.mean(y)
        return float(1.0 - (p1 ** 2 + (1.0 - p1) ** 2))

    def _best_split(self, X: np.ndarray, y: np.ndarray) -> Tuple[Optional[int], Optional[float], float]:
        n_samples, n_features = X.shape
        current_impurity = self._gini(y)

        if n_samples < self.min_samples_split:
            return None, None, 0.0

        # Subsample features (Random Forest subspace sampling)
        if self.max_features == "sqrt":
            k = max(1, int(np.sqrt(n_features)))
        elif self.max_features == "log2":
            k = max(1, int(np.log2(n_features)))
        else:
            k = n_features

        features_to_check = self.rng.choice(n_features, size=k, replace=False)

        best_gain = 0.0
        best_feat = None
        best_thresh = None

        for feat in features_to_check:
            vals = X[:, feat]
            unique_vals = np.unique(vals)
            if len(unique_vals) <= 1:
                continue

            # Check candidate thresholds (percentiles for efficiency)
            if len(unique_vals) > 20:
                thresholds = np.percentile(unique_vals, np.linspace(5, 95, 15))
            else:
                thresholds = (unique_vals[:-1] + unique_vals[1:]) / 2.0

            for thresh in thresholds:
                left_mask = vals <= thresh
                right_mask = ~left_mask

                n_left = np.sum(left_mask)
                n_right = len(y) - n_left

                if n_left < self.min_samples_leaf or n_right < self.min_samples_leaf:
                    continue

                impurity_left = self._gini(y[left_mask])
                impurity_right = self._gini(y[right_mask])
                weighted_impurity = (n_left / n_samples) * impurity_left + (n_right / n_samples) * impurity_right
                gain = current_impurity - weighted_impurity

                if gain > best_gain:
                    best_gain = gain
                    best_feat = int(feat)
                    best_thresh = float(thresh)

        return best_feat, best_thresh, best_gain

    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int = 0) -> DecisionTreeNode:
        n_samples, _ = X.shape
        n_pos = np.sum(y == 1)
        prob_pos = float(n_pos / n_samples) if n_samples > 0 else 0.0
        current_impurity = self._gini(y)

        # Leaf conditions
        if (
            depth >= self.max_depth
            or n_samples < self.min_samples_split
            or current_impurity == 0.0
            or n_pos == 0
            or n_pos == n_samples
        ):
            return DecisionTreeNode(value=prob_pos, impurity=current_impurity, sample_count=n_samples)

        feat, thresh, gain = self._best_split(X, y)
        if feat is None or gain <= 1e-7:
            return DecisionTreeNode(value=prob_pos, impurity=current_impurity, sample_count=n_samples)

        # Record feature importance (weighted impurity decrease)
        self.feature_importances_[feat] += gain * (n_samples / self._total_samples)

        left_mask = X[:, feat] <= thresh
        right_mask = ~left_mask

        left_child = self._build_tree(X[left_mask], y[left_mask], depth + 1)
        right_child = self._build_tree(X[right_mask], y[right_mask], depth + 1)

        return DecisionTreeNode(
            feature_idx=feat,
            threshold=thresh,
            left=left_child,
            right=right_child,
            impurity=current_impurity,
            sample_count=n_samples
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.n_features_ = X.shape[1]
        self._total_samples = X.shape[0]
        self.feature_importances_ = np.zeros(self.n_features_, dtype=float)
        self.root = self._build_tree(X, y, depth=0)
        return self

    def _predict_sample(self, x: np.ndarray, node: DecisionTreeNode) -> float:
        if node.is_leaf:
            return node.value
        if x[node.feature_idx] <= node.threshold:
            return self._predict_sample(x, node.left)
        return self._predict_sample(x, node.right)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        probs = np.array([self._predict_sample(x, self.root) for x in X])
        return np.vstack([1.0 - probs, probs]).T

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


class ExplainableRandomForest:
    """Explainable Random Forest Classifier with ensemble bagging and Gini feature importances."""
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 14,
        min_samples_split: int = 4,
        min_samples_leaf: int = 2,
        max_features: str = "sqrt",
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.random_state = random_state
        self.trees: List[DecisionTreeClassifier] = []
        self.feature_importances_: np.ndarray = np.array([])

    def fit(self, X: np.ndarray, y: np.ndarray):
        n_samples, n_features = X.shape
        rng = np.random.RandomState(self.random_state)
        self.trees = []
        accumulated_importances = np.zeros(n_features, dtype=float)

        for i in range(self.n_estimators):
            # Bootstrap sample with replacement
            boot_idx = rng.choice(n_samples, size=n_samples, replace=True)
            X_boot = X[boot_idx]
            y_boot = y[boot_idx]

            tree = DecisionTreeClassifier(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                min_samples_leaf=self.min_samples_leaf,
                max_features=self.max_features,
                random_state=rng.randint(0, 1000000)
            )
            tree.fit(X_boot, y_boot)
            self.trees.append(tree)
            accumulated_importances += tree.feature_importances_

        # Normalize feature importances to sum to 1.0
        total_imp = np.sum(accumulated_importances)
        if total_imp > 0:
            self.feature_importances_ = accumulated_importances / total_imp
        else:
            self.feature_importances_ = np.ones(n_features) / n_features
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        all_probs = np.zeros((len(X), 2))
        for tree in self.trees:
            all_probs += tree.predict_proba(X)
        all_probs /= len(self.trees)
        return all_probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


class ExplainableLogisticRegression:
    """L2 Regularized Logistic Regression with internal standardization."""
    def __init__(self, C: float = 1.0, max_iter: int = 400):
        self.C = C
        self.max_iter = max_iter
        self.weights: Optional[np.ndarray] = None
        self.intercept: float = 0.0
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None

    def _sigmoid(self, z: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(z, -25.0, 25.0)))

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.mean_ = np.mean(X, axis=0)
        self.std_ = np.std(X, axis=0)
        self.std_[self.std_ == 0] = 1.0

        X_scaled = (X - self.mean_) / self.std_
        n_samples, n_features = X_scaled.shape

        # Cost and gradient function for L-BFGS
        def loss_and_grad(theta):
            w = theta[:-1]
            b = theta[-1]
            z = X_scaled @ w + b
            p = self._sigmoid(z)
            p = np.clip(p, 1e-15, 1.0 - 1e-15)

            # Cross entropy + L2 penalty
            loss = -np.mean(y * np.log(p) + (1.0 - y) * np.log(1.0 - p)) + (0.5 / self.C) * np.sum(w ** 2)

            error = p - y
            grad_w = (X_scaled.T @ error) / n_samples + (1.0 / self.C) * w
            grad_b = np.mean(error)
            grad = np.append(grad_w, grad_b)
            return loss, grad

        init_theta = np.zeros(n_features + 1)
        res = scipy.optimize.minimize(
            loss_and_grad,
            init_theta,
            jac=True,
            method="L-BFGS-B",
            options={"maxiter": self.max_iter}
        )

        self.weights = res.x[:-1]
        self.intercept = float(res.x[-1])
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X_scaled = (X - self.mean_) / self.std_
        z = X_scaled @ self.weights + self.intercept
        p1 = self._sigmoid(z)
        return np.vstack([1.0 - p1, p1]).T

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


class ExplainableGradientBoosting:
    """Gradient Boosting with decision stumps fitting pseudo-residuals."""
    def __init__(self, n_estimators: int = 60, learning_rate: float = 0.1, max_depth: int = 4, random_state: int = 42):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.random_state = random_state
        self.base_pred_: float = 0.0
        self.trees: List[DecisionTreeClassifier] = []

    def fit(self, X: np.ndarray, y: np.ndarray):
        n_samples = len(y)
        self.base_pred_ = float(np.mean(y))
        F = np.full(n_samples, self.base_pred_)
        self.trees = []
        rng = np.random.RandomState(self.random_state)

        for _ in range(self.n_estimators):
            # Compute negative gradient (residuals)
            residuals = y - F
            # Fit tree to target pseudo-probabilities
            target = (residuals >= 0).astype(int)
            tree = DecisionTreeClassifier(max_depth=self.max_depth, random_state=rng.randint(0, 100000))
            tree.fit(X, target)
            pred = tree.predict_proba(X)[:, 1] - 0.5
            F = np.clip(F + self.learning_rate * pred, 0.001, 0.999)
            self.trees.append(tree)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        F = np.full(len(X), self.base_pred_)
        for tree in self.trees:
            pred = tree.predict_proba(X)[:, 1] - 0.5
            F = np.clip(F + self.learning_rate * pred, 0.001, 0.999)
        return np.vstack([1.0 - F, F]).T

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> Dict[str, Any]:
    """Computes comprehensive classification metrics."""
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    total = len(y_true)
    accuracy = float((tp + tn) / total) if total > 0 else 0.0
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fn_rate = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    fp_rate = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # ROC AUC calculation via trapezoidal rule on ranked scores
    sorted_indices = np.argsort(y_proba)[::-1]
    y_sorted = y_true[sorted_indices]
    n_pos = np.sum(y_true == 1)
    n_neg = np.sum(y_true == 0)

    if n_pos == 0 or n_neg == 0:
        roc_auc = 0.5
    else:
        # Wilcoxon rank-sum / Mann-Whitney U for ROC-AUC
        ranks = np.argsort(sorted_indices) + 1
        pos_rank_sum = np.sum(ranks[y_true == 1])
        u_stat = pos_rank_sum - (n_pos * (n_pos + 1)) / 2.0
        roc_auc = float(1.0 - (u_stat / (n_pos * n_neg)))

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "false_negative_rate": round(fn_rate, 4),
        "false_positive_rate": round(fp_rate, 4),
    }
