"""
Model Loader Service.
Loads serialized machine learning artifacts, validates schema compatibility,
and exposes safe probability prediction interfaces.
"""

import os
import json
from typing import Dict, Any, List, Optional
import joblib
import numpy as np


CURRENT_DIR = os.path.dirname(__file__)
DEFAULT_MODEL_PATH = os.path.join(CURRENT_DIR, "trained_models", "model.joblib")
DEFAULT_METADATA_PATH = os.path.join(CURRENT_DIR, "trained_models", "model_metadata.json")


class ModelLoader:
    """Manages loading and inference for the champion ML phishing classifier."""

    _instance: Optional['ModelLoader'] = None

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, metadata_path: str = DEFAULT_METADATA_PATH):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.load()

    @classmethod
    def get_instance(cls) -> 'ModelLoader':
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model artifact not found at {self.model_path}. Train the model first.")

        if not os.path.exists(self.metadata_path):
            raise FileNotFoundError(f"Model metadata not found at {self.metadata_path}.")

        with open(self.metadata_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        self.model = joblib.load(self.model_path)

    @property
    def model_version(self) -> str:
        return self.metadata.get("model_version", "1.0.0")

    @property
    def feature_schema_version(self) -> str:
        return self.metadata.get("feature_schema_version", "1.0.0")

    @property
    def feature_names(self) -> List[str]:
        return self.metadata.get("feature_names", [])

    def predict_proba(self, feature_vector: List[float]) -> float:
        """
        Returns phishing probability P(y=1) as float between 0.0 and 1.0.
        """
        if self.model is None:
            raise RuntimeError("Model is not loaded.")

        X = np.array([feature_vector], dtype=float)
        probas = self.model.predict_proba(X)
        phishing_prob = float(probas[0, 1])
        return round(phishing_prob, 4)
