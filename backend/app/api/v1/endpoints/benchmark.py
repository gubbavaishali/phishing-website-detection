"""
ML Benchmark & Model Comparison Endpoint.
Serves comparative evaluation metrics, confusion matrices, and generalization test results.
"""

import os
import json
from fastapi import APIRouter, HTTPException


router = APIRouter()
CURRENT_DIR = os.path.dirname(__file__)
BENCHMARK_PATH = os.path.abspath(
    os.path.join(CURRENT_DIR, "..", "..", "..", "ml", "trained_models", "benchmark_results.json")
)


@router.get("/benchmark", summary="Get model benchmarking and generalization metrics")
def get_benchmark_results():
    if not os.path.exists(BENCHMARK_PATH):
        raise HTTPException(status_code=404, detail="Benchmark results not found.")

    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Determine champion model: highest F1 score
    comparisons = data.get("model_comparisons", {})
    if comparisons:
        champion = max(comparisons.items(), key=lambda kv: kv[1].get("f1_score", 0))[0]
        data["champion_model"] = champion
    else:
        data["champion_model"] = "Random Forest"

    return data
