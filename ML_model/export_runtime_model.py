#!/usr/bin/env python3
"""Export the trained scikit-learn forest to a dependency-free JSON runtime model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("model/lid_ds_random_forest.joblib"))
    parser.add_argument("--output", type=Path, default=Path("model/lid_ds_random_forest_runtime.json"))
    args = parser.parse_args()
    artifact = joblib.load(args.input)
    classifier = artifact["classifier"]
    trees = []
    for estimator in classifier.estimators_:
        tree = estimator.tree_
        trees.append({
            "children_left": tree.children_left.tolist(),
            "children_right": tree.children_right.tolist(),
            "feature": tree.feature.tolist(),
            "threshold": tree.threshold.tolist(),
            "value": tree.value[:, 0, :].tolist(),
        })
    runtime = {
        "format_version": 1,
        "model_type": "RandomForestClassifier",
        "window_size": artifact["window_size"],
        "threshold": 0.50,
        "feature_index": artifact["vectorizer"].vocabulary_,
        "trees": trees,
        "metrics": artifact.get("metrics", {}),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(runtime, separators=(",", ":")), encoding="utf-8")
    print(f"Exported {len(trees)} trees and {len(runtime['feature_index'])} features to {args.output}")


if __name__ == "__main__":
    main()
