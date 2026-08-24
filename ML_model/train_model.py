#!/usr/bin/env python3
"""Train and save the Random Forest syscall attack classifier.

Run from this directory:
  ../.venv/bin/python train_model.py
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support


def read_windows(paths: Iterable[Path], window_size: int) -> tuple[list[dict[str, Any]], list[int]]:
    """Create per-process syscall-window features from ordered JSONL events."""
    rows: list[dict[str, Any]] = []
    labels: list[int] = []
    for path in paths:
        histories: dict[tuple[str, int], deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=window_size))
        with path.open(encoding="utf-8") as source:
            for line in source:
                event = json.loads(line)
                key = (str(event.get("trace_id", "single_trace")), int(event["pid"]))
                histories[key].append(event)
                history = histories[key]
                if len(history) < 3:
                    continue
                syscalls = [str(item["syscall"]) for item in history]
                row: dict[str, Any] = {f"process={event.get('process_name', 'unknown')}": 1, "window_length": len(syscalls)}
                for syscall, count in Counter(syscalls).items():
                    row[f"syscall={syscall}"] = count
                for size in (2, 3):
                    for index in range(len(syscalls) - size + 1):
                        row[f"ngram{size}=" + "->".join(syscalls[index:index + size])] = 1
                timestamps = [int(item.get("timestamp_ns", 0)) for item in history]
                row["window_span_ms"] = max(0.0, (timestamps[-1] - timestamps[0]) / 1_000_000)
                rows.append(row)
                labels.append(1 if event.get("event_label") == "attack" else 0)
    return rows, labels


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("datasets/lid_ds_2019_supervised_pilot"))
    parser.add_argument("--output", type=Path, default=Path("model/lid_ds_random_forest.joblib"))
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--trees", type=int, default=300)
    args = parser.parse_args()
    train_paths = [args.data_dir / "benign_train.jsonl", args.data_dir / "attack_train.jsonl"]
    test_paths = [args.data_dir / "benign_test.jsonl", args.data_dir / "attack_test.jsonl"]
    missing = [str(path) for path in train_paths + test_paths if not path.exists()]
    if missing:
        raise SystemExit("Missing dataset file(s): " + ", ".join(missing))

    train_rows, y_train = read_windows(train_paths, args.window)
    test_rows, y_test = read_windows(test_paths, args.window)
    vectorizer = DictVectorizer(sparse=True)
    x_train, x_test = vectorizer.fit_transform(train_rows), vectorizer.transform(test_rows)
    classifier = RandomForestClassifier(n_estimators=args.trees, max_depth=20, min_samples_leaf=2,
                                        class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    classifier.fit(x_train, y_train)
    predicted = classifier.predict(x_test)
    accuracy = accuracy_score(y_test, predicted)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predicted, average="binary", zero_division=0)
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Attack precision: {precision:.4f}; recall: {recall:.4f}; F1: {f1:.4f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, predicted, labels=[0, 1]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model_type": "RandomForestClassifier", "window_size": args.window,
                 "vectorizer": vectorizer, "classifier": classifier,
                 "metrics": {"accuracy": float(accuracy), "attack_precision": float(precision),
                             "attack_recall": float(recall), "attack_f1": float(f1)}}, args.output)
    joblib.load(args.output)
    print(f"Saved model: {args.output}")


if __name__ == "__main__":
    main()
