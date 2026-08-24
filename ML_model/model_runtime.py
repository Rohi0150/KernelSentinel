"""Live inference adapter for the saved Random Forest syscall classifier."""

from __future__ import annotations

from collections import Counter, deque
from pathlib import Path
from typing import Any, Iterable

import json


class LiveSyscallModel:
    """Transforms a live per-PID syscall window into the training feature set."""

    def __init__(self, model_path: str | Path, threshold: float | None = None) -> None:
        self.model_path = Path(model_path)
        self.artifact = json.loads(self.model_path.read_text(encoding="utf-8"))
        if self.artifact.get("model_type") != "RandomForestClassifier" or self.artifact.get("format_version") != 1:
            raise ValueError("expected a RandomForestClassifier model artifact")
        self.window_size = int(self.artifact["window_size"])
        self.threshold = float(self.artifact["threshold"] if threshold is None else threshold)

    @staticmethod
    def make_features(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
        history = list(events)
        syscalls = [str(event["syscall"]) for event in history]
        row: dict[str, Any] = {
            f"process={history[-1].get('process_name', 'unknown')}": 1,
            "window_length": len(syscalls),
        }
        for syscall, count in Counter(syscalls).items():
            row[f"syscall={syscall}"] = count
        for size in (2, 3):
            for index in range(len(syscalls) - size + 1):
                row[f"ngram{size}=" + "->".join(syscalls[index:index + size])] = 1
        timestamps = [int(event.get("timestamp_ns", 0)) for event in history]
        row["window_span_ms"] = max(0.0, (timestamps[-1] - timestamps[0]) / 1_000_000)
        return row

    def score(self, events: deque[dict[str, Any]]) -> tuple[bool, float, str | None]:
        if len(events) < 3:
            return False, 0.0, None
        feature_values = self.make_features(events)
        probability = self._predict_probability(feature_values)
        flagged = probability >= self.threshold
        reason = None
        if flagged:
            sequence = " -> ".join(event["syscall"] for event in list(events)[-3:])
            reason = f"Random Forest attack probability={probability:.3f}; recent sequence={sequence}"
        return flagged, probability, reason

    def _predict_probability(self, feature_values: dict[str, Any]) -> float:
        """Evaluate exported sklearn decision trees without sklearn/joblib."""
        feature_index = self.artifact["feature_index"]
        by_index = {feature_index[name]: value for name, value in feature_values.items() if name in feature_index}
        probabilities = []
        for tree in self.artifact["trees"]:
            node = 0
            while tree["children_left"][node] != tree["children_right"][node]:
                value = by_index.get(tree["feature"][node], 0.0)
                node = tree["children_left"][node] if value <= tree["threshold"][node] else tree["children_right"][node]
            classes = tree["value"][node]
            total = sum(classes)
            probabilities.append(classes[1] / total if total else 0.0)
        return sum(probabilities) / len(probabilities) if probabilities else 0.0
