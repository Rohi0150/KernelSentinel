#!/usr/bin/env python3
"""Load the trained model and score an ordered JSONL file of syscall events.

Example:
  ../.venv/bin/python predict_model.py examples/benign_input.jsonl
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

import joblib


def make_features(history: deque[dict[str, Any]]) -> dict[str, Any]:
    syscalls = [str(item["syscall"]) for item in history]
    row: dict[str, Any] = {f"process={history[-1].get('process_name', 'unknown')}": 1, "window_length": len(syscalls)}
    for syscall, count in Counter(syscalls).items():
        row[f"syscall={syscall}"] = count
    for size in (2, 3):
        for index in range(len(syscalls) - size + 1):
            row[f"ngram{size}=" + "->".join(syscalls[index:index + size])] = 1
    timestamps = [int(item.get("timestamp_ns", 0)) for item in history]
    row["window_span_ms"] = max(0.0, (timestamps[-1] - timestamps[0]) / 1_000_000)
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSONL with trace_id, pid, process_name, timestamp_ns, syscall")
    parser.add_argument("--model", type=Path, default=Path("model/lid_ds_random_forest.joblib"))
    args = parser.parse_args()
    artifact = joblib.load(args.model)
    window_size = int(artifact["window_size"])
    histories: dict[tuple[str, int], deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=window_size))
    with args.input.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            event = json.loads(line)
            required = {"trace_id", "pid", "process_name", "timestamp_ns", "syscall"}
            missing = required - event.keys()
            if missing:
                raise SystemExit(f"{args.input}:{line_number}: missing {', '.join(sorted(missing))}")
            key = (str(event["trace_id"]), int(event["pid"]))
            histories[key].append(event)
            if len(histories[key]) < 3:
                continue
            matrix = artifact["vectorizer"].transform([make_features(histories[key])])
            probability = float(artifact["classifier"].predict_proba(matrix)[0][1])
            print(json.dumps({"trace_id": key[0], "pid": key[1], "prediction": "attack" if probability >= 0.5 else "benign",
                              "attack_probability": round(probability, 4), "latest_syscall": event["syscall"]}))


if __name__ == "__main__":
    main()
