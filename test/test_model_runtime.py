#!/usr/bin/env python3
"""Offline integration check for the model artifact and live inference adapter."""

from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ML_model"))
from model_runtime import LiveSyscallModel


def load_events(path: Path) -> deque[dict]:
    return deque((json.loads(line) for line in path.open(encoding="utf-8")), maxlen=10)


def main() -> None:
    model = LiveSyscallModel(ROOT / "ML_model" / "model" / "lid_ds_random_forest_runtime.json")
    benign = load_events(ROOT / "ML_model" / "examples" / "benign_input.jsonl")
    attack = load_events(ROOT / "ML_model" / "examples" / "attack_input.jsonl")
    benign_flagged, benign_score, _ = model.score(benign)
    attack_flagged, attack_score, _ = model.score(attack)
    print(f"benign: flagged={benign_flagged}, score={benign_score:.4f}")
    print(f"attack: flagged={attack_flagged}, score={attack_score:.4f}")
    if benign_flagged or not attack_flagged:
        raise SystemExit("model integration check failed")


if __name__ == "__main__":
    main()
