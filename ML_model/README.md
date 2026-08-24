# ML model

This folder contains the supervised Random Forest model and its deployment
runtime.

## Train

```bash
cd ML_model
../.venv/bin/python train_model.py
```

It reads `datasets/lid_ds_2019_supervised_pilot/` and writes
`model/lid_ds_random_forest.joblib`.

After retraining, export the deployment model used by `src/pipeline.py` and
`src/dashboard.py`:

```bash
../.venv/bin/python export_runtime_model.py
```

This writes `model/lid_ds_random_forest_runtime.json`. It stores the trained
forest in a dependency-free format, so live eBPF inference works with the
system Python/BCC installation and does not import scikit-learn.

## Predict

```bash
../.venv/bin/python predict_model.py path/to/input.jsonl
```

Each JSONL event requires `trace_id`, `pid`, `process_name`,
`timestamp_ns`, and `syscall`. Predictions start after three events for each
`trace_id` and `pid` combination.

Two ready-to-run examples are in `examples/`:

```bash
../.venv/bin/python predict_model.py examples/benign_input.jsonl
../.venv/bin/python predict_model.py examples/attack_input.jsonl
```

The held-out pilot metrics for the trained artifact are: accuracy 91.19%,
attack precision 94.36%, recall 91.80%, and F1 93.06%. These are dataset
metrics, not a guarantee of real-host accuracy.
