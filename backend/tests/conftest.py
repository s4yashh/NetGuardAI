"""Test fixtures.

The tests train a tiny model on SYNTHETIC data inside a temporary folder, so they
run in seconds and never touch the real model or the real evaluation report.
"""

import io
import json

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from backend.app.main import create_app

FEATURES = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Flow Bytes/s"]


def synthetic_flows(n: int = 200, seed: int = 0) -> pd.DataFrame:
    """Random flows where 'malicious' rows have many forward packets."""
    rng = np.random.default_rng(seed)
    malicious = rng.random(n) < 0.3
    return pd.DataFrame({
        "Destination Port": rng.integers(1, 65535, n),
        "Flow Duration": rng.integers(1, 1_000_000, n),
        "Total Fwd Packets": np.where(malicious, rng.integers(500, 1000, n), rng.integers(1, 50, n)),
        "Flow Bytes/s": rng.random(n) * 1e5,
        "Label": np.where(malicious, "DDoS", "BENIGN"),
    })


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    return buffer.getvalue().encode()


@pytest.fixture
def model_files(tmp_path):
    flows = synthetic_flows()
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(n_estimators=10, random_state=0)),
    ])
    pipeline.fit(flows[FEATURES], (flows["Label"] != "BENIGN").astype(int))

    model_path = tmp_path / "model.joblib"
    joblib.dump({"pipeline": pipeline, "feature_names": FEATURES,
                 "model_name": "Random Forest", "trained_at": "test"}, model_path)

    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(json.dumps({"best_model": "Random Forest", "models": []}))
    return model_path, metrics_path


@pytest.fixture
def client(model_files):
    model_path, metrics_path = model_files
    return TestClient(create_app(model_path, metrics_path, serve_frontend=False))


@pytest.fixture
def client_without_model(tmp_path):
    app = create_app(tmp_path / "missing.joblib", tmp_path / "missing.json", serve_frontend=False)
    return TestClient(app)
