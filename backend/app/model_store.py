"""Loads the saved model bundle from disk and runs predictions."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.preprocess import prepare_features


class ModelNotAvailableError(RuntimeError):
    """Raised when no trained model has been saved yet (or it cannot be read)."""


class ModelStore:
    """Keeps the trained pipeline in memory and reloads it if the file changes."""

    def __init__(self, model_path: Path):
        self.model_path = Path(model_path)
        self._bundle: dict | None = None
        self._loaded_mtime: float | None = None

    def get(self) -> dict:
        if not self.model_path.exists():
            raise ModelNotAvailableError(
                "No trained model found. Run `python -m ml.train` first."
            )
        mtime = self.model_path.stat().st_mtime
        if self._bundle is None or mtime != self._loaded_mtime:
            try:
                bundle = joblib.load(self.model_path)
            except Exception as exc:  # corrupted or incompatible file
                raise ModelNotAvailableError(f"Model file could not be loaded: {exc}") from exc
            if not {"pipeline", "feature_names", "model_name"} <= set(bundle):
                raise ModelNotAvailableError("Model file has an unexpected format.")
            self._bundle, self._loaded_mtime = bundle, mtime
        return self._bundle

    def predict(self, raw: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Return (predicted class 0/1, probability of Malicious) for every row."""
        bundle = self.get()
        features = prepare_features(raw, bundle["feature_names"])
        pipeline = bundle["pipeline"]
        predictions = pipeline.predict(features)
        malicious_probability = pipeline.predict_proba(features)[:, 1]
        return predictions.astype(int), malicious_probability
