"""Loads the saved model bundle from disk and runs predictions.

The bundle may or may not contain a ``reliability`` layer and a ``shift_profile``.
Bundles written before those existed still load and predict exactly as before, so
old model artefacts and the existing tests remain valid.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml import reliability
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

    def predict(self, raw: pd.DataFrame) -> dict:
        """Return predictions, calibrated probabilities, decisions and a shift verdict.

        Keys
        ----
        ``predictions``   binary 0/1 (``calibrated >= 0.5``); kept for compatibility
        ``probabilities`` calibrated probability of Malicious
        ``raw_probabilities`` the ensemble's raw vote fraction
        ``decisions``     0 benign / 1 malicious / 2 review
        ``reliability``   whether the layer is active, and its thresholds
        ``shift``         batch-level distribution verdict, or ``None``
        """
        bundle = self.get()
        features = prepare_features(raw, bundle["feature_names"])
        pipeline = bundle["pipeline"]

        raw_probabilities = np.asarray(
            pipeline.predict_proba(features)[:, 1], dtype=float)

        layer = bundle.get("reliability")
        if layer:
            probabilities = reliability.apply_calibration(
                layer.get("calibrator"), raw_probabilities)
            decisions = reliability.decide(
                probabilities, layer["t_benign"], layer["t_alert"])
            layer_info = {
                "active": True,
                "kind": layer.get("kind", "isotonic+crc"),
                "alpha": layer.get("alpha"),
                "t_alert": layer.get("t_alert"),
                "t_benign": layer.get("t_benign"),
                "review_capacity": layer.get("review_capacity"),
            }
        else:
            probabilities = np.clip(raw_probabilities, 0.0, 1.0)
            decisions = np.where(probabilities >= 0.5,
                                 reliability.MALICIOUS, reliability.BENIGN).astype(np.int8)
            layer_info = {"active": False}

        predictions = np.where(probabilities >= 0.5,
                               reliability.MALICIOUS, reliability.BENIGN).astype(int)

        shift = None
        profile = bundle.get("shift_profile")
        if profile:
            matrix = features.to_numpy(dtype=float)
            # Compare the traffic the model believes is benign against the benign
            # reference. Flagged flows are meant to look different, so including
            # them would make every batch with attacks look "shifted".
            benign_like = decisions != reliability.MALICIOUS
            basis = "non_alerted"
            if np.count_nonzero(benign_like) < 100:
                benign_like = np.ones(matrix.shape[0], dtype=bool)
                basis = "all_flows"
            score, per_feature = reliability.batch_shift_score(
                matrix[benign_like], profile)
            shift = {
                **reliability.shift_verdict(score, profile, per_feature=per_feature),
                "basis": basis,
                "rows_compared": int(np.count_nonzero(benign_like)),
            }

        return {
            "predictions": predictions,
            "probabilities": probabilities,
            "raw_probabilities": raw_probabilities,
            "decisions": decisions,
            "reliability": layer_info,
            "shift": shift,
        }
