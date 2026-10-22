"""Preprocessing shared by training (ml/train.py) and inference (backend).

Keeping these functions in one place guarantees that a CSV uploaded to the API
is cleaned exactly the same way as the data the model was trained on.

Steps applied to every CSV:
  1. Strip whitespace from column names (CIC-IDS2017 headers look like " Flow Duration").
  2. Keep only the feature columns the model was trained on (in the same order).
  3. Convert values to numbers and turn +/-infinity into NaN.
The remaining NaN values are filled by the SimpleImputer that lives *inside* the
saved scikit-learn Pipeline, so imputation is also identical at inference time.
"""

import numpy as np
import pandas as pd

from ml.config import BENIGN_LABEL, LABEL_COLUMN

# CIC-IDS2017 contains "Fwd Header Length" twice; pandas renames the copy.
DUPLICATE_COLUMNS = ["Fwd Header Length.1"]


class FeatureValidationError(ValueError):
    """Raised when an uploaded CSV cannot be used by the model."""

    def __init__(self, message: str, columns: list[str] | None = None):
        super().__init__(message)
        self.columns = columns or []


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip spaces from headers and drop the known duplicate column."""
    df = df.rename(columns=lambda c: str(c).strip())
    return df.drop(columns=[c for c in DUPLICATE_COLUMNS if c in df.columns])


def to_binary_labels(labels: pd.Series) -> np.ndarray:
    """Map 'BENIGN' -> 0 and every attack type -> 1 (Malicious)."""
    cleaned = labels.astype(str).str.strip().str.upper()
    return (cleaned != BENIGN_LABEL).astype(np.int8).to_numpy()


def prepare_features(df: pd.DataFrame, feature_names: list[str]) -> pd.DataFrame:
    """Validate a raw DataFrame and return only the model's numeric features.

    Raises FeatureValidationError if columns are missing or contain text that
    cannot be interpreted as a number.
    """
    df = clean_column_names(df)

    missing = [name for name in feature_names if name not in df.columns]
    if missing:
        raise FeatureValidationError(
            f"CSV is missing {len(missing)} required feature column(s).", missing
        )

    features = pd.DataFrame(index=df.index)
    bad_columns = []
    for name in feature_names:
        column = df[name]
        numeric = pd.to_numeric(column, errors="coerce")
        # A value is "bad" if it was present in the file but is not a number.
        if (numeric.isna() & column.notna() & (column.astype(str).str.strip() != "")).any():
            bad_columns.append(name)
        features[name] = numeric

    if bad_columns:
        raise FeatureValidationError(
            f"{len(bad_columns)} feature column(s) contain non-numeric values.", bad_columns
        )

    features = features.astype(np.float64).replace([np.inf, -np.inf], np.nan)
    return features


def has_labels(df: pd.DataFrame) -> bool:
    """True if the (header-cleaned) DataFrame contains a ground-truth Label column."""
    return LABEL_COLUMN in df.columns
