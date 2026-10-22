"""NetGuard AI - FastAPI backend.

Start from the project root:
    uvicorn backend.app.main:app --reload --port 8000
"""

import io
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from backend.app.model_store import ModelNotAvailableError, ModelStore
from ml import config
from ml.preprocess import FeatureValidationError, clean_column_names, has_labels, to_binary_labels

MAX_UPLOAD_MB = 100
MAX_TABLE_ROWS = 5000  # rows returned for the results table; counts always use every row

# A few human-friendly columns shown in the dashboard's results table.
DISPLAY_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
]

FRONTEND_DIST = config.PROJECT_ROOT / "frontend" / "dist"


def read_csv_upload(upload: UploadFile) -> pd.DataFrame:
    """Validate the uploaded file and parse it into a DataFrame."""
    if not upload.filename or not upload.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a file with a .csv extension.")

    content = upload.file.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File is larger than {MAX_UPLOAD_MB} MB.")
    if not content.strip():
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    try:
        df = pd.read_csv(io.BytesIO(content), encoding="latin-1", low_memory=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}") from exc

    if df.empty:
        raise HTTPException(status_code=400, detail="The CSV has a header but no data rows.")
    return clean_column_names(df)


def json_value(value):
    """Convert numpy / NaN values into something JSON can represent."""
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        return None if math.isnan(value) or math.isinf(value) else float(value)
    return value


def create_app(model_path: Path = config.MODEL_PATH,
               metrics_path: Path = config.METRICS_PATH,
               serve_frontend: bool = True) -> FastAPI:
    app = FastAPI(title="NetGuard AI", version="1.0.0",
                  description="Malware detection using AI-based network traffic analysis")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    store = ModelStore(model_path)

    def predict_or_raise(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        try:
            return store.predict(df)
        except ModelNotAvailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except FeatureValidationError as exc:
            raise HTTPException(
                status_code=422, detail={"message": str(exc), "columns": exc.columns}
            ) from exc

    @app.get("/api/health")
    def health():
        try:
            bundle = store.get()
        except ModelNotAvailableError as exc:
            return {"status": "ok", "model_loaded": False, "error": str(exc)}
        return {
            "status": "ok",
            "model_loaded": True,
            "model_name": bundle["model_name"],
            "trained_at": bundle.get("trained_at"),
            "feature_count": len(bundle["feature_names"]),
        }

    @app.get("/api/model/features")
    def model_features():
        try:
            bundle = store.get()
        except ModelNotAvailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"features": bundle["feature_names"]}

    @app.get("/api/metrics")
    def metrics():
        path = Path(metrics_path)
        if not path.exists():
            raise HTTPException(
                status_code=404,
                detail="No evaluation report found. Run `python -m ml.train` first.",
            )
        return json.loads(path.read_text())

    @app.post("/api/predict")
    def predict(file: UploadFile = File(...)):
        df = read_csv_upload(file)
        predictions, probabilities = predict_or_raise(df)

        total = len(predictions)
        malicious = int(predictions.sum())
        labelled = has_labels(df)
        actual = to_binary_labels(df[config.LABEL_COLUMN]) if labelled else None

        display_columns = [c for c in DISPLAY_COLUMNS if c in df.columns]
        rows = []
        for i in range(min(total, MAX_TABLE_ROWS)):
            pred = int(predictions[i])
            rows.append({
                "row": i + 1,
                "values": {c: json_value(df[c].iat[i]) for c in display_columns},
                "prediction": config.CLASS_NAMES[pred],
                "malicious_probability": round(float(probabilities[i]), 4),
                "actual": config.CLASS_NAMES[int(actual[i])] if labelled else None,
            })

        evaluation = None
        if labelled:
            correct = int((actual == predictions).sum())
            evaluation = {
                "accuracy": correct / total,
                "correct": correct,
                "actual_malicious": int(actual.sum()),
                "actual_benign": int(total - actual.sum()),
            }

        return {
            "filename": file.filename,
            "model_name": store.get()["model_name"],
            "summary": {
                "total": total,
                "benign": total - malicious,
                "malicious": malicious,
                "malicious_ratio": malicious / total,
            },
            "evaluation": evaluation,
            "display_columns": display_columns,
            "rows": rows,
            "rows_truncated": total > MAX_TABLE_ROWS,
        }

    @app.post("/api/predict/download")
    def predict_download(file: UploadFile = File(...)):
        """Return the uploaded CSV with Prediction and Malicious_Probability columns added."""
        df = read_csv_upload(file)
        predictions, probabilities = predict_or_raise(df)
        df["Prediction"] = [config.CLASS_NAMES[p] for p in predictions]
        df["Malicious_Probability"] = np.round(probabilities, 4)

        buffer = io.StringIO()
        df.to_csv(buffer, index=False)
        stem = Path(file.filename or "traffic").stem
        return StreamingResponse(
            iter([buffer.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{stem}_predictions.csv"'},
        )

    # Optional: serve the built React app so the whole project runs on one port.
    if serve_frontend and FRONTEND_DIST.exists():
        app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

    return app


app = create_app()
