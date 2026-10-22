import io

import numpy as np
import pandas as pd

from backend.tests.conftest import FEATURES, synthetic_flows, to_csv_bytes
from ml.preprocess import FeatureValidationError, prepare_features, to_binary_labels


def upload(client, content: bytes, filename: str = "flows.csv", path: str = "/api/predict"):
    return client.post(path, files={"file": (filename, content, "text/csv")})


# ---------------------------------------------------------------- health / metrics
def test_health_reports_loaded_model(client):
    body = client.get("/api/health").json()
    assert body["model_loaded"] is True
    assert body["model_name"] == "Random Forest"
    assert body["feature_count"] == len(FEATURES)


def test_health_without_model(client_without_model):
    body = client_without_model.get("/api/health").json()
    assert body["model_loaded"] is False


def test_metrics_endpoint(client, client_without_model):
    assert client.get("/api/metrics").json()["best_model"] == "Random Forest"
    assert client_without_model.get("/api/metrics").status_code == 404


# ---------------------------------------------------------------- predictions
def test_predict_returns_counts_for_every_row(client):
    flows = synthetic_flows(n=120, seed=1)
    response = upload(client, to_csv_bytes(flows))
    assert response.status_code == 200
    body = response.json()

    summary = body["summary"]
    assert summary["total"] == 120
    assert summary["benign"] + summary["malicious"] == 120
    assert len(body["rows"]) == 120
    assert {r["prediction"] for r in body["rows"]} <= {"Benign", "Malicious"}
    # The synthetic pattern is easy, so the model should get almost everything right.
    assert body["evaluation"]["accuracy"] > 0.9


def test_predict_without_label_column(client):
    flows = synthetic_flows(n=30).drop(columns=["Label"])
    body = upload(client, to_csv_bytes(flows)).json()
    assert body["evaluation"] is None
    assert body["rows"][0]["actual"] is None


def test_headers_with_spaces_and_infinity_are_accepted(client):
    """CIC-IDS2017 files have headers like ' Flow Duration' and 'Infinity' values."""
    flows = synthetic_flows(n=10)
    flows["Flow Bytes/s"] = flows["Flow Bytes/s"].astype(object)
    flows.loc[0, "Flow Bytes/s"] = "Infinity"
    flows.loc[1, "Flow Bytes/s"] = np.nan
    flows.columns = [" " + c for c in flows.columns]
    response = upload(client, to_csv_bytes(flows))
    assert response.status_code == 200
    assert response.json()["summary"]["total"] == 10


def test_download_adds_prediction_columns(client):
    flows = synthetic_flows(n=25)
    response = upload(client, to_csv_bytes(flows), path="/api/predict/download")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    result = pd.read_csv(io.StringIO(response.text))
    assert len(result) == 25
    assert {"Prediction", "Malicious_Probability"} <= set(result.columns)


# ---------------------------------------------------------------- invalid input
def test_missing_columns_are_rejected(client):
    flows = synthetic_flows(n=10).drop(columns=["Flow Duration", "Total Fwd Packets"])
    response = upload(client, to_csv_bytes(flows))
    assert response.status_code == 422
    assert set(response.json()["detail"]["columns"]) == {"Flow Duration", "Total Fwd Packets"}


def test_non_numeric_values_are_rejected(client):
    flows = synthetic_flows(n=10)
    flows["Flow Duration"] = flows["Flow Duration"].astype(object)
    flows.loc[3, "Flow Duration"] = "hello"
    response = upload(client, to_csv_bytes(flows))
    assert response.status_code == 422
    assert response.json()["detail"]["columns"] == ["Flow Duration"]


def test_wrong_extension_is_rejected(client):
    assert upload(client, b"a,b\n1,2\n", filename="flows.txt").status_code == 400


def test_empty_file_is_rejected(client):
    assert upload(client, b"").status_code == 400
    assert upload(client, b"Flow Duration,Label\n").status_code == 400


def test_predict_without_model_returns_503(client_without_model):
    response = upload(client_without_model, to_csv_bytes(synthetic_flows(n=5)))
    assert response.status_code == 503


# ---------------------------------------------------------------- preprocessing
def test_label_mapping():
    labels = pd.Series(["BENIGN", " DDoS", "PortScan", "benign "])
    assert to_binary_labels(labels).tolist() == [0, 1, 1, 0]


def test_prepare_features_keeps_model_column_order():
    df = synthetic_flows(n=5)[list(reversed(FEATURES))]
    prepared = prepare_features(df, FEATURES)
    assert list(prepared.columns) == FEATURES


def test_prepare_features_reports_missing_columns():
    try:
        prepare_features(pd.DataFrame({"Flow Duration": [1]}), FEATURES)
    except FeatureValidationError as exc:
        assert "Destination Port" in exc.columns
    else:
        raise AssertionError("expected FeatureValidationError")
