from ml.train import select_model


def results(rf: float, dt: float, lr: float) -> list[dict]:
    return [
        {"name": "Random Forest", "validation_f1": rf},
        {"name": "Decision Tree", "validation_f1": dt},
        {"name": "Logistic Regression", "validation_f1": lr},
    ]


def test_random_forest_kept_when_difference_is_noise():
    assert select_model(results(0.9955, 0.9957, 0.87))["name"] == "Random Forest"


def test_clearly_better_model_replaces_random_forest():
    assert select_model(results(0.95, 0.99, 0.87))["name"] == "Decision Tree"
