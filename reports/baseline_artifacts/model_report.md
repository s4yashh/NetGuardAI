# Model evaluation report

Generated: 2026-10-22T05:43:09+00:00  
Dataset: CIC-IDS2017 MachineLearningCSV (Canadian Institute for Cybersecurity)  
Flows used: 500,000 (train 360,000 / validation 40,000 / test 100,000)  
Selected model: **Random Forest**  
Selection rule: validation F1-score (Random Forest is kept unless another model beats it by more than 0.001)

Test-set results (positive class = Malicious):

| Model | Validation F1 | Accuracy | Precision | Recall | F1-score | Train time (s) |
|---|---|---|---|---|---|---|
| Random Forest | 0.9955 | 0.9983 | 0.9958 | 0.9944 | 0.9951 | 74.16 |
| Decision Tree | 0.9957 | 0.9981 | 0.9941 | 0.9950 | 0.9946 | 30.96 |
| Logistic Regression | 0.8688 | 0.9561 | 0.8781 | 0.8623 | 0.8701 | 31.36 |

Confusion matrices on the test set ([[TN, FP], [FN, TP]]):

- Random Forest: [[82890, 72], [95, 16943]]
- Decision Tree: [[82862, 100], [85, 16953]]
- Logistic Regression: [[80922, 2040], [2346, 14692]]
