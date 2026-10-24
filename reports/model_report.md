# Model evaluation report

Generated: 2026-10-22T18:45:52+00:00  
Dataset: CIC-IDS2017 MachineLearningCSV (Canadian Institute for Cybersecurity)  
Protocol: original  
Flows used: 500,000 (train 310,000 / validation 39,996 / calibration 50,004 / test 100,000)  
Selected model: **Random Forest**  
Selection rule: validation F1-score (Random Forest is kept unless another model beats it by more than 0.001)

Test-set results (positive class = Malicious):

| Model | Validation F1 | Accuracy | Precision | Recall | F1-score | Train time (s) |
|---|---|---|---|---|---|---|
| Random Forest | 0.9946 | 0.9983 | 0.9956 | 0.9942 | 0.9949 | 14.66 |
| Decision Tree | 0.9944 | 0.9982 | 0.9947 | 0.9946 | 0.9946 | 10.62 |
| Logistic Regression | 0.8698 | 0.9561 | 0.8780 | 0.8618 | 0.8699 | 4.07 |

Confusion matrices on the test set ([[TN, FP], [FN, TP]]):

- Random Forest: [[82887, 75], [99, 16939]]
- Decision Tree: [[82871, 91], [92, 16946]]
- Logistic Regression: [[80922, 2040], [2354, 14684]]

## Reliability layer

- Calibration: isotonic+crc (alpha=0.01, review capacity=0.05)
- Alert threshold: 0.0182, review band lower edge: 0.0116

| Variant | Precision | Recall | F1 | FPR | Alerts |
|---|---|---|---|---|---|
| B0 raw RF @0.5 | 0.9953 | 0.9942 | 0.9948 | 0.00096 | 17020 |
| B1 calibrated @0.5 | 0.9910 | 0.9982 | 0.9946 | 0.00186 | 17161 |
| B2 CRC threshold | 0.9683 | 0.9992 | 0.9835 | 0.00673 | 17583 |
| B3 + review band | 0.9683 | 0.9992 | 0.9835 | 0.00673 | 17583 |

- Review rate: 0.30% (301 of 100,000 flows)

## Batch shift gate

- In-distribution false-alarm rate: 0.00%
- Synthetic-shift detection rate: 100.00%
- Separation (AUC): 1.0000
