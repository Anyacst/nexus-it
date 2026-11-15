# NEXUS-IoT synthetic evaluation

Scenario count: 10

| Condition | Event P | Event R | Event F1 | Label accuracy | Time ≤1s | Median error | Max error | Order | Completeness | Processing (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| E1 Normal operation | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.000s | 0.000s | 100.0% | 100.0% | 0.026179 |
| E2 Device disconnection | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.000s | 0.000s | 100.0% | 100.0% | 0.016830 |
| E3 Missing log entries | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.000s | 0.000s | 100.0% | 95.8% | 0.017733 |
| E4 Timestamp manipulation | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.000s | 0.000s | 100.0% | 100.0% | 0.016704 |
| E5 Gateway packet loss | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.000s | 0.000s | 100.0% | 91.7% | 0.017084 |
| E6 Evidence tampering | 84.6% | 91.7% | 88.0% | 100.0% | 91.7% | 0.000s | 0.000s | 100.0% | 100.0% | 0.018066 |
| E7 Multiple failures combined | 80.0% | 88.9% | 84.2% | 100.0% | 77.8% | 0.000s | 2.000s | 100.0% | 88.2% | 0.016784 |
| T1 Tamper control: edit only | 91.7% | 91.7% | 91.7% | 100.0% | 91.7% | 0.000s | 0.000s | 100.0% | 100.0% | 0.017332 |
| T2 Tamper control: insertion only | 92.3% | 100.0% | 96.0% | 100.0% | 100.0% | 0.000s | 0.000s | 100.0% | 100.0% | 0.016721 |
| T3 Inference control: omitted periodic event | 100.0% | 91.7% | 95.7% | 100.0% | 91.7% | 0.000s | 0.000s | 100.0% | 91.7% | 0.017802 |

## Gap and inference quality

- Unknown-gap precision / recall: 100.0% / 100.0%
- Inferred-event precision / recall: 100.0% / 100.0%
- Scores are averaged per scenario. The inference control removes a periodic event from every evidence source; the score does not establish general inference quality.

## Tamper alerts

- Recall: 100.0%
- False-positive rate: 0.0%
- Precision: 100.0%

## Clock anomaly alerts

- Recall: 100.0%
- False-positive rate: 0.0%
- Precision: 100.0%

## Aggregate metrics

- Event precision / recall: 94.8% / 96.5%
- Mean event-label accuracy: 100.0%
- Mean pairwise ordering: 100.0%
- Mean completeness: 96.7%
- Mean processing: 0.018124s

## Metrics and limits

- Event precision/recall/F1 are exact event-ID and event-name matching scores.
- Label accuracy compares Confirmed/Single-source against known expected source rows and agreement.
- Time≤1s counts correctly matched truth events whose reconstructed time is within one second; misses count as failures.
- Pairwise order compares the order of correctly matched event pairs; it excludes misses.
- Completeness counts expected source-event rows present by ID; extra inserted records cannot mask missing rows.
- Tamper and clock alert rates are scenario-level indicators over small deterministic cases. They are not proof or general estimates.
- Unknown-gap precision/recall compare predicted missing sequence values with source rows intentionally omitted from the synthetic fixtures; they do not score arbitrary semantic gaps.
- Inferred-event scores use events absent from all supplied sources and match predictions by name and within one second. Only one dedicated synthetic inference control is present; this does not measure uncertainty calibration or general inference validity.
- PCAP loss detection beyond sequence-bearing gateway logs and real testbed performance remain unscored.

These results characterize the generated dataset only.
