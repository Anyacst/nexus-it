# NEXUS-IoT testbed benchmark `bench-20261118-011226`

- Created: 2026-11-17T19:42:26+00:00
- Seeds: 1, 2
- Scenarios: S1, S2, S3, S4, S5, S6, S7
- Duration per run: 45 s
- Runs: 14 total, 14 scored, 0 failed
- Wall time: 784 s

## Per-scenario summary

Mean ± sample std (min) across seeds; failed runs excluded.

| Scenario | Title | Runs ok/total | Event F1 | Precision | Recall | Time <= 1 s | Completeness | Gap precision | Gap recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Normal operation | 2/2 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S2 | Device disconnection | 2/2 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S3 | Clock step | 2/2 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S4 | Clock drift | 2/2 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S5 | Capture gap | 2/2 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S6 | Post-collection tampering | 2/2 | 0.978 ± 0.000 (min 0.978) | 0.971 ± 0.000 (min 0.971) | 0.985 ± 0.000 (min 0.985) | 0.985 ± 0.000 (min 0.985) | 0.993 ± 0.000 (min 0.993) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S7 | Combined | 2/2 | 0.978 ± 0.000 (min 0.978) | 0.971 ± 0.000 (min 0.971) | 0.985 ± 0.000 (min 0.985) | 0.985 ± 0.000 (min 0.985) | 0.992 ± 0.000 (min 0.992) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |

## Alert detection (scenario level)

Over all scored runs. Tamper positives: `tampering_seeded`; clock positives: `clock_manipulated`.

| Alert | Positive runs | Negative runs | TP | FP | FN | TN | Recall | False-positive rate | Precision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| tamper | 4 | 10 | 4 | 2 | 0 | 8 | 1.000 | 0.200 | 0.667 |
| clock | 6 | 8 | 6 | 0 | 0 | 8 | 1.000 | 0.000 | 1.000 |

## Runs

| Scenario | Seed | Status | F1 | Precision | Recall | Time <= 1 s | Completeness | Gap P | Gap R | Median error (s) | Tamper alert | Clock alert | Parameters |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | disconnect temp-sensor 10.9-26.4s |
| S3 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | yes | yes | step motion-sensor -30.5s at 26.3s, offset -6.9s |
| S4 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift smart-lock +14106 ppm |
| S5 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 23.9-29.3s |
| S6 | 1 | ok | 0.978 | 0.971 | 0.985 | 0.985 | 0.993 | 1.000 | 1.000 | 0.002 | yes | no | delete smart-plug[10]; edit door-sensor[13]->door_close; insert door-sensor[4] |
| S7 | 1 | ok | 0.978 | 0.971 | 0.985 | 0.985 | 0.992 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect door-sensor 10.3-25.3s; step temp-sensor -10s at 21.7s, offset -2.1s; delete motion-sensor[2]; edit door-sensor[1]->door_close; insert door-sensor[13] |
| S1 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect door-sensor 16.1-32s |
| S3 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | yes | yes | step smart-lock -34.2s at 22s, offset +3.2s |
| S4 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift door-sensor +9394 ppm |
| S5 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | capture gap 9-23.6s |
| S6 | 2 | ok | 0.978 | 0.971 | 0.985 | 0.985 | 0.993 | 1.000 | 1.000 | 0.002 | yes | no | delete door-sensor[12]; edit smart-plug[4]->plug_on; insert smart-plug[8] |
| S7 | 2 | ok | 0.978 | 0.971 | 0.985 | 0.985 | 0.992 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect temp-sensor 7.1-17s; step door-sensor -96.6s at 34.6s, offset +9.3s; delete temp-sensor[1]; edit smart-plug[7]->plug_off; insert smart-plug[6] |

## Limits

- Synthetic testbed: simulated devices publish scripted telemetry on a closed Docker network; scores describe tool behaviour on this testbed, not on real IoT hardware or traffic.
- All containers share the host clock. Device clock faults (offset, drift, step) are simulated in software and the gateway clock is taken as true time.
- Small samples: each scenario is run once per seed, so a std over a few seeds is a rough spread, not a confidence interval. Alert rates are per run (scenario level), not per event.
- Seeds vary fault parameters, device jitter and values; the seven fault families are fixed and only S7 combines faults.
- Ground truth for delivery comes from the pre-tamper gateway log, so a missed source row means one the gateway actually logged. Docker timing (disconnect detection, reconnect delay) adds variance the seed does not control.
- Clock steps may be negative (clock set back). Backward device timestamps can also be read as tampering; such an alert counts as a tamper false positive here.
