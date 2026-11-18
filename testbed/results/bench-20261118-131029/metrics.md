# NEXUS-IoT testbed benchmark `bench-20261118-131029`

- Created: 2026-11-18T07:40:29+00:00
- Seeds: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
- Scenarios: S1, S2, S3, S4, S5, S6, S7
- Duration per run: 60 s
- Runs: 70 total, 70 scored, 0 failed
- Wall time: 4961 s

## Per-scenario summary

Mean ± sample std (min) across seeds; failed runs excluded.

| Scenario | Title | Runs ok/total | Event F1 | Precision | Recall | Time <= 1 s | Completeness | Gap precision | Gap recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Normal operation | 10/10 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S2 | Device disconnection | 10/10 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S3 | Clock step | 10/10 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S4 | Clock drift | 10/10 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S5 | Capture gap | 10/10 | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S6 | Post-collection tampering | 10/10 | 0.983 ± 0.000 (min 0.983) | 0.978 ± 0.000 (min 0.978) | 0.989 ± 0.000 (min 0.989) | 0.989 ± 0.000 (min 0.989) | 0.994 ± 0.000 (min 0.994) | 1.000 ± 0.000 (min 1.000) | 1.000 ± 0.000 (min 1.000) |
| S7 | Combined | 10/10 | 0.983 ± 0.000 (min 0.983) | 0.978 ± 0.000 (min 0.978) | 0.989 ± 0.000 (min 0.989) | 0.989 ± 0.000 (min 0.989) | 0.994 ± 0.000 (min 0.994) | 0.900 ± 0.316 (min 0.000) | 0.900 ± 0.316 (min 0.000) |

## Alert detection (scenario level)

Over all scored runs. Tamper positives: `tampering_seeded`; clock positives: `clock_manipulated`.

| Alert | Positive runs | Negative runs | TP | FP | FN | TN | Recall | False-positive rate | Precision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| tamper | 20 | 50 | 20 | 0 | 0 | 50 | 1.000 | 0.000 | 1.000 |
| clock | 30 | 40 | 30 | 0 | 0 | 40 | 1.000 | 0.000 | 1.000 |

## Runs

| Scenario | Seed | Status | F1 | Precision | Recall | Time <= 1 s | Completeness | Gap P | Gap R | Median error (s) | Tamper alert | Clock alert | Parameters |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect temp-sensor 15.9-31.4s |
| S3 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step motion-sensor -30.5s at 43.7s, offset -6.9s |
| S4 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift smart-lock +14106 ppm |
| S5 | 1 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | capture gap 42.6-48s |
| S6 | 1 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.003 | yes | no | delete smart-plug[12]; edit door-sensor[19]->door_close; insert door-sensor[7] |
| S7 | 1 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 0.000 | 0.000 | 0.002 | yes | yes | disconnect door-sensor 14.6-29.6s; step temp-sensor -10s at 21.7s, offset -2.1s; delete motion-sensor[11]; edit door-sensor[18]->door_open; insert door-sensor[5] |
| S1 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect door-sensor 26.2-42.1s |
| S3 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step smart-lock -34.2s at 25.3s, offset +3.2s |
| S4 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift door-sensor +9394 ppm |
| S5 | 2 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 12.1-26.7s |
| S6 | 2 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete door-sensor[8]; edit smart-plug[5]->plug_off; insert smart-plug[11] |
| S7 | 2 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect smart-lock 9.4-29.7s; step door-sensor -96.6s at 48.1s, offset +9.3s; delete smart-plug[4]; edit door-sensor[10]->door_open; insert door-sensor[2] |
| S1 | 3 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 3 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect door-sensor 8.6-16.8s |
| S3 | 3 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step smart-plug +48.8s at 13.9s, offset +2.2s |
| S4 | 3 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift door-sensor +15011 ppm |
| S5 | 3 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 33.7-42.9s |
| S6 | 3 | ok | 0.984 | 0.978 | 0.989 | 0.989 | 0.995 | 1.000 | 1.000 | 0.002 | yes | no | delete smart-plug[8]; edit temp-sensor[2]->temperature_reading_forced; insert temp-sensor[17] |
| S7 | 3 | ok | 0.984 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect door-sensor 13.6-28.2s; step temp-sensor -15.6s at 16.9s, offset -1.4s; delete smart-plug[11]; edit door-sensor[12]->door_open; insert door-sensor[16] |
| S1 | 4 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 4 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect smart-lock 9.6-27.9s |
| S3 | 4 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | yes | step smart-plug +110.6s at 30.4s, offset -2.9s |
| S4 | 4 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift smart-plug -19855 ppm |
| S5 | 4 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | capture gap 12.2-23.2s |
| S6 | 4 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete temp-sensor[16]; edit smart-lock[7]->lock_released; insert smart-lock[2] |
| S7 | 4 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect motion-sensor 16-29s; step smart-plug -118.9s at 44.6s, offset +7.3s; delete motion-sensor[8]; edit smart-lock[5]->lock_released; insert smart-lock[2] |
| S1 | 5 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 5 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | disconnect temp-sensor 12.2-23.1s |
| S3 | 5 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step smart-lock -19.1s at 37.3s, offset -9.8s |
| S4 | 5 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift motion-sensor +8960 ppm |
| S5 | 5 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 25.7-36.6s |
| S6 | 5 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete motion-sensor[7]; edit smart-lock[5]->lock_released; insert smart-lock[8] |
| S7 | 5 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.003 | yes | yes | disconnect temp-sensor 44.3-53.2s; step motion-sensor +40.3s at 26.8s, offset -0.8s; delete smart-plug[2]; edit motion-sensor[4]->motion_detected; insert motion-sensor[9] |
| S1 | 6 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 6 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect smart-lock 8.1-28s |
| S3 | 6 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step temp-sensor -80.7s at 7.4s, offset +5.4s |
| S4 | 6 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift motion-sensor -14356 ppm |
| S5 | 6 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 36.3-51.1s |
| S6 | 6 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete smart-plug[8]; edit door-sensor[6]->door_open; insert door-sensor[2] |
| S7 | 6 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect smart-plug 31.2-44.6s; step temp-sensor -98s at 47.3s, offset -2.8s; delete motion-sensor[8]; edit smart-plug[4]->plug_on; insert smart-plug[13] |
| S1 | 7 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | none |
| S2 | 7 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect smart-lock 19-34s |
| S3 | 7 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step smart-lock -71.8s at 23.1s, offset -1.5s |
| S4 | 7 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift motion-sensor +16982 ppm |
| S5 | 7 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 47.3-53.3s |
| S6 | 7 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete door-sensor[2]; edit smart-plug[12]->plug_on; insert smart-plug[2] |
| S7 | 7 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect motion-sensor 28-47.6s; step smart-lock -106.5s at 19.2s, offset +0.2s; delete smart-plug[11]; edit motion-sensor[10]->motion_detected; insert motion-sensor[8] |
| S1 | 8 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 8 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect temp-sensor 28.7-43s |
| S3 | 8 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | step temp-sensor -82.6s at 29.2s, offset -8.1s |
| S4 | 8 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift smart-lock +6605 ppm |
| S5 | 8 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | capture gap 48.1-53.8s |
| S6 | 8 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete motion-sensor[10]; edit temp-sensor[23]->temperature_reading_forced; insert temp-sensor[8] |
| S7 | 8 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect smart-plug 20.7-36.6s; step temp-sensor +45.6s at 31.3s, offset +7.3s; delete temp-sensor[11]; edit smart-plug[2]->plug_on; insert smart-plug[11] |
| S1 | 9 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 9 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | disconnect temp-sensor 22.3-36.2s |
| S3 | 9 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | yes | step motion-sensor -100.9s at 30.4s, offset -5.8s |
| S4 | 9 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift smart-lock -13258 ppm |
| S5 | 9 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | capture gap 33.6-47.4s |
| S6 | 9 | ok | 0.984 | 0.978 | 0.989 | 0.989 | 0.995 | 1.000 | 1.000 | 0.003 | yes | no | delete smart-lock[6]; edit door-sensor[16]->door_open; insert door-sensor[8] |
| S7 | 9 | ok | 0.984 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.003 | yes | yes | disconnect smart-plug 9.9-23.4s; step temp-sensor +78.9s at 7.2s, offset +0.3s; delete smart-lock[3]; edit motion-sensor[9]->motion_cleared; insert motion-sensor[5] |
| S1 | 10 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | none |
| S2 | 10 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | no | disconnect motion-sensor 20.7-39.5s |
| S3 | 10 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | yes | step smart-plug -39.1s at 15s, offset +4.5s |
| S4 | 10 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.002 | no | yes | drift smart-lock +16898 ppm |
| S5 | 10 | ok | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.003 | no | no | capture gap 14.2-22.4s |
| S6 | 10 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | no | delete smart-plug[11]; edit door-sensor[15]->door_close; insert door-sensor[14] |
| S7 | 10 | ok | 0.983 | 0.978 | 0.989 | 0.989 | 0.994 | 1.000 | 1.000 | 0.002 | yes | yes | disconnect temp-sensor 21.6-33.4s; step door-sensor +71.2s at 49.9s, offset -8.6s; delete smart-lock[2]; edit motion-sensor[8]->motion_detected; insert motion-sensor[4] |

## Limits

- Synthetic testbed: simulated devices publish scripted telemetry on a closed Docker network; scores describe tool behaviour on this testbed, not on real IoT hardware or traffic.
- All containers share the host clock. Device clock faults (offset, drift, step) are simulated in software and the gateway clock is taken as true time.
- Small samples: each scenario is run once per seed, so a std over a few seeds is a rough spread, not a confidence interval. Alert rates are per run (scenario level), not per event.
- Seeds vary fault parameters, device jitter and values; the seven fault families are fixed and only S7 combines faults.
- Ground truth for delivery comes from the pre-tamper gateway log, so a missed source row means one the gateway actually logged. Docker timing (disconnect detection, reconnect delay) adds variance the seed does not control.
- Clock steps may be negative (clock set back). The analyzer models a single backward step and reports it as a clock change; a backward jump it cannot explain is still read as possible tampering and counts as a tamper false positive here.
