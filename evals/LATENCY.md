# Guard latency: one run on this host

## Host fingerprint

- date: 2026-11-18T20:14:52.246Z
- commit: 4f413e1
- kernel: Linux 6.18.55-2-cachyos-lts x86_64
- cpu: AMD Ryzen 5 5500U with Radeon Graphics, 12 cores
- load average (1 / 5 / 15 min) before: 4.71 / 4.91 / 4.25; after: 5.93 / 5.17 / 4.35
- versions: node 26.13.0, Python 3.14.9, bun 1.4.4, omp/18.22.2
- method: cold N=30, warm and worker N=50, 5 warmups, rows interleaved, steady median of 50 calls per omp process

## Results (ms)

| Measurement | n | median | p90 | min | max | observed | expected |
|---|---:|---:|---:|---:|---:|---|---|
| Claude hook: `ls` (local rules, allow) · process wall | 30 | 178.67 | 239.46 | 145.09 | 308.22 | allow x30 | allow |
| Claude hook: `cat .env` (local rules, block or ask) · process wall | 30 | 179.82 | 228.43 | 146.47 | 433.41 | block x30 | block or ask |
| Claude hook: `ls` with JEV_GUARD_LOCAL=off, no server (fail-open floor) · process wall | 30 | 83.67 | 108.37 | 60.92 | 232.35 | allow x30 | allow |
| omp hook (stubbed omp import): `ls` · import (in-process) | 30 | 21.24 | 24.82 | 13.31 | 35.22 | allow x30 | allow |
| omp hook (stubbed omp import): `ls` · first tool_call | 30 | 3.37 | 5.21 | 2.72 | 23.11 | allow x30 | allow |
| omp hook (stubbed omp import): `ls` · steady median of 50 (per process) | 30 | 0.05 | 0.07 | 0.04 | 0.07 | allow x30 | allow |
| guardCommand in-process: `ls` | 50 | 0.17 | 0.3 | 0.12 | 0.62 | allow x50 | allow |
| guardCommand in-process: `cat .env` | 50 | 0.13 | 0.26 | 0.08 | 0.71 | block x50 | block or ask |

A local decision is not a network round trip. The Claude and warm rows run with no server configured, so they make no network call; only the Worker rows, enabled by --url, do.
