# Guard latency: one run on this host

> **NOISY RUN.** 1-min load 12.64 before the run is above cores/2 (6); 1-min load 11.94 after the run is above cores/2 (6). Read these as upper bounds, not a clean baseline.

## Host fingerprint

- date: 2026-11-18T20:32:33.168Z
- commit: 506f892 (merge-base with origin/main: b12e50f)
- kernel: Linux 6.18.55-2-cachyos-lts x86_64
- cpu: AMD Ryzen 5 5500U with Radeon Graphics, 12 cores
- load average (1 / 5 / 15 min) before: 12.64 / 9.03 / 7.21; after: 11.94 / 9.37 / 7.41
- versions: node 26.13.0, Python 3.14.9, bun 1.4.4, omp/18.22.2
- method: cold N=30, warm and worker N=50, 5 warmups, rows interleaved, steady median of 50 calls per omp process

## Results (ms)

| Measurement | n | median | p90 | min | max | observed | expected |
|---|---:|---:|---:|---:|---:|---|---|
| Claude hook: `ls` (local rules, allow) · process wall | 30 | 211.27 | 255.31 | 163.42 | 369.36 | allow x30 | allow |
| Claude hook: `cat .env` (local rules, block or ask) · process wall | 30 | 216.36 | 248.23 | 162.62 | 271.1 | block x30 | block or ask |
| Claude hook: `ls` with JEV_GUARD_LOCAL=off, no server (fail-open floor) · process wall | 30 | 91.42 | 113.9 | 64.63 | 138.67 | allow x30 | allow |
| omp hook (stubbed omp import): `ls` · import (in-process) | 30 | 23.24 | 31.02 | 16.77 | 33.97 | allow x30 | allow |
| omp hook (stubbed omp import): `ls` · first tool_call | 30 | 86.53 | 101.12 | 62.32 | 113.93 | allow x30 | allow |
| omp hook (stubbed omp import): `ls` · steady median of 50 (per process) | 30 | 1.1 | 1.36 | 0.7 | 1.7 | allow x30 | allow |
| omp hook (stubbed omp import): `cat .env` (rules must load, so block) · import (in-process) | 30 | 20.84 | 26.44 | 16.27 | 31.2 | block x30 | block |
| omp hook (stubbed omp import): `cat .env` (rules must load, so block) · first tool_call | 30 | 72.14 | 83.85 | 55.21 | 89 | block x30 | block |
| omp hook (stubbed omp import): `cat .env` (rules must load, so block) · steady median of 50 (per process) | 30 | 0.93 | 1.09 | 0.66 | 1.25 | block x30 | block |
| guardCommand in-process: `ls` | 50 | 0.24 | 0.34 | 0.14 | 0.66 | allow x50 | allow |
| guardCommand in-process: `cat .env` | 50 | 0.16 | 0.22 | 0.09 | 0.45 | block x50 | block or ask |

A local decision is not a network round trip. The Claude and warm rows run with no server configured, so they make no network call; only the Worker rows, enabled by --url, do.

This is the middle of three full runs at `506f892`. All three were NOISY (1-minute load 10 to 13 on 12 cores, above the cores/2 threshold of 6), so read these as upper bounds. The other two, not committed, were: Claude `ls` median 218.01 ms and omp `ls` first call 85.49 ms, steady 1.07 ms (run 1); Claude `ls` median 203.20 ms and omp `ls` first call 79.59 ms, steady 0.96 ms (run 3). Across runs the Claude `ls` median moved about 7 percent within one commit, and earlier runs on this host gave 114 to 179 ms.
