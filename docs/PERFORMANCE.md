# Guard latency: method and how to read it

`scripts/bench-guard.mjs` measures where the guard's time goes on one machine. It answers "what does a guard decision cost here", not "how fast is the network". One committed run from this host is in [`evals/LATENCY.md`](../evals/LATENCY.md), with its raw numbers in `evals/latency.json`.

A local decision is not a network round trip. The local rules run in the hook's own process (Claude) or in-process (omp). They never open a socket. Only the optional Worker rows make network calls, and those are off unless you pass `--url`.

## What it measures

| Row | What it is |
|---|---|
| Claude hook, `ls` / `cat .env` | One `python3 hooks/jev_guard_hook.py` process per call, the local rules on. Includes Python and Node startup. |
| Claude hook, `JEV_GUARD_LOCAL=off`, no server | The fail-open floor: the same process with no local rules and no server. It is the cost of starting the hook at all. |
| omp hook: import, first call, steady | One `bun` process per sample, with the omp import stubbed as in `tests/local-first-omp.test.ts`. Import and first call are per process. Steady is the median of 50 calls in that process. |
| guardCommand in-process, `ls` / `cat .env` | The local rules called directly, no hook or process overhead. |
| Worker (only with `--url`) | `kit_guard_command ls` over `POST` and `GET /health`. Real network round trips. |

Each Claude row checks the decision the hook prints against the expected one (`ls` allow; `cat .env` block or ask). A row whose decision falls outside its expected set is flagged as UNEXPECTED, and the script exits 1. Timing numbers are reported only with the decisions they came from.

## Method

- Cold rows: N=30 after 5 warmups. Warm and Worker rows: N=50 after 5 warmups.
- Rows are interleaved. Each round starts from a different scenario, so slow drift affects all rows alike.
- Each row reports n, median, p90 (nearest rank), min, and max, in milliseconds.
- Every child process gets a clean environment: PATH, a temp HOME, and temp XDG directories. Nothing is inherited from the shell, so no real `~/.config/jev/env`, `JEV_MCP_TOKEN`, or `JEV_MCP_URL` can reach a hook run.
- The host fingerprint is printed with each run: kernel, CPU and core count, load average before and after, Node, Python, bun and omp versions, date, and the commit. A run is marked NOISY when the 1-minute load average is above cores/2 at either end. Treat a noisy run as an upper bound.

## How to run

```sh
node scripts/bench-guard.mjs                       # local rows only, full N
node scripts/bench-guard.mjs --md out.md --json out.json
node scripts/bench-guard.mjs --quick               # N=1 smoke; the numbers mean nothing
```

For the Worker rows, pass the URL and put the token in the environment. The token is never printed or written to a file:

```sh
JEV_MCP_TOKEN=... node scripts/bench-guard.mjs --url https://<worker>/mcp
```

`--url` must be `https://`. Without `JEV_MCP_TOKEN` the script refuses to run in Worker mode.

The omp rows need `bun` on PATH. Without it they are skipped, and the fingerprint shows `bun not found`.

## Reading the numbers

- Compare rows with the same unit of work. `ls` allow and `cat .env` block are both full hook processes, so their difference is the local decision cost. The off row is the floor under both.
- The omp steady row is per call inside a warm process. Import and first call are the cost a new omp session pays once.
- The warm rows isolate the rules from process startup.
- Check the fingerprint before comparing two runs. Differences in CPU, Node version, or load change the numbers without any change in the guard.
- A p90 far above the median means the host was busy during that run. Re-run before concluding anything.

## What CI does

CI does not time anything. The `hooks` job runs `node --check scripts/bench-guard.mjs` and an `--quick` smoke. The smoke fails only on a crash or an unexpected decision, never on a number. The timing numbers in `evals/LATENCY.md` come from a local run, not from CI.

The local rules path is also checked statically by `hooks/local-rules-no-deps.test.mjs`. It fails if a rule file imports a package or reaches outside its directory. That keeps a local decision from depending on `node_modules` being installed on the machine running the hook.
