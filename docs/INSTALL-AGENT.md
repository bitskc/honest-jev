# Install honest-jev (agent runbook)

You are a coding agent. A user gave you this repo URL. Follow this file top to bottom to connect them to a **Jev MCP server** and install the **skills + full hook set** (Honest Jev levels, guard, classify redact, Stop) for the host you run in. Do not skip the verification section.

## Rules (read first)
1. **Never** commit, print, log or echo `JEV_MCP_TOKEN`, `MCP_BEARER_TOKEN`, `AI_GATEWAY_API_KEY` or any API key. Don't put them in command arguments you will repeat, in chat, in git, or in config files. Config files hold only `${JEV_MCP_URL}` / `${JEV_MCP_TOKEN}` references. Real values live in `~/.config/jev/env` (mode 0600) or the host's secret store.
2. **Ask the user** for anything you don't have. Don't invent URLs or tokens. Ask once, for all missing values together.
3. Everything is idempotent and token-free by default. `install.sh --wire` backs up each config it edits to `<file>.jev-bak` (the first time); later runs add `<file>.jev-bak.<timestamp>` and never overwrite an earlier backup. Config writes are atomic (temp file + rename) and validated before replacing the original.
4. Don't edit the user's shell profile or other agents' config without saying so. Report each file you changed.
5. Don't merge or push anything to the user's repos as part of this install.

## Step 0: get the repo
```sh
git clone https://github.com/bitskc/honest-jev ~/.local/share/honest-jev 2>/dev/null || git -C ~/.local/share/honest-jev pull --ff-only
cd ~/.local/share/honest-jev
```
(No git: `curl -fsSL https://github.com/bitskc/honest-jev/archive/refs/heads/main.tar.gz | tar xz`.)
Needs: `bash`, `python3`, `curl`. Self-hosting (Option B) also needs Node >= 22 and `git`.

## Step 1: detect your host
Pick the first match; if several agents are installed, install for each the user wants (ask if unsure).

| You are | Tell-tale | `--wire` target |
|---|---|---|
| **omp** (oh-my-pi) | you are `omp`; `~/.omp/` exists | `--omp` |
| **Claude Code** | you are `claude`; `~/.claude/` exists | `--claude` |
| **Codex CLI** | `~/.codex/` exists | manual (Step 4c) |
| **Cursor** | running inside Cursor; `~/.cursor/` | manual (Step 4c) |
| other (Gemini CLI, Aider, Windsurf, ...) | none of the above | manual (Step 4c) |

## Step 2: get a Jev MCP server (choose A or B)
Ask the user: **"Do you already have a hosted Jev MCP server URL and bearer token, or should I deploy one to your Cloudflare account?"**

### Option A: connect to an existing server
Ask the user for:
- `JEV_MCP_URL` (looks like `https://<name>.<subdomain>.workers.dev/mcp`)
- `JEV_MCP_TOKEN` (the server's `MCP_BEARER_TOKEN`)

Best: have the user put them in the environment themselves. If they paste them to you, use them once to create the env file and then never repeat them:
```sh
# values come from the user; export them in this shell only, don't echo
export JEV_MCP_URL=...   # ask the user
export JEV_MCP_TOKEN=... # ask the user
./install.sh --save-env  # writes ~/.config/jev/env with mode 0600
unset JEV_MCP_TOKEN
```
Then load for this session: `set -a; . ~/.config/jev/env; set +a`. Tell the user the agent process needs those two variables at launch (e.g. `. ~/.config/jev/env` in `~/.bashrc`/`~/.zshrc`, or the service unit); offer to add that line, don't add it silently.

### Option B: self-host on Cloudflare Workers
Requirements, ask the user for whatever is missing:
- Cloudflare auth: `npx wrangler login` (interactive; the user does the browser step) **or** `CLOUDFLARE_API_TOKEN` (Workers Scripts: Edit) in the environment (+ `CLOUDFLARE_ACCOUNT_ID` if the token spans several accounts).
- A Vercel AI Gateway key in `AI_GATEWAY_API_KEY` (routes to model `typesafe-ai/jev`). Direct TypeSafe alternative: `TYPESAFE_API_KEY`. Without any Jev key the server still runs, but only the deterministic guard rules work.

```sh
cd server
npm ci
npm run vendor      # clones jkudish/jev-mcp at a pinned commit and builds ./vendor (not committed)
npm test            # 21 offline tests; must pass
npx wrangler deploy # prints https://<name>.<subdomain>.workers.dev
```
If the Worker name `jev-mcp` is taken in the account, change `name` in `server/wrangler.jsonc` locally (don't commit it).

Set the secrets. Values are piped via stdin, so they never appear in argv or history:
```sh
umask 077
TOKEN=$(openssl rand -hex 32)                       # generated, not user-supplied
printf %s "$TOKEN" | npx wrangler secret put MCP_BEARER_TOKEN
printf %s "$AI_GATEWAY_API_KEY" | npx wrangler secret put AI_GATEWAY_API_KEY   # or TYPESAFE_API_KEY
export JEV_MCP_URL="https://<url printed by deploy>/mcp"
JEV_MCP_TOKEN="$TOKEN" ../install.sh --save-env     # stores URL + token in ~/.config/jev/env (0600)
unset TOKEN
```
Report back to the user: the **URL** (fine to show) and that the token was saved to `~/.config/jev/env`. Do **not** print the token. If they need it for another machine, tell them to read that file themselves. The Worker is public on the internet and protected only by the token; mention that it can be rotated with `npx wrangler secret put MCP_BEARER_TOKEN`.

## Step 3: install skills, hooks, `jev-call`
From the repo root:
```sh
./install.sh --omp --wire        # omp
./install.sh --claude --wire     # Claude Code
./install.sh --both --wire       # both
./install.sh --claude --wire --project /path/to/repo   # project scope instead of user scope
./install.sh --omp --wire --no-hook                    # skip all hooks (MCP only)
```
Without `--wire` it only copies files (skills, hooks, `~/.local/bin/jev-call`) and prints manual steps. Make sure `~/.local/bin` is on `PATH`.

What `--wire` writes (no secrets, only `${VAR}` references):

| Host | MCP entry | Skills | Hooks |
|---|---|---|---|
| omp | `~/.omp/agent/mcp.json` (project: `.omp/mcp.json`) | `~/.omp/agent/skills/` | `~/.omp/agent/hooks/pre/jev-guard.ts` + `jev-honest.ts` |
| Claude Code | `~/.claude.json` top-level `mcpServers` (project: `.mcp.json`) | `~/.claude/skills/` | full set from `config/claude-settings-hook.json` into `~/.claude/settings.json` (levels + guard + classify redact + Stop) |

If a config file isn't plain JSON, the installer refuses to touch it; merge `config/*.json` by hand.

## Step 4: host-specific notes

### 4a. omp (oh-my-pi)
- MCP shape (what `--wire` writes; omp expands `${VAR}` in `url` and `headers`; an unresolved placeholder shows up as a 401):
  ```json
  { "mcpServers": { "jev": { "type": "http", "url": "${JEV_MCP_URL}", "headers": { "Authorization": "Bearer ${JEV_MCP_TOKEN}" } } } }
  ```
- Reload: `/mcp reload`, `/reload-plugins`, then `/mcp list`, `/mcp test jev`.
- The omp hooks fail closed on a throwing handler, so `jev-guard.ts` / `jev-honest.ts` swallow their own errors. They were not run inside omp when written; if either misbehaves, delete that file from `~/.omp/agent/hooks/pre/`.
- **gstack coexists.** gstack runs fine in omp, and its `careful` / `freeze` regex checks stay the fast path. The Jev hooks only add a second opinion; don't remove or reorder gstack's hooks.

### 4b. Claude Code
- Equivalent CLI (stores the *expanded* token in `~/.claude.json`, so prefer `--wire`, which stores references): `claude mcp add --transport http jev "$JEV_MCP_URL" --header "Authorization: Bearer $JEV_MCP_TOKEN"`.
- Tools show up as `mcp__jev__<tool>`. Restart Claude Code after wiring; verify with `/mcp`.
- Hooks from `--wire`: SessionStart / SubagentStart / UserPromptSubmit (Honest Jev levels), `PreToolUse` on `Bash|Read|NotebookRead|Grep` (`jev-guard-hook.sh`: the deterministic rules run **locally first** through `hooks/jev-guard-local.mjs` (one `node` process, rules from `~/.local/share/honest-jev/jev-policy/server/src/kit`, no npm install needed), so a command they settle never touches the network; only a command they cannot settle goes to the Worker, and only if `JEV_MCP_URL`/`JEV_MCP_TOKEN` are set; fails open; `JEV_GUARD_MODE=shadow` logs only; `JEV_GUARD_LOCAL=off` restores send-everything-to-the-server), `PreToolUse` on `jev_classify` (`jev-classify-redact.js`), and Stop (`jev-stop-verify.js`, off until `JEV_STOP_GATE`/`stopGate` is set).

### 4c. Codex, Cursor and everything else (manual, generic)
1. **Skills**: `./install.sh` already copied them to `~/.omp/agent/skills` / `~/.claude/skills`. Copy `skills/*/` (each a `SKILL.md`) to the host's skills directory if it has one (Codex: `~/.codex/skills/`; check the host's docs), or paste the `description` + body into its rules file (`.cursor/rules/`, `AGENTS.md`, ...).
2. **MCP**: add a streamable-HTTP server named `jev` with URL `$JEV_MCP_URL` and header `Authorization: Bearer $JEV_MCP_TOKEN`, using the host's env-var reference syntax where it has one:
   - Codex `~/.codex/config.toml`: `[mcp_servers.jev]` with `url = "<JEV_MCP_URL>"` and `bearer_token_env_var = "JEV_MCP_TOKEN"`.
   - Cursor `~/.cursor/mcp.json`: `{"mcpServers":{"jev":{"url":"${env:JEV_MCP_URL}","headers":{"Authorization":"Bearer ${env:JEV_MCP_TOKEN}"}}}}`.
   - Anything else: `config/claude-mcp.json` is the generic shape.
   These host formats change; confirm against the host's current docs before writing.
3. **No MCP client at all**: use the shell helper `jev-call <tool> '<json>'` (installed to `~/.local/bin`). The skills work with it unchanged.
4. Skip the hook unless the host has a pre-tool-call hook you can map `hooks/jev_guard_hook.py` onto (stdin JSON in, JSON decision out).

## Step 5: verify (required)
Load the env first (`set -a; . ~/.config/jev/env; set +a`), then:
```sh
./install.sh --doctor
```
Expected: every line `ok`, ending with `tools/list = 16 tools`. It checks env vars, `/health`, that an unauthenticated call is rejected with 401, and the tool count; it never prints the token. A value found only in `~/.config/jev/env` is shown as `ok   JEV_MCP_URL set (from <path> only)`, followed by a `note` that the hooks read these two variables from the agent's environment, not from the file: start the agent from a shell that loaded it, or the guard will not reach the server.

Then in the host (after restart/reload):
1. List MCP tools (omp: `/mcp test jev`; Claude Code: `/mcp`). Expect **16**: 12 `jev_*` + `kit_guard_command`, `kit_size_dispatch`, `kit_verify_done`, `kit_decide`.
2. Call a cheap deterministic tool, which needs no model call:
   ```sh
   jev-call kit_guard_command '{"command":"ls","cwd":"/tmp"}'        # expect decision "allow"
   jev-call kit_guard_command '{"command":"cat .env","cwd":"/tmp"}'  # expect decision "block"
   ```
3. Confirm the skills are visible (`jev-classify`, `jev-command-guard`, `jev-dispatch-sizing`, `jev-verify-before-done`, `fast-file-search`).
4. Optional: `JEV_MCP_URL=... JEV_MCP_TOKEN=... ./tests/test-hook.sh` for the end-to-end hook test.

Finish with a short report to the user: host(s) detected, option used (A/B), files created or modified (with the `.jev-bak` backups), server URL (no token), doctor result.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| 401 on every call | Token missing or wrong. Placeholders unexpanded means the agent process doesn't have `JEV_MCP_TOKEN` in its environment: export it **before launching** the agent. Rotate with `wrangler secret put MCP_BEARER_TOKEN`. |
| `tools/list` returns not 15 | Old deploy. Re-run `npm run vendor && npx wrangler deploy` in `server/`. |
| `/health` fails | Wrong URL (must end in `/mcp` for `JEV_MCP_URL`; `/health` is derived from it) or the Worker isn't deployed. |
| 403 from Cloudflare with a custom script | Python's default urllib User-Agent is blocked; set another User-Agent. |
| `npm run vendor` fails | Needs `git`, network, Node >= 22. `JEV_MCP_SRC=/path/to/jev-mcp npm run vendor` uses a local checkout. |
| Jev tools fail, guard still works | No `AI_GATEWAY_API_KEY`/`TYPESAFE_API_KEY` on the Worker (the guard's deterministic rules need none; the hooks run them locally anyway). Set one with `wrangler secret put`. |
| Hook blocks or slows every command | `JEV_GUARD_MODE=shadow` to log only; or remove the hook entry. The server path fails open on timeout (2 s). `JEV_GUARD_LOCAL=off` makes the hook send every call to the server instead of settling rule-decided commands locally. |
| "no server is configured" (the guard says its local rules are unverified) | The hook only reads `JEV_MCP_URL` / `JEV_MCP_TOKEN` from the agent's own environment (not from `~/.config/jev/env`): export both **before launching** the agent. Commands the rules block or ask on are still judged locally, and so are the ones they allow, but nothing checks the local rules against a server's, and only the unclear ones (uploads, publishes, DB writes, ...) go unjudged until a server is reachable. `./install.sh --doctor` shows whether the local rules load, whether the HOOKS see a server (a value that exists only in the env file, or a URL that is not `https://`, is no server to them), and whether each value came from the environment or only from the env file. |
| "the rules on this machine differ from the server's" / "could not confirm that the rules on this machine match the server's" | The local rules are not byte-identical to the Worker's (or the Worker could not say). The guard did the safe thing: a command the local rules would allow was sent to the server to decide, and a local block or ask was kept. `./install.sh --doctor` prints both rules fingerprints (`FAIL guard rules differ from the server's (here ..., server ...)`). If the server is newer: `jev-update`, then restart the agent (omp keeps the rules it first loaded until it restarts). If this machine is newer: deploy the Worker (`cd server && npx wrangler deploy --keep-vars`; wrangler's build step regenerates the rules fingerprint, so a plain deploy of an edited working tree cannot report a stale one). "Could not confirm" with a note that the server did not report a fingerprint means an older Worker: deploy it first. |
| "the server did not answer, so for the next minute commands the local rules would allow stand locally" | The Worker timed out, refused or reset the connection (or DNS/TLS failed) while the guard was verifying a local allow. For 60 s local allows stand with no server call (log rows: `fail_open`, `client_timeout` / `client_network`); local blocks and asks and unclear commands are unchanged. Check the URL and that the Worker is up (`curl -s <worker>/health`); a wrong or revoked token is a 401 and never opens this window (it shows as a prompt). Any successful call ends the window early. |
| "the local rules could not run and no server is configured" | Nothing checked the commands: both the local rules and the server are off. Run `./install.sh --doctor`: `FAIL guard rules do not load locally` means no `node`/`bun` on the agent's PATH, or the rules were not installed (re-run `./install.sh`). Decision-log rows for this state have `fail_reason: local_rules_unavailable`. Fix the rules, or configure a server (export `JEV_MCP_URL` / `JEV_MCP_TOKEN` before launching the agent); `JEV_GUARD_LOCAL=off` is the choice to use only the server and says nothing. |
| Skills not showing | Restart the agent or `/reload-plugins` (omp); check the skills dir for your host in Step 3. |
| `refusing to edit ...: not plain JSON` | The file has comments or trailing commas. Merge `config/*.json` by hand. |
| Undo | Restore the `*.jev-bak` files, remove `~/.omp/agent/skills/jev-*`, `~/.claude/skills/jev-*`, `fast-file-search`, `~/.local/share/honest-jev`, `~/.local/bin/jev-call`. |

More detail: [README.md](../README.md). Licences and attribution: [NOTICE.md](../NOTICE.md).
