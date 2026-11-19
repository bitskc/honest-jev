# Connecting clients to the Jev MCP server

The Worker speaks MCP over Streamable HTTP at `https://<your-worker>.workers.dev/mcp` and authenticates with a static bearer token (`MCP_BEARER_TOKEN`). It exposes 16 tools. Every recipe below uses the same two values:

- `JEV_MCP_URL`: the `/mcp` URL of your deployed Worker
- `JEV_MCP_TOKEN`: the `MCP_BEARER_TOKEN` you set on the Worker

Keep the token in a `0600` env file or your client's secret store, never in git (see the README "Configure the client" section).

## Status

"Verified" means the repository's conformance test (`server/test/conformance.test.mjs`) exercises the server behavior the client depends on. It does not start the client itself. "Documented" means the recipe follows the client's published config format, and we have not run that client against a deployed Worker.

| Client | Auth the client accepts | Status |
| --- | --- | --- |
| Claude Code | Static bearer header | Verified at the server level. Recipe in the README. |
| omp (oh-my-pi) | Static bearer header | Verified at the server level. Recipe in the README. |
| Cursor | Static bearer header (`${env:NAME}` in `headers`) | Documented. Not run against a deployed Worker. |
| Codex CLI | Bearer token from an env var (`bearer_token_env_var`) | Documented. Not run against a deployed Worker. |
| Claude Desktop | Only stdio servers, so it needs the `mcp-remote` bridge | Documented. Not run against a deployed Worker. |
| ChatGPT connectors | OAuth 2.1 or no auth; no static bearer | **Not supported.** Needs the OAuth layer in [#77](https://github.com/bitskc/honest-jev/issues/77). Do not expect it to work. |

The server-level checks the conformance test covers:

- POST `/mcp` without a token returns 401 with `WWW-Authenticate: Bearer`.
- POST `/mcp` with a wrong token returns 401.
- GET `/mcp` with a valid token returns 405. The server does not open an SSE stream.
- An unknown path returns 404. `/health` returns `ok` to anyone; the rules fingerprint header appears only for the bearer holder.
- A valid MCP client lists exactly the 16 tools, and `kit_guard_command` returns a decision.

## Claude Code

Recommended: `.mcp.json` in the project, using `config/claude-mcp.json`:

```json
{ "mcpServers": { "jev": { "type": "http", "url": "${JEV_MCP_URL}", "headers": { "Authorization": "Bearer ${JEV_MCP_TOKEN}" } } } }
```

Or from the shell (this stores the expanded token in `~/.claude.json`, so prefer the file):

```sh
claude mcp add --transport http jev "$JEV_MCP_URL" --header "Authorization: Bearer $JEV_MCP_TOKEN"
```

Tools appear as `mcp__jev__<tool>`.

## omp (oh-my-pi)

`~/.omp/agent/mcp.json` (user) or `.omp/mcp.json` (project). `config/omp-mcp.json` is the file:

```json
{ "mcpServers": { "jev": { "type": "http", "url": "${JEV_MCP_URL}", "headers": { "Authorization": "Bearer ${JEV_MCP_TOKEN}" } } } }
```

Then `/mcp reload`, then `/mcp test jev` (expect 16 tools).

## Cursor

`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project). Cursor resolves `${env:NAME}` in `url` and `headers`, so the variable must be present in the environment Cursor starts with:

```json
{
  "mcpServers": {
    "jev": {
      "url": "${env:JEV_MCP_URL}",
      "headers": { "Authorization": "Bearer ${env:JEV_MCP_TOKEN}" }
    }
  }
}
```

Restart Cursor after changing the env file. Check that the server shows 16 tools in Customize.

## Codex CLI

`~/.codex/config.toml`. Codex reads the bearer token from the environment variable named by `bearer_token_env_var`, so the token never sits in the file:

```toml
[mcp_servers.jev]
url = "https://<your-worker>.workers.dev/mcp"
bearer_token_env_var = "JEV_MCP_TOKEN"
```

Export `JEV_MCP_TOKEN` in the shell that starts Codex.

## Claude Desktop

Claude Desktop only launches stdio servers. Bridge the remote server with `mcp-remote` in `claude_desktop_config.json`. Keep the token out of that file: write `Authorization: Bearer <your-token>` to a `0600` file (one `Name: value` per line) and pass its absolute path with `--header-file`. `mcp-remote` reads the file and fails if the path is wrong, so it never sends unauthenticated requests:

```json
{
  "mcpServers": {
    "jev": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://<your-worker>.workers.dev/mcp",
        "--header-file",
        "/absolute/path/to/jev-auth-header"
      ]
    }
  }
}
```

If you cannot use a file, the `env` form works, but it puts the token in `claude_desktop_config.json`, which then holds a secret: keep that file `0600` and out of git. Use no space after the colon in the `--header` argument, because Cursor and Claude Desktop on Windows do not escape spaces in `args` (from the `mcp-remote` README):

```json
{
  "mcpServers": {
    "jev": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://<your-worker>.workers.dev/mcp",
        "--header",
        "Authorization:${JEV_AUTH_HEADER}"
      ],
      "env": {
        "JEV_AUTH_HEADER": "Bearer <your-token>"
      }
    }
  }
}
```

The Settings → Connectors remote path needs OAuth ([#77](https://github.com/bitskc/honest-jev/issues/77)) or Anthropic's beta request headers. This recipe does not cover it.

## ChatGPT connectors

**Not supported yet.** OpenAI's connector docs require OAuth 2.1 with the MCP authorization spec, and this server only accepts a static bearer token. Do not follow any recipe that claims otherwise. The OAuth layer is tracked in [#77](https://github.com/bitskc/honest-jev/issues/77). That issue covers the design and threat model. It is not implemented here.

## Not covered

- Other clients (n8n, the OpenAI Responses API `mcp` tool, Windsurf). We have not confirmed their header syntax, so no recipe is given. Add one only after checking the client's own docs and running it against a deployed Worker.
- Client UI behavior. The conformance test checks the server, not the client.
