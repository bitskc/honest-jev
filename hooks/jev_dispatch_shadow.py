#!/usr/bin/env python3
"""OPT-IN, SHADOW-ONLY PreToolUse hook for sub-agent dispatch (openspec add-decision-ledger, task group 5).

Calls the server's `kit_size_dispatch` for every sub-agent spawn and records the result in the local ledger so the
report can show what dispatch sizing WOULD have said (`enforced: false`, `would_have: warn|block`). It NEVER denies,
asks, or alters the dispatch: no stdout, exit 0 on every path. Off unless config/claude-dispatch-shadow-hook.json is
merged into your settings. Same env as jev_guard_hook.py (JEV_MCP_URL, JEV_MCP_TOKEN, JEV_GUARD_TIMEOUT, JEV_LEDGER).

The sub-agent tool is named `Task` in Claude Code today and `Agent` in newer releases (unverified here: the matcher
in the config covers both). Fields read from tool_input: description, prompt, subagent_type (else model).
"""
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jev_guard_hook as g  # noqa: E402  (shares the HTTP call, caps and ledger plumbing; its main() is not run)

TOOL = "kit_size_dispatch"
SUBAGENT_TOOLS = ("Task", "Agent")


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    if event.get("tool_name") not in SUBAGENT_TOOLS:
        sys.exit(0)
    ti = event.get("tool_input") or {}
    model = ti.get("subagent_type") or ti.get("model")
    description = ti.get("description")
    if not model or not description:
        sys.exit(0)
    args = {"description": str(description)[:2000], "model": str(model)[:200]}
    if ti.get("prompt"):
        args["prompt"] = str(ti["prompt"])[:12000]
    g._CTX.update(on=True, t0=time.monotonic(), tool=TOOL, enforced=False)
    try:
        signal.signal(signal.SIGALRM, g._alarm)
        signal.setitimer(signal.ITIMER_REAL, g.TIMEOUT + 0.5)
        reply = g.call_guard(args, TOOL)
    except (g.ServerRejected, g.RedirectRefused):
        g.led(decision="ask", decided_by="fail_closed", fail_reason="client_rejected", enforced=False)
        sys.exit(0)
    except Exception as e:
        g.fail_open("%s: %s" % (type(e).__name__, str(e)[:120]), g._ledger.fail_reason_for(e) if g._ledger else "client_network")
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except Exception:
            pass
    action = reply.get("action") if isinstance(reply, dict) else None
    g.led(reply, decision=action, enforced=False, would_have=action if action in ("warn", "block") else None)
    sys.exit(0)


if __name__ == "__main__":
    main()
