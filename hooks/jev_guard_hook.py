#!/usr/bin/env python3
"""PreToolUse hook for Claude Code (and Claude-Code-compatible agents).

Reads the hook JSON on stdin. The deterministic rules run LOCALLY first (hooks/jev-guard-local.mjs, one node process). A command the
rules block or ask on is answered from the local result and never touches the network (being stricter than the server is safe).
A command the rules ALLOW is trusted only when the rules on this machine are the rules the server runs: the rules fingerprint
(hooks/jev-rules-fingerprint.mjs) is compared with the one the server reports on GET /health, cached for a few minutes in the state
dir. When they differ, or the server's cannot be read (an older Worker, no network), the local allow is not final: the command goes to
the server like any unclear one, and a notice says so once per session. A command the rules cannot settle without a model ("unclear")
goes on to the jev-mcp server's `kit_guard_command` tool (MCP tools/call over streamable HTTP), and only if a server is configured.
With no server there is nothing to compare against: the local rules decide alone and are unverified. Prints Claude Code's PreToolUse
decision JSON:

    allow -> no output, exit 0 (the normal permission flow continues)
    ask   -> {"hookSpecificOutput": {"permissionDecision": "ask",  ...}}
    block -> {"hookSpecificOutput": {"permissionDecision": "deny", ...}}

Fails OPEN: any error, timeout (default 2 s hard cap), missing token, non-200, or malformed reply
exits 0 with no output. Set JEV_GUARD_DEBUG=1 to see why on stderr. If the local rules cannot run (no node, the rules
not found, a crash, the time budget), the call falls through to the server path exactly as before.
The first unclear command allowed because no server is configured prints a one-line `systemMessage` once per session. The same hook
file can be edited by anything running as the same user, so none of this is a sandbox (README: "What it protects against").

Env:
  JEV_MCP_TOKEN        required. Bearer token; never hardcoded, never logged.
  JEV_MCP_URL          required. Your deployed endpoint, e.g. https://<your-worker>.workers.dev/mcp
  JEV_GUARD_TIMEOUT    seconds, default 2
  JEV_GUARD_MODE       enforce (default) | shadow (never blocks; logs what it would do to stderr)
  JEV_GUARD_ASK_AT     risk threshold sent as ask_at (server default 0.65)
  JEV_GUARD_HOME       the user's home dir to send as `home` (default $HOME)
  JEV_GUARD_DEBUG      1 = explain on stderr
  JEV_GUARD_LOCAL      off = skip the local rules and send every call to the server (the pre-local-first behaviour). Default: on.
  JEV_GUARD_LOCAL_TIMEOUT  seconds for the local rules process, default 1.5 (clamped to 0.1..1.5)
  JEV_GUARD_RULES      absolute path of a guard.mjs to use as the local rules (tests); default: the rules of this hook's own release
  JEV_POLICY_USER      user policy layer file (default $XDG_CONFIG_HOME/jev/policy.json). Only when it contains a `trigger` does the
                       hook run the policy path (hooks/../jev-policy/scripts/jev-policy-hook.mjs, or $JEV_POLICY_HOOK).
  JEV_POLICY_TIMEOUT   seconds for the whole policy path, default 3 (clamped to 1..4); it runs beside the guard call
  JEV_LEDGER           path of the local decision ledger (default $XDG_STATE_HOME/jev/ledger.jsonl); "off" disables.
                       One content-free JSONL record per decision; a ledger failure never changes the decision.
"""
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

URL = os.environ.get("JEV_MCP_URL", "").strip()
TIMEOUT = float(os.environ.get("JEV_GUARD_TIMEOUT", "2"))
MODE = os.environ.get("JEV_GUARD_MODE", "enforce")
DEBUG = os.environ.get("JEV_GUARD_DEBUG") == "1"

# Plain decimal literal only (no hex, underscores, or words), the same accepted set as parseAskAt in hooks/omp/jev-guard.ts.
ASK_AT_RE = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")

def parse_ask_at(raw):
    """JEV_GUARD_ASK_AT as a float in [0, 1], or None (server default). Blank, non-decimal text, NaN, Infinity and
    anything outside [0, 1] all fall back to the default. Same rule as parseAskAt in hooks/omp/jev-guard.ts."""
    if raw is None:
        return None
    s = raw.strip()
    if not ASK_AT_RE.fullmatch(s):
        return None
    n = float(s)
    return n if math.isfinite(n) and 0.0 <= n <= 1.0 else None

# Local decision ledger (hooks/jev_ledger.py). Optional by construction: if the module is missing or broken, the hook
# behaves exactly as before.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import jev_ledger as _ledger
except Exception:
    _ledger = None
_CTX = {"on": False, "t0": 0.0, "tool": "kit_guard_command", "host": "claude-code"}


LEDGER_BUDGET = 0.5  # seconds: a stalled ledger write may never hold the decision for longer than this


class _LedgerStalled(BaseException):  # BaseException, not Exception: jev_ledger.record's own `except Exception` must not swallow it
    pass


def _ledger_alarm(_signum, _frame):
    raise _LedgerStalled()


def led(reply=None, **kw):
    """Append one ledger record. Never raises, never changes the decision. Runs under its own LEDGER_BUDGET alarm (it
    replaces the guard's hard-timeout alarm) so a stalled write cannot hold the process. Callers emit the decision
    before calling this (see emit), so a stall here cannot cost the decision."""
    if _ledger is None or not _CTX["on"]:
        return
    try:
        kw.setdefault("latency_ms", (time.monotonic() - _CTX["t0"]) * 1000)
        signal.signal(signal.SIGALRM, _ledger_alarm)
        signal.setitimer(signal.ITIMER_REAL, LEDGER_BUDGET)
        _ledger.record(kw.pop("tool", _CTX["tool"]), _CTX["host"], reply, **kw)
    except (_LedgerStalled, Exception):
        pass
    finally:
        # disarm and ignore: the process exits right after this, and a late SIGALRM must not escape anywhere
        try:
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            signal.setitimer(signal.ITIMER_REAL, 0)
        except Exception:
            pass


def note(msg):
    if DEBUG:
        sys.stderr.write("jev-guard: %s\n" % msg)


def fail_open(why, code=None):
    note("fail-open: %s" % why)
    if code:
        led(decision="allow", decided_by="fail_open", fail_reason=code, enforced=_CTX.get("enforced", True))
    sys.exit(0)


def _alarm(_signum, _frame):
    raise TimeoutError("hard timeout")


class RedirectRefused(Exception):
    """The endpoint tried to redirect the call: the server answered (just not sanely), so this is not an
    outage to fail open on — same class as ServerRejected, never a silent allow."""


_http_state = None


def _http():
    """(urllib.request, urllib.error, opener), imported on first use: a call the local rules settle never reaches the network,
    so it must not pay for urllib/http.client/ssl either."""
    global _http_state
    if _http_state is None:
        import urllib.error
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            # A redirect would re-send the bearer to whatever host/scheme the 3xx names. Never follow one.
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise RedirectRefused("redirect refused (%s -> %s)" % (code, newurl[:80]))

        _http_state = (urllib.request, urllib.error, urllib.request.build_opener(_NoRedirect))
    return _http_state

# Server-side input caps (server/src/kit/tools.mjs). Anything longer would be rejected by the schema, and a
# schema rejection must not turn into a silent allow, so oversized input is answered with "ask" before any call.
CAPS = {"command": 20000, "file_path": 2000, "cwd": 1000, "home": 500, "description": 1000}


class ServerRejected(Exception):
    """The server answered but refused the call: the server is up, so this is not an outage to fail open on."""


class GuardFailOpen(Exception):
    """The call cannot be made at all (no URL, no token): an outage, so the caller applies its own failure rule."""

    def __init__(self, why, code):
        Exception.__init__(self, why)
        self.why, self.code = why, code


def call_guard(args, tool="kit_guard_command", timeout=None):
    token = os.environ.get("JEV_MCP_TOKEN", "").strip()
    if not URL:
        raise GuardFailOpen("JEV_MCP_URL is not set", "client_config")
    if not URL.startswith("https://"):
        raise GuardFailOpen("JEV_MCP_URL must be https:// (got %r)" % URL[:40], "client_config")
    if not token:
        raise GuardFailOpen("JEV_MCP_TOKEN is not set", "client_config")
    request, error, opener = _http()
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }).encode()
    req = request.Request(URL, data=body, method="POST", headers={
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "authorization": "Bearer " + token,
        "user-agent": "jev-guard-hook/1.0",  # Cloudflare 403s the default Python-urllib UA
    })
    try:
        with opener.open(req, timeout=timeout or TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except error.HTTPError as e:
        # 4xx (bad/revoked token, Cloudflare block, bad request): the server answered and refused the call,
        # same class as a JSON-RPC error -- ask, never a silent allow. 5xx/network stays an outage: fail open.
        if 400 <= e.code < 500:
            raise ServerRejected("HTTP %d from the guard endpoint" % e.code)
        raise
    # The server answers JSON or a single SSE `data:` frame.
    payload = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            line = line[5:].strip()
        if line.startswith("{"):
            try:
                payload = json.loads(line)
                break
            except ValueError:
                continue
    if not payload:
        raise ValueError("no JSON-RPC payload")
    if "error" in payload:  # JSON-RPC error: the server is up and refused this call (bad input, unknown tool)
        raise ServerRejected(str(payload["error"].get("message", payload["error"]))[:200])
    result = payload.get("result") or {}
    if result.get("isError"):
        raise ServerRejected(str((result.get("content") or [{}])[0].get("text", "tool error"))[:200])
    return json.loads(result["content"][0]["text"])


RANK = {"allow": 0, "ask": 1, "deny": 2}
POLICY_TRIGGER = '"trigger"'
POLICY_LAYER_MAX = 16384


class Outcome(object):
    """One party's result: its effect (allow|ask|deny), the reason shown if it asks or denies, and the ledger row to write.
    Writing the row is deferred until the decision has been printed (a stalled ledger can never cost the decision)."""

    def __init__(self, effect="allow", reason="", reply=None, row=None, stderr=None, tool=None, notice=None):
        self.effect, self.reason, self.reply, self.row, self.stderr, self.tool, self.notice = effect, reason, reply, row, stderr, tool, notice

    def write(self):
        if self.row is None:
            return
        kw = dict(self.row)
        if self.tool:
            kw["tool"] = self.tool
        led(self.reply, **kw)


LOCAL_SETTLED = ("prefilter", "fail_closed")
LOCAL_NOTICE = ("Honest Jev guard: no server is configured (JEV_MCP_URL / JEV_MCP_TOKEN), so the local rules run unverified and are not checked against the server's. "
                "This command was unclear to the rules and was allowed without a model check. Run install.sh --doctor for details.")


def local_enabled():
    return os.environ.get("JEV_GUARD_LOCAL", "").strip().lower() != "off"


def local_timeout():
    """JEV_GUARD_LOCAL_TIMEOUT seconds, default 1.5, clamped to 0.1..1.5: with the server call's own 2.5 s alarm the guard path stays
    under the 5 s the shipped hook config allows."""
    try:
        v = float(os.environ.get("JEV_GUARD_LOCAL_TIMEOUT", "1.5"))
    except ValueError:
        return 1.5
    return min(1.5, max(0.1, v)) if v == v else 1.5


def run_local(args):
    """Run the deterministic rules in one node process (hooks/jev-guard-local.mjs; the args travel on its stdin only).
    Returns guardCommand's reply (a dict, with `unclear`), or None when the rules did not run: switched off, no JavaScript runtime,
    the runner or the rules not found, a crash, the time budget, output that is not a reply. None means: take the server path."""
    _CTX["local_why"] = None  # None = the rules ran, or were switched off (the user chose server-only)
    if not local_enabled():
        return None
    _CTX["local_why"] = "failed"  # until proven otherwise below: "timeout" for the time budget, None once a usable reply is in hand
    runtime = policy_runtime()
    runner = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jev-guard-local.mjs")
    if not runtime or not os.path.isfile(runner):
        note("local rules: no runtime or runner")
        return None
    try:
        r = subprocess.run([runtime, runner], input=json.dumps(args).encode(), capture_output=True, timeout=local_timeout())
    except subprocess.TimeoutExpired:
        _CTX["local_why"] = "timeout"
        note("local rules: out of time")
        return None
    except Exception as e:
        note("local rules: %s" % type(e).__name__)
        return None
    if r.returncode != 0:
        note("local rules: runner exited %d" % r.returncode)
        return None
    try:
        reply = json.loads(r.stdout.decode("utf-8", "replace"))
    except ValueError:
        note("local rules: unusable output")
        return None
    if not isinstance(reply, dict) or reply.get("decision") not in ("allow", "ask", "block") or reply.get("decided_by") not in ("prefilter", "fail_closed", "fail_open"):
        note("local rules: unusable reply")
        return None
    _CTX["local_why"] = None
    return reply


def local_unclear(local):
    """The rules would have asked a model (nothing local can settle this command)."""
    return local is not None and (local.get("unclear") is True or local.get("decided_by") == "fail_open")


def _session_key():
    return re.sub(r"[^A-Za-z0-9_-]", "", str(_CTX.get("session") or ""))[:64] or ("ppid%d" % os.getppid())


def first_unclear_in_session():
    """True once per session (marker in the ledger's private state dir, keyed by the hook's session_id)."""
    try:
        sid = _session_key()
        return bool(_ledger is not None and _ledger.mark_once("notice-" + sid))
    except Exception:
        return False


LOCAL_DOWN_NOTICE = ("Honest Jev guard: the local rules could not run and no server is configured (JEV_MCP_URL / JEV_MCP_TOKEN), "
                     "so commands are not being checked. Run install.sh --doctor for details.")

# The local rules' fingerprint against the server's (hooks/jev-rules-fingerprint.mjs; the server reports its own on GET /health, see
# server/src/health.mjs). Only a local ALLOW needs it: a local ask or block is honoured whatever the server's rules are.
FP_RE = re.compile(r"[0-9a-f]{64}")
FP_TTL = 300           # seconds a fingerprint read from the server is trusted (the hot path reads one tiny file and makes no network call)
FP_TTL_DOWN = 60       # seconds the fact "the server gave none" is remembered, so an offline or older server costs one fetch a minute, not one per command
FP_FETCH_BUDGET = 0.8  # seconds for the whole GET /health; with the local runner's 1.5 and the server call's 2.5 the path stays under the hook's 5
FP_HEADER = "x-jev-rules-fingerprint"
TRUST_NOTICES = {
    "mismatch": ("Honest Jev guard: the rules on this machine differ from the server's, so commands the local rules would allow are being sent to the "
                 "server to decide. Run jev-update (or deploy the Worker, if this machine is the newer one), then restart the agent. install.sh --doctor shows which."),
    "unverified": ("Honest Jev guard: could not confirm that the rules on this machine match the server's (the server did not answer, or is an older "
                   "Worker that does not report its rules, or the rule files here are incomplete or a symlink), so commands the local rules would allow are being sent to the server to decide. "
                   "Run install.sh --doctor for details."),
}


def server_configured():
    """A server the hook can actually call: an https URL and a token in the PROCESS environment (what call_guard needs)."""
    return URL.startswith("https://") and bool(os.environ.get("JEV_MCP_TOKEN", "").strip())


def _fp_cache_path():
    """(state dir, cache file) for the current server URL, or None when there is no ledger module to give the private state dir."""
    if _ledger is None:
        return None
    import hashlib
    d = _ledger.state_dir()
    return d, os.path.join(d, "rules-fp-%s.json" % hashlib.sha256(URL.encode()).hexdigest()[:16])


def _fp_cache_read():
    """A fresh cached answer as a 1-tuple (fingerprint or None), or None when there is none. Only a regular file we own is read."""
    try:
        where = _fp_cache_path()
        if where is None:
            return None
        import stat as _s
        fd = os.open(where[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not _s.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_size > 1024:
                return None
            data = json.loads(os.read(fd, 1024).decode("utf-8", "replace"))
        finally:
            os.close(fd)
        fp, t = data.get("fp"), data.get("t")
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not (fp is None or (isinstance(fp, str) and FP_RE.fullmatch(fp))):
            return None
        age = time.time() - t
        return (fp,) if 0 <= age <= (FP_TTL if fp else FP_TTL_DOWN) else None
    except Exception:
        return None


def _fp_cache_write(fp):
    """Remember the server's answer (atomic: a private temp file renamed into place, 0600, in the ledger's own state dir). Never raises."""
    try:
        where = _fp_cache_path()
        if where is None or not _ledger._owned_dir(where[0]):
            return
        tmp = "%s.%d.tmp" % (where[1], os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, json.dumps({"v": 1, "fp": fp, "t": time.time()}).encode())
        finally:
            os.close(fd)
        os.replace(tmp, where[1])
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def fetch_server_fp():
    """The fingerprint the server reports (GET <server>/health with the bearer token), or None: an older Worker that sends no header, a
    refused token, no network, a redirect, a slow answer. Never raises; bounded by FP_FETCH_BUDGET."""
    try:
        from urllib.parse import urlsplit
        request, _error, opener = _http()
        u = urlsplit(URL)
        path = u.path[:-4] if u.path.endswith("/mcp") else u.path
        req = request.Request("%s://%s%s/health" % (u.scheme, u.netloc, path.rstrip("/")), method="GET", headers={
            "authorization": "Bearer " + os.environ.get("JEV_MCP_TOKEN", "").strip(),
            "user-agent": "jev-guard-hook/1.0",  # Cloudflare 403s the default Python-urllib UA
        })
        signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, FP_FETCH_BUDGET)
        with opener.open(req, timeout=FP_FETCH_BUDGET - 0.1) as resp:
            got = (resp.headers.get(FP_HEADER) or "").strip().lower()
        return got if FP_RE.fullmatch(got) else None
    except Exception:
        return None
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except Exception:
            pass


def server_rules_fp():
    """The server's rules fingerprint: the cached one while it is fresh, else one GET /health (and the answer, even 'none', is cached)."""
    cached = _fp_cache_read()
    if cached is not None:
        return cached[0]
    fp = fetch_server_fp()
    _fp_cache_write(fp)
    return fp


def rules_trust(local):
    """Whether a local allow may stand: "match" (the rules here are byte-identical to the server's), "mismatch" (both known, different) or
    "unverified" (this machine's rules are not the whole release, or the server's fingerprint is unavailable). Anything but "match" means the
    server decides."""
    mine = local.get("rules_fp")
    if not (isinstance(mine, str) and FP_RE.fullmatch(mine)):
        return "unverified"
    theirs = server_rules_fp()
    if theirs is None:
        return "unverified"
    return "match" if theirs == mine else "mismatch"


def trust_notice(trust):
    """The one-time-per-session notice for a local allow that went to the server because its rules could not be matched to the server's."""
    try:
        if trust in TRUST_NOTICES and _ledger is not None and _ledger.mark_once("notice-rules-%s-%s" % (trust, _session_key())):
            return TRUST_NOTICES[trust]
    except Exception:
        pass
    return None


def local_down_notice(why):
    """Whether to say, now, that the local rules could not run (once per session, its own marker). A hard failure (no runtime, no runner
    or rules, a crash, output that is not a reply) is said at once. A time-budget miss alone is one slow command, and the next command is
    checked again, so it only counts: the notice goes out on the SECOND miss in a session (a host too slow for the budget misses every time)."""
    try:
        if why == "timeout" and _ledger is not None and _ledger.mark_once("notice-slow-" + _session_key()):
            return False
        return bool(_ledger is not None and _ledger.mark_once("notice-down-" + _session_key()))
    except Exception:
        return False


def guard_outcome(args):
    """The guard path: the local rules first, then (only for what they cannot settle) kit_guard_command; returned as an Outcome."""
    # Oversized input would be rejected by the server schema; a rejection is not a reason to run it unguarded.
    for key, cap in CAPS.items():
        if key in args and len(args[key]) > cap:
            if key in ("command", "file_path"):
                if MODE == "shadow":
                    return Outcome("allow", row=dict(decision="ask", decided_by="fail_closed", fail_reason="oversize", enforced=False, would_have="ask"),
                                   stderr="jev-guard (shadow): would ask: %s exceeds %d chars\n" % (key, cap))
                return Outcome("ask", "Jev guard: %s is %d chars, over the %d-char limit the guard can judge; confirm it by hand." % (key, len(args[key]), cap),
                               row=dict(decision="ask", decided_by="fail_closed", fail_reason="oversize"))
            args[key] = args[key][:cap]
    local = run_local(args)
    unclear = local_unclear(local)
    trust = None  # set only when a local ALLOW needs the server's rules fingerprint before it can stand
    if local is not None and not unclear and local.get("decided_by") in LOCAL_SETTLED:
        # A local ask or block stands whatever the server's rules are (stricter than the server is safe). A local allow stands when there is
        # no server to ask, or when the rules on this machine are the ones the server runs.
        if local.get("decision") == "allow" and server_configured():
            trust = rules_trust(local)
        if trust is None or trust == "match":
            note("settled by the local rules; no server call")
            return reply_outcome(local)
        note("local allow not final: the local rules %s the server's; asking the server" % ("differ from" if trust == "mismatch" else "could not be verified against"))
    out = server_outcome(args, local, unclear)
    if trust is not None and out.notice is None:
        out.notice = trust_notice(trust)
    return out


def server_outcome(args, local, unclear):
    """The server half of the guard path: send the command to kit_guard_command, and say what stands when it cannot be consulted."""
    # What the ledger row of a command that goes on without a decision can still say: which rule flagged it (a rule id, never text).
    hint = {"rule": local.get("rule")} if unclear and isinstance(local.get("rule"), str) else None
    # `unclear` can hold while the local reply is already an ask (a rule asked on one reading, the model question came from the other):
    # if the server then cannot be consulted, that ask is the decision. Never an allow only because nobody answered the model question.
    stands = local if unclear and local.get("decision") in ("ask", "block") else None
    try:
        signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, TIMEOUT + 0.5)
        r = call_guard(args)
    except GuardFailOpen as e:
        note("fail-open: %s" % e.why)
        if stands is not None:
            return reply_outcome(stands)
        if local is None and _CTX.get("local_why") and e.code == "client_config":
            # the local step was on and did not run, and there is no server either: nothing checked this command. Its own closed reason, so the
            # log tells it from "unclear, no server" (those rows have a reply from the rules; these have none).
            notice = LOCAL_DOWN_NOTICE if local_down_notice(_CTX["local_why"]) else None
            return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason="local_rules_unavailable", enforced=True), notice=notice)
        notice = LOCAL_NOTICE if unclear and e.code == "client_config" and first_unclear_in_session() else None
        return Outcome("allow", reply=hint, row=dict(decision="allow", decided_by="fail_open", fail_reason=e.code, enforced=True), notice=notice)
    except (ServerRejected, RedirectRefused) as e:  # server reachable but refused/redirected the call: ask, never allow silently
        if MODE == "shadow":
            return Outcome("allow", row=dict(decision="ask", decided_by="fail_closed", fail_reason="client_rejected", enforced=False, would_have="ask"),
                           stderr="jev-guard (shadow): would ask: server rejected call: %s\n" % str(e)[:200])
        return Outcome("ask", "Jev guard could not judge this call (server rejected it: %s); confirm it by hand." % str(e)[:200],
                       row=dict(decision="ask", decided_by="fail_closed", fail_reason="client_rejected"))
    except Exception as e:  # timeout, DNS, HTTP error, bad JSON ... all fail open
        note("fail-open: %s: %s" % (type(e).__name__, str(e)[:120]))
        if stands is not None:
            return reply_outcome(stands)
        return Outcome("allow", reply=hint, row=dict(decision="allow", decided_by="fail_open", fail_reason=_ledger.fail_reason_for(e) if _ledger else "client_network", enforced=True))
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except Exception:
            pass
    return reply_outcome(r)


def reply_outcome(r):
    """A guard reply (the server's, or the local rules' own) as an Outcome: the one place a reply becomes an effect and a ledger row."""
    decision = r.get("decision")
    would = decision if MODE == "shadow" and decision in ("ask", "block") else None
    row = {"decision": decision, "enforced": would is None, "would_have": would}
    if r.get("decided_by") == "fail_closed" and r.get("fail_reason") == "rule_error":
        row["fail_reason"] = "rule_error"  # a server reply carries this in its record; a local reply has none
    why = "%s%s%s" % (
        "Jev guard [%s]: " % r["rule"] if r.get("rule") else "Jev guard: ",
        r.get("reason", ""),
        (" " + r["suggestion"]) if r.get("suggestion") and decision != "allow" else "",
    )
    note("%s score=%s rule=%s decided_by=%s" % (decision, r.get("score"), r.get("rule"), r.get("decided_by")))
    if decision not in ("ask", "block"):
        return Outcome("allow", reply=r, row=row)  # allow (including the server's own fail-open)
    if MODE == "shadow":
        return Outcome("allow", reply=r, row=row, stderr="jev-guard (shadow): would %s: %s\n" % (decision, why[:300]))
    return Outcome("deny" if decision == "block" else "ask", why, reply=r, row=row)


# ── policy path (openspec add-policy-hook-adapter) ──────────────────────────────────────────────────────────────────
def policy_user_layer_path():
    p = os.environ.get("JEV_POLICY_USER", "").strip()
    if p:
        return p
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    return os.path.join(xdg if xdg and os.path.isabs(xdg) else os.path.join(os.environ.get("HOME") or os.path.expanduser("~"), ".config"), "jev", "policy.json")


def policy_has_trigger():
    """True when the user layer is a small regular file (not a symlink) whose text mentions a trigger. Cheap, no process
    started: with no trigger the hook behaves exactly as before. A policy-path failure after this is recorded."""
    try:
        path = policy_user_layer_path()
        st = os.lstat(path)
        if not stat_is_regular(st) or st.st_size > POLICY_LAYER_MAX:
            return False
        with open(path, "rb") as f:
            return POLICY_TRIGGER in f.read(POLICY_LAYER_MAX + 1).decode("utf-8", "replace")
    except Exception:
        return False


def stat_is_regular(st):
    import stat as _stat
    return _stat.S_ISREG(st.st_mode)


POLICY_NOTICE = ("Jev policy: a policy gate was not evaluated for this command (the helper is unavailable, the policy file is "
                 "unusable, or it ran out of time). The reason is in the decision ledger.")


def policy_gate_may_be_closed():
    """True when a class with a trigger fails closed (its on_unavailable decision is not its baseline), or when the layer cannot be
    read well enough to tell (unknown counts as closed). Used only to decide whether a silent fail-open deserves a notice for the
    user; it never changes a decision. Cheap, never raises."""
    try:
        with open(policy_user_layer_path(), "rb") as f:
            doc = json.loads(f.read(POLICY_LAYER_MAX + 1).decode("utf-8", "replace"))
        decisions = doc["decisions"]
        if not isinstance(decisions, list):
            return True
        closed = False
        for d in decisions:
            if isinstance(d, dict) and "trigger" in d:
                un = d.get("on_unavailable")
                if not isinstance(un, dict) or un.get("decision") is None or un.get("decision") != d.get("baseline"):
                    closed = True
        return closed
    except Exception:
        return True


def policy_runtime():
    """The JavaScript runtime that runs the plan helper: node, else bun (the helper uses only node: APIs both provide)."""
    return shutil.which("node") or shutil.which("bun")


def policy_helper_path():
    p = os.environ.get("JEV_POLICY_HOOK", "").strip()
    return p or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "jev-policy", "scripts", "jev-policy-hook.mjs")


def policy_timeout():
    try:
        v = float(os.environ.get("JEV_POLICY_TIMEOUT", "3"))
    except ValueError:
        v = 3.0
    return min(4.0, max(1.0, v)) if v == v else 3.0


def run_plan(event_input, deadline):
    """Run the plan helper (argv array, no shell). Returns (plan, None) or (None, fail_code)."""
    helper = policy_helper_path()
    node = policy_runtime()
    if not node or not os.path.isfile(helper):
        return None, "client_config"
    budget = max(0.5, deadline - time.monotonic() - 1.0)
    try:
        r = subprocess.run([node, helper, "plan"], input=json.dumps(event_input).encode(), capture_output=True, timeout=budget)
    except subprocess.TimeoutExpired:
        return None, "client_timeout"
    except Exception:
        return None, "client_network"
    try:
        plan = json.loads(r.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
    except Exception:
        return None, "client_parse"
    return (plan, None) if isinstance(plan, dict) and plan.get("ok") is True else (None, "client_config")


def _effect_of(plan, word):
    e = (plan.get("effects") or {}).get(word)
    return e if e in RANK else "ask"


def policy_outcome(event_input, deadline):
    """The whole policy path, run in a thread beside the guard call. Returns an Outcome (allow with no row when nothing fired)."""
    try:
        plan, code = run_plan(event_input, deadline)
        if plan is None:
            note("policy: plan helper failed (%s); policy not enforced" % code)
            return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason=code, enforced=True), tool="kit_decide",
                           notice=POLICY_NOTICE if MODE != "shadow" and policy_gate_may_be_closed() else None)
        if not plan.get("triggered"):
            return Outcome("allow")
        cls, pv = str(plan.get("class", ""))[:48], plan.get("policy_version")
        un = plan.get("on_unavailable") or {}
        closed = un.get("mode") == "closed"
        shadow = MODE == "shadow"

        def done(effect, reason, reply=None, **row):
            would = ({"ask": "ask", "deny": "block"}.get(effect) if shadow else None)
            if shadow and effect != "allow":
                row.update(enforced=False, would_have=would)
                return Outcome("allow", reply=reply, row=row, tool="kit_decide", stderr="jev-guard (shadow): policy would %s: %s\n" % (effect, reason[:300]))
            row.setdefault("enforced", True)
            return Outcome(effect, reason, reply=reply, row=row, tool="kit_decide")

        def unavailable(code, why):
            eff = un.get("effect") if un.get("effect") in RANK else "ask"
            return done(eff, "Jev policy [%s]: %s; applying the class's failure rule (%s)." % (cls, why, un.get("decision")),
                        decision=un.get("decision"), decided_by="fail_closed" if closed else "fail_open", fail_reason=code, policy_version=pv)

        if plan.get("extra"):
            return done("ask", "Jev policy: more than one policy gate matches this command; run them one at a time.",
                        decision="ask", decided_by="policy", fail_reason=None, policy_version=pv)
        if plan.get("provider_failure"):
            pf = plan["provider_failure"]
            return unavailable(pf.get("code"), "a fact provider (%s) could not answer" % str(pf.get("name"))[:40])
        remaining = deadline - time.monotonic()
        if remaining < 0.3:
            return unavailable("client_timeout", "no time left for the policy call")
        call = dict(plan["call"])
        call["budget_ms"] = max(300, int(remaining * 1000) - 300)
        try:
            reply = call_guard(call, tool="kit_decide", timeout=max(0.3, remaining))
        except (ServerRejected, RedirectRefused) as e:
            return done("ask", "Jev policy [%s]: the server rejected the policy call (%s); confirm it by hand." % (cls, str(e)[:120]),
                        decision="ask", decided_by="fail_closed", fail_reason="client_rejected", policy_version=pv)
        except GuardFailOpen as e:
            return unavailable(e.code, e.why)
        except Exception as e:
            return unavailable(_ledger.fail_reason_for(e) if _ledger else "client_network", "the policy call failed")
        word = reply.get("decision")
        eff = _effect_of(plan, word)
        rid = reply.get("rule_id")
        why = "Jev policy [%s/%s]: %s" % (cls, rid or "default", reply.get("reason", ""))
        return done(eff, why, reply=reply, decision=word, policy_version=pv)
    except Exception as e:  # never let the policy path break the hook
        note("policy: %s" % type(e).__name__)
        return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason="client_network", enforced=True), tool="kit_decide",
                       notice=POLICY_NOTICE if MODE != "shadow" and policy_gate_may_be_closed() else None)


class PolicyRun(threading.Thread):
    def __init__(self, event_input, deadline):
        threading.Thread.__init__(self, daemon=True)
        self.event_input, self.deadline, self.outcome = event_input, deadline, None

    def run(self):
        self.outcome = policy_outcome(self.event_input, self.deadline)


def conclude(g, policy):
    """Print the stricter of the guard's and the policy's decisions, THEN write both ledger rows."""
    p = Outcome("allow")
    if policy is not None:
        policy.join(max(0.0, policy.deadline - time.monotonic()) + 0.3)
        p = policy.outcome if policy.outcome is not None else Outcome(
            "allow", row=dict(decision="allow", decided_by="fail_open", fail_reason="client_timeout", enforced=True), tool="kit_decide",
            notice=POLICY_NOTICE if MODE != "shadow" and policy_gate_may_be_closed() else None)
    for o in (g, p):
        if o.stderr:
            sys.stderr.write(o.stderr)
    final = g.effect if RANK[g.effect] >= RANK[p.effect] else p.effect
    notice = p.notice or g.notice
    out = {}
    if final != "allow":
        parts = []
        if p.effect == final and p.reason:
            parts.append(p.reason)
        if g.effect == final and g.reason:
            parts.append(g.reason)
        out["hookSpecificOutput"] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": final,
            "permissionDecisionReason": " ".join(parts)[:1500],
        }
    if notice:
        # for the USER (systemMessage), not the model: fixed text, no command, no path, no instruction
        out["systemMessage"] = notice
        sys.stderr.write(notice + "\n")
    if out:
        print(json.dumps(out), flush=True)
    g.write()
    p.write()
    sys.exit(0)


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        _CTX["on"], _CTX["t0"] = True, time.monotonic()  # this hook's own tool: the input was unusable, which is worth a row
        fail_open("stdin was not JSON", "client_input")
    tool = event.get("tool_name", "")
    ti = event.get("tool_input") or {}
    policy_input = None
    if tool == "Bash" and ti.get("command"):
        args = {"tool": "Bash", "command": str(ti["command"])}
        if ti.get("description"):
            args["description"] = str(ti["description"])
        if str(event.get("cwd") or "").startswith("/"):
            policy_input = {"tool": "Bash", "command": str(ti["command"]), "cwd": str(event["cwd"]), "host": _CTX["host"]}
    elif tool in ("Read", "NotebookRead") and (ti.get("file_path") or ti.get("notebook_path")):
        args = {"tool": "Read", "file_path": str(ti.get("file_path") or ti.get("notebook_path"))}
    elif tool == "Grep" and ti.get("pattern") and ti.get("output_mode") == "content":
        # output_mode defaults to files_with_matches (paths only, no content); only "content" mode prints
        # matching lines verbatim, so only that mode is judged as the grep command it is (R1 secret reader).
        args = {"tool": "Bash", "command": "grep -r %s %s" % (json.dumps(str(ti["pattern"])), json.dumps(str(ti.get("path") or ".")))}
    else:
        sys.exit(0)  # not a tool this guard covers
    _CTX["on"], _CTX["t0"], _CTX["session"] = True, time.monotonic(), event.get("session_id")
    if event.get("cwd"):
        args["cwd"] = str(event["cwd"])
    home = os.environ.get("JEV_GUARD_HOME") or os.path.expanduser("~")
    if home and home != "~":
        args["home"] = home
    ask_at = parse_ask_at(os.environ.get("JEV_GUARD_ASK_AT"))
    if ask_at is not None:
        args["ask_at"] = ask_at

    policy = None
    if policy_input is not None and policy_has_trigger():
        policy = PolicyRun(policy_input, _CTX["t0"] + policy_timeout())
        policy.start()
    conclude(guard_outcome(args), policy)


if __name__ == "__main__":
    main()
