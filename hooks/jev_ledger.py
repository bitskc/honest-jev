"""Local decision ledger for the jev hooks (openspec add-decision-ledger).

Append-only JSONL, one content-free record per decision, written by the party that knows what happened: the hook
sees what the server cannot (client-side fail-open, the decision shadow mode did not enforce, a server rejection that
became an `ask`). Stdlib only. Nothing here may change a hook's decision, exit status or latency in any way worth
noticing, so every public function swallows every exception and returns False.

Rules this module enforces by construction:
  * content-free: a record is REBUILT from allow-list shapes; a value that does not fit its shape becomes null (it is
    rejected, never redacted and kept), so no command, path, prompt or message text and no exception text, hostname or
    URL can reach it, whatever the caller passes; a row over 2 KB is dropped, never truncated;
  * fail_reason is a closed code list;
  * one atomic append: open with O_APPEND|O_NOFOLLOW, a single os.write of one whole line (no buffered file object,
    no lock, no fsync); the file must be a regular file owned by us, in a directory owned by us (0700);
  * rotation at 20 MB never overwrites: the old file is renamed to a unique `ledger.jsonl.<UTC>-<pid>`, the newest
    three rotated files are kept.

Env: JEV_LEDGER=<absolute path> overrides the location (a relative path is refused: no row is written), JEV_LEDGER=off disables. Default $XDG_STATE_HOME/jev/ledger.jsonl
(only if absolute), else ~/.local/state/jev/ledger.jsonl.
"""
import json
import os
import re
import stat
import time
import uuid

VERSION = 1
MAX_BYTES = 20 * 1024 * 1024
MAX_LINE = 2048
KEEP_ROTATED = 3
DECIDED_BY = ("prefilter", "jev", "fail_open", "fail_closed", "policy")
FAIL_REASONS = (
    "no_upstream", "upstream_error", "timeout", "invalid_response", "oversize",
    "client_config", "client_input", "client_timeout", "client_network", "client_http_5xx", "client_parse", "client_rejected", "rule_error",
)
COST_SOURCES = ("upstream", "configured", "unknown")

_WORD = re.compile(r"^[a-z][a-z_]{0,31}$")
_RULE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
_TOOL = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_TIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_HOST = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
_CORRELATION = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_POLICY_VERSION = re.compile(r"^[0-9a-f]{12}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")


def _pick(rx, v):
    return v if isinstance(v, str) and rx.match(v) else None


def _nonneg(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v if v == v and v not in (float("inf"),) and v >= 0 else None


def ledger_path():
    p = os.environ.get("JEV_LEDGER", "").strip()
    if p.lower() == "off":
        return None
    if p:
        return p if os.path.isabs(p) else None  # relative would land in the working directory: refused, no row written
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    base = xdg if xdg and os.path.isabs(xdg) else os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "jev", "ledger.jsonl")


def state_dir():
    """The private directory the ledger lives in (its parent when a ledger path is set; the default state dir when the ledger is off)."""
    p = ledger_path()
    if p:
        return os.path.dirname(p) or "."
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    return os.path.join(xdg if xdg and os.path.isabs(xdg) else os.path.join(os.path.expanduser("~"), ".local", "state"), "jev")


def fail_reason_for(exc):
    """Map an exception to a closed code. The exception's text is never read."""
    try:
        # imported here, not at module top: a hook that never reaches the network never pays for socket/urllib (tempfile, shutil, ...)
        import socket
        import urllib.error
        if isinstance(exc, (TimeoutError, socket.timeout)):
            return "client_timeout"
        if isinstance(exc, urllib.error.HTTPError):
            return "client_http_5xx" if exc.code >= 500 else "client_network"
        if isinstance(exc, urllib.error.URLError):
            return "client_timeout" if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)) else "client_network"
        if isinstance(exc, (ValueError, KeyError, IndexError, TypeError)):
            return "client_parse"
    except Exception:
        pass
    return "client_network"


def _jev_block(src):
    j = src if isinstance(src, dict) else {}
    used = j.get("calls") == 1 if "calls" in j else j.get("used") is True
    u = j.get("usage") if isinstance(j.get("usage"), dict) else {}
    src_cost = _nonneg(j.get("cost")) if "cost" in j else _nonneg(u.get("cost"))
    cs = j.get("cost_source")
    return {
        "calls": 1 if used else 0,
        "status": _pick(_WORD, j.get("status")),
        "model": _pick(_MODEL, j.get("model")) if used else None,
        "input_tokens": _nonneg(j.get("input_tokens", u.get("input_tokens"))) if used else None,
        "output_tokens": _nonneg(j.get("output_tokens", u.get("output_tokens"))) if used else None,
        "cost": src_cost if used else None,
        "cost_source": (cs if cs in COST_SOURCES else ("upstream" if src_cost is not None else "unknown")) if used else None,
    }


def build_row(rec, *, tool, host, decision=None, decided_by=None, fail_reason=None, latency_ms=None,
              enforced=True, would_have=None, source="client", policy_version=None):
    """Whitelist rebuild. `rec` is an optional server-sent record (untrusted shape); explicit kwargs override it."""
    r = rec if isinstance(rec, dict) else {}
    t = r.get("tiers") if isinstance(r.get("tiers"), dict) else None
    tiers = {"chosen": _pick(_TIER, t.get("chosen")), "recommended": _pick(_TIER, t.get("recommended"))} if t else None
    db = decided_by if decided_by is not None else r.get("decided_by")
    db = db if db in DECIDED_BY else None
    fr = fail_reason if fail_reason is not None else r.get("fail_reason")
    fr = fr if fr in FAIL_REASONS else None
    if db == "fail_open" and fr is None:
        fr = "upstream_error"
    rid = r.get("decision_id")
    ts = r.get("ts")
    return {
        "v": VERSION,
        # The hook mints every row's id so fail-open and old-Worker rows are first-class; the Worker's id is kept apart.
        "decision_id": str(uuid.uuid4()),
        "server_decision_id": rid if isinstance(rid, str) and _UUID.match(rid) else None,
        "ts": ts if isinstance(ts, str) and _TS.match(ts) else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": _pick(_TOOL, tool),
        "decision": _pick(_WORD, decision if decision is not None else r.get("decision")),
        "verdict": _pick(_WORD, r.get("verdict")),
        "decided_by": db,
        "rule": _pick(_RULE, r.get("rule")),
        "fail_reason": fr,
        "latency_ms": None if _nonneg(latency_ms) is None else int(round(latency_ms)),
        "jev": _jev_block(r.get("jev")),
        "tiers": tiers if tiers and (tiers["chosen"] or tiers["recommended"]) else None,
        "host": _pick(_HOST, host),
        "correlation_id": _pick(_CORRELATION, r.get("correlation_id")),
        # 12 lower-case hex or null: the hash of a policy class's effective spec (add-policy-layers), never free text
        "policy_version": _pick(_POLICY_VERSION, policy_version if policy_version is not None else r.get("policy_version")),
        "source": source if source in ("server", "client") else "client",
        "enforced": bool(enforced),
        "would_have": _pick(_WORD, would_have),
    }


def synth_from_reply(tool, reply):
    """A worker that predates the ledger sends no `record`. Rebuild what we can from the reply's own fields."""
    r = reply if isinstance(reply, dict) else {}
    jev = r.get("jev") if isinstance(r.get("jev"), dict) else {}
    used = jev.get("used") is True
    status = jev.get("status")
    failed = status in ("unavailable", "invalid_response")
    decided_by = r.get("decided_by") if r.get("decided_by") in DECIDED_BY else ("fail_open" if failed else "jev" if used else "prefilter")
    detail = jev.get("detail") if isinstance(jev.get("detail"), str) else ""
    code = "invalid_response" if status == "invalid_response" else (
        "no_upstream" if "no jev credentials" in detail.lower() else
        "timeout" if re.search(r"timed out|timeout|abort", detail, re.I) else "upstream_error")
    usage = jev.get("usage") if isinstance(jev.get("usage"), dict) else {}
    chosen = r.get("chosen") if isinstance(r.get("chosen"), dict) else {}
    policy = r.get("policy") if isinstance(r.get("policy"), dict) else {}
    tiers = {"chosen": chosen.get("tier"), "recommended": r.get("recommended_tier")} if tool == "kit_size_dispatch" else None
    return {
        "decision": r.get("decision") if tool in ("kit_guard_command", "kit_decide") else r.get("action"),
        "verdict": None if tool in ("kit_guard_command", "kit_decide") else r.get("verdict"),
        "decided_by": decided_by,
        "rule": r.get("rule_id") if tool == "kit_decide" else r.get("rule"),
        # kit_decide names its own closed fail_reason (a spec's on_unavailable also reports one on a fail_closed row)
        "fail_reason": r.get("fail_reason") if tool == "kit_decide" else (code if decided_by == "fail_open" else None),
        "policy_version": policy.get("version") if tool == "kit_decide" else None,
        "jev": {"used": used, "status": status, "model": jev.get("model"), "usage": usage},
        "tiers": tiers,
    }


def _owned_dir(d):
    """The ledger directory must be a real directory (not a symlink) owned by us; created 0700."""
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.lstat(d)
        return stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
    except Exception:
        return False


def _open(path):
    """O_APPEND|O_NOFOLLOW; returns an fd of a regular file owned by us, else raises."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):  # a symlink, FIFO or device is refused before it is opened
            raise OSError("ledger path is not a regular file")
    except FileNotFoundError:
        pass
    # O_NONBLOCK: a FIFO swapped in after the check must fail to open, not hang the hook (no-op for regular files)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
        os.close(fd)
        raise OSError("ledger is not a regular file owned by this user")
    return fd


_ROTATED = re.compile(r"\.\d{8}T\d{12}Z-\d+$")  # UTC stamp to the microsecond, then the pid


def rotated_files(path):
    """Rotated generations of `path`, oldest first."""
    d, base = os.path.split(path)
    try:
        names = [n for n in os.listdir(d or ".") if n.startswith(base + ".") and _ROTATED.search(n)]
    except OSError:
        return []
    return [os.path.join(d, n) for n in sorted(names)]


def _rotate(path, fd, measured):
    """Rotate at the cap and return a descriptor for the new file. The old file is RENAMED to a unique name (never
    overwritten); if the path no longer refers to the file we measured, another writer already rotated and we only
    reopen. Two concurrent rotators can at worst leave an extra small rotated file; no existing row is lost."""
    try:
        cur = os.lstat(path)
        if (cur.st_ino, cur.st_dev) == (measured.st_ino, measured.st_dev):
            now = time.time()
            target = "%s.%s%06dZ-%d" % (path, time.strftime("%Y%m%dT%H%M%S", time.gmtime(now)), int((now % 1) * 1e6), os.getpid())
            if not os.path.lexists(target):  # unique by construction; never clobber an existing generation
                os.rename(path, target)
    except FileNotFoundError:
        pass
    os.close(fd)
    fd = _open(path)
    for old in rotated_files(path)[:-KEEP_ROTATED]:
        try:
            os.unlink(old)
        except OSError:
            pass
    return fd


def append(row, path=None):
    """One atomic append of one whole line. Returns True if the whole line was written. Never raises."""
    fd = None
    try:
        path = path or ledger_path()
        if not path:
            return False
        line = (json.dumps(row, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        if len(line) > MAX_LINE:
            return False
        if not _owned_dir(os.path.dirname(path) or "."):
            return False
        fd = _open(path)
        st = os.fstat(fd)
        if st.st_size > MAX_BYTES:
            fd = _rotate(path, fd, st)
        return os.write(fd, line) == len(line)
    except Exception:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def record(tool, host, reply=None, **kw):
    """Build and append one row. `reply` is the worker's parsed tool payload (may carry `record`)."""
    try:
        rec = None
        source = kw.pop("source", None)
        if isinstance(reply, dict):
            if isinstance(reply.get("record"), dict):
                rec, source = reply["record"], source or "server"
            else:
                rec, source = synth_from_reply(tool, reply), source or "client"
        return append(build_row(rec, tool=tool, host=host, source=source or "client", **kw))
    except Exception:
        return False


MARKER_MAX_AGE = 14 * 24 * 3600
_MARKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")


def mark_once(name):
    """True exactly once per `name`, across processes: the first caller creates state_dir()/<name> (O_EXCL, 0600, in the same
    private directory as the ledger); every later caller finds it and gets False. Any failure to remember also returns False,
    because a notice that cannot be remembered must not repeat on every call. Never raises. Markers older than 14 days are
    removed whenever a new one is made, so the directory does not grow without bound."""
    try:
        if not isinstance(name, str) or not _MARKER_NAME.match(name):
            return False
        d = state_dir()
        if not _owned_dir(d):
            return False
        os.close(os.open(os.path.join(d, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600))
    except Exception:
        return False
    try:
        now = time.time()
        prefix = name.split("-", 1)[0] + "-"
        for n in os.listdir(d):
            if n.startswith(prefix) and n != name:
                p = os.path.join(d, n)
                if now - os.lstat(p).st_mtime > MARKER_MAX_AGE:
                    os.unlink(p)
    except Exception:
        pass
    return True
