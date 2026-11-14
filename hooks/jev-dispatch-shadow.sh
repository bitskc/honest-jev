#!/usr/bin/env bash
# OPT-IN shadow-only PreToolUse hook for sub-agent dispatch: records what kit_size_dispatch would say, never blocks.
# See jev_dispatch_shadow.py and config/claude-dispatch-shadow-hook.json. Fails open; exits 0 on every path.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || exit 0
python3 "$here/jev_dispatch_shadow.py"
exit 0
