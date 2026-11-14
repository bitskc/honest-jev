// Issue #96 case tables, shared by server/test/verify-96.test.mjs and hooks/jev-stop-verify-96.test.mjs so the server and the
// hook's copy are pinned to the SAME cases. Every command and output is DATA handed to runOutcome()/exitIsMasked(); nothing is executed.
export const PIPEFAIL96 = [
  // [command, masked?]
  ["set -o pipefail; npm test | tail -5", false], ["set -eo pipefail; npm test | tail -5", false], ["set -euo pipefail; npm test | tail -5", false],
  ["set -e -o pipefail; npm test | tail -5", false], ["set -o errexit -o pipefail; npm test | tail -5", false], ["set -u -o pipefail; npm test | tail", false],
  ["set -o pipefail && npm test | tail -5", false], ["set -o pipefail\nnpm test | tail -5", false], ["set -o pipefail;npm test|tail", false],
  ["cd app; set -o pipefail; npm test | tail", false], ["bash -o pipefail -c 'npm test | tail'", false], ["bash -c 'set -o pipefail; npm test | tail'", false],
  ["set +o pipefail; set -o pipefail; npm test | tail", false], ["set +o pipefail -o pipefail; npm test | tail", false],
  // not enabled, or enabled and disabled again before the pipe
  ["set +o pipefail; npm test | tail -5", true], ["set -o pipefail; set +o pipefail; npm test | tail -5", true], ["set -o pipefail +o pipefail; npm test | tail", true],
  ["set -euo pipefail; set +o pipefail; npm test | tail", true], ["bash -o pipefail -c 'set +o pipefail; npm test | tail'", true],
  // the word is data, not a statement: a test filter, an echo, a quoted or escaped word, a comment, a later statement
  ["npm test -- -t pipefail | tail -5", true], ["npm test --test-name-pattern pipefail | tail -5", true], ["node --test --test-name-pattern=pipefail | tail", true],
  ["echo 'set -o pipefail'; npm test | tail", true], ["echo set -o pipefail; npm test | tail", true], ["# set -o pipefail\nnpm test | tail", true],
  ["set '-o' pipefail; npm test | tail", true], ["set -o 'pipefail'; npm test | tail", true], ["set -o pipefail\\; npm test | tail", true],
  ["npm test | tail; set -o pipefail", true], ["echo hi; set -o pipefail; npm test | tail", true], ["set -o pipefailx; npm test | tail", true],
  // `set` arguments after `--`, `-` or a plain word are positional parameters, not options
  ["set -- -o pipefail; npm test | tail", true], ["set x -o pipefail; npm test | tail", true], ["set - -o pipefail; npm test | tail", true], ["set -e foo -o pipefail; npm test | tail", true],
  // another process or a scope that does not reach the pipe
  ["set -o pipefail | cat; npm test | tail", true], ["(set -o pipefail; npm test | tail)", true], ["{ set -o pipefail; npm test | tail; }", true],
  ["f() { set -o pipefail; }; f; npm test | tail", true], ["bash -o pipefail script.sh | tail", true], ["set -o; npm test | tail", true],
];
export const CRASH96 = [
  "SyntaxError: Unexpected token ')' in test/x.test.mjs", "Uncaught SyntaxError: Unexpected end of input", "ReferenceError: x is not defined", "TypeError: x is not a function",
  "RangeError: Maximum call stack size exceeded", "Traceback (most recent call last):\n  File \"t.py\", line 1, in <module>", "thread 'main' panicked at src/lib.rs:3:5",
  "Segmentation fault (core dumped)", "Segmentation fault", "free(): invalid pointer\nAborted (core dumped)",
];

