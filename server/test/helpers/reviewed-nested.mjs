// Regexes whose repeated group holds another unbounded quantifier or an alternation, each READ for ambiguity (can one string match in
// more than one way with a failure after the group?) and timed. Shared by server/test/regex-sweep.test.mjs and
// hooks/regex-sweep.test.mjs (the hook ships copies of the server's rules). Keyed by the exact regex source.
export const REVIEWED_NESTED = new Map([
  ["'([^'\\\\]*(?:\\\\.[^'\\\\]*)*)'|\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"", "unrolled quoted string: the inner class excludes the backslash, so each backslash pair is matched one way"],
  ["(?<!\\d)\\d+(?:\\.\\d+)*$", "dot-delimited digit groups; (?<!\\d) starts a run at its first digit only"],
  ["\\$\\(\\s*(?:realpath|readlink)(?:\\s+-\\S+)*\\s+([^\\s()`$]+)\\s*\\)|`\\s*(?:realpath|readlink)(?:\\s+-\\S+)*\\s+([^\\s()`$]+)\\s*`", "options are whitespace-delimited words: `\\S+` cannot cross the `\\s+` the next repeat starts with"],
  ["\\/(\\*|\\.(?:\\[[^\\]/]*\\]|\\?|\\*)*\\*)$", "glob pieces start with distinct characters (`[`, `?`, `*`); a bracket class cannot contain `]`"],
  ["^(?:\\.\\/)*(?:\\*|\\.(?:\\[[^\\]/]*\\]|\\?|\\*)*\\*)$", "same glob pieces, anchored; `./` repeats are literal"],
  ["^(?:\\.\\.\\/)+(?:\\*|\\.(?:\\[[^\\]/]*\\]|\\.|\\?|\\*)*\\*)$", "same glob pieces, anchored; `../` repeats are literal"],
  ["^([a-z]+?)(\\d+(?:\\.\\d+)*)$", "anchored; a dot separates every repeat"],
  ["\\$\\(\\s*(?:echo(?:\\s+-[neE]+)*|printf)\\s+('[^']*'|\"[^\"$`\\\\]*\"|[^\\s()$`'\"\\\\;&|<>%]+)\\s*\\)|`\\s*(?:echo(?:\\s+-[neE]+)*|printf)\\s+('[^']*'|\"[^\"$`\\\\]*\"|[^\\s()$`'\"\\\\;&|<>%]+)\\s*`", "whitespace-delimited flags; the operand alternatives start with different characters"],
  ["^(\\s*(?:[({!]+\\s*)?)((?:\\$\\([^()]*\\)|`[^`]*`|\\$\\{[A-Za-z_]\\w*\\}|\\$[A-Za-z_]\\w*|[^\\s;&|()$`'\"<>\\\\])+)", "`$name` and the plain-character class can split a name more than one way, but nothing follows the group, so the match cannot fail after it and never backtracks"],
  ["'([^'\\\\]*(?:\\\\.[^'\\\\]*)*)'|\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"|`([^`\\\\]*(?:\\\\.[^`\\\\]*)*)`", "unrolled quoted strings, as above"],
  ["(?<!<)<<(-?)[ \\t]*(?!<)(?:'([^']*)'|\"([^\"]*)\"|((?:\\\\.|[^\\s;&|<>()'\"])+))", "a backslash can be read as `\\\\.` or as a class character, but nothing follows the group, so the match cannot fail after it and never backtracks"],
  ["'[^']*'|\"(?:[^\"\\\\]|\\\\.)*\"", "the alternatives of the repeat exclude the backslash from the first one"],
  ["^exec(?:\\s+-\\S+)*\\s+(?=\\S)", "anchored; options are whitespace-delimited words, one parse"],
  ["^(?:\\S*\\/)?(?:(?:docker|podman|kubectl)\\s+exec|(?:docker|podman)\\s+compose\\s+run|docker-compose\\s+run|chroot|ssh)\\b(?:\\s+-\\S+)*\\s+\\S+\\s+(?:--\\s+)?(.*)$", "anchored; each repeat consumes exactly one whitespace-delimited option word, so the repeat count is the only choice (polynomial at worst, timed)"],
  ["^\\s*(?:(?:cd|pushd|popd|export|set|unset|source|\\.)(?=\\s|$)|[A-Za-z_]\\w*=\\S*(?:\\s+[A-Za-z_]\\w*=\\S*)*\\s*$)", "round 27 rewrite of `(?:NAME=\\S*\\s*)+$`, which was exponential (`a=` x28 + ` b`): assignments are now separated by required whitespace, one parse"],
  ["^(?:ba|z|da|k)?sh(?:\\s+-[A-Za-np-z]+)*\\s+-[A-Za-np-z]*c\\s+(?:'([^']*)'|\"((?:[^\"\\\\$`]|\\\\.)*)\")$", "anchored; whitespace-delimited flags; the quoted body's class excludes the backslash"],
  ["(?:^|[\\s;&|\\/])(?:ba|z|da|k)?sh\\s+(?:\\S+\\s+)*?-\\w*c\\b", "lazy repeat of whitespace-delimited words: one parse per word count (polynomial at worst, timed)"],
  ["^bash\\s+-o\\s+pipefail\\s+-c\\s+(?:'([^']*)'|\"((?:[^\"\\\\$`]|\\\\.)*)\")$", "anchored quoted body; the class excludes the backslash"],
  ["^[A-Za-z_]\\w*\\+?=\\S*(?:\\s+[A-Za-z_]\\w*\\+?=\\S*)*\\s*$", "round 27 rewrite of the exponential `(?:NAME=\\S*\\s*)+$`: whitespace-separated assignments, anchored, one parse"],
  ["^=+ (?:\\d+ (?:skipped|deselected|warnings?|xfailed|xpassed),? ?)+ in [\\d.]+s", "each repeat starts with a digit run and a fixed word, so a split of the text is unique"],
  ["(\\s*\\|\\s*tail(?:\\s+-\\S+)*\\s*)$", "whitespace-delimited options then `\\s*$`; one parse"],
  ["^\\|?\\s*:?-{3,}:?\\s*(\\|\\s*:?-{3,}:?\\s*)*\\|?$", "each repeat starts with a literal `|`; one parse"],
  ["^(?:>\\s*)+", "each repeat starts with a literal `>`; one parse"],
  ["(?<![\\w.])([A-Za-z_]\\w*)(?:\\s*\\[[^\\]=\\n]*\\]|\\.\\w+)*\\s*=\\s*([^;\\n]+)", "the lookbehind starts a match only at an identifier's first character; each repeat begins with a distinct character (`[` or `.`) and ends at its own closer, so the split is unique"],
]);
