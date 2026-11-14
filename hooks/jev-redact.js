// Ported from server/src/kit/shell.mjs's redact()/redactCap() (in turn adapted from valentynkit/jev-belay
// belay.mjs, MIT — see server/NOTICE-jev-kit.md). Not imported directly: the server is a separate
// Cloudflare Worker package (ESM, its own deps); hooks stay zero-dependency plain Node (CommonJS). This
// is a byte-for-byte copy of SECRET_RULES/redact/redactCap — keep it in sync by hand. Drift is caught by
// hooks/jev-stop-verify.test.mjs's dedicated test (the server's own redact-test strings through BOTH copies) and
// hooks/jev-redact-parity.test.mjs (the rule literals themselves, compared source-to-source, plus the #27 leak table).
'use strict';

const REDACTED = '<redacted>';
const SECRET_RULES = [
  // Private key blocks. The body may not contain another BEGIN, so each BEGIN scans only to the next one (linear). An
  // unterminated key is redacted up to the next BEGIN or the end of the input, never left in the clear.
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?(?:-----END [A-Z ]*PRIVATE KEY-----|(?=-----BEGIN )|$)/g, REDACTED],
  [/(authorization\s*[:=]\s*)(?:(?:basic|bearer|token)\s+)?("[^"\n]{0,512}"|'[^'\n]{0,512}'|"[^\s"]*|'[^\s']*|[^\s"']+)/gi, `$1${REDACTED}`],
  [/\b(bearer\s+)[\w.-]{16,}/gi, `$1${REDACTED}`],
  // name-based: anything ending in key/pass/pwd/auth/cookie/session/signature/token/secret, plus the classic words;
  // a quoted value runs to the closing quote (multi-word passphrases), an unquoted one to the next delimiter.
  [/((?:\b[a-z0-9_-]{0,64}(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|passw(?:or)?d|passphrase|credentials?|_key|_pass|_pwd|_auth|_cookie|_session|_signature|token|secret)[a-z0-9_-]{0,64})["']?\s*[=:]\s*)("([^"]*)"|'([^']*)'|[^\s"'&;]+)/gi, `$1${REDACTED}`],
  // CLI option values, scoped to avoid eating -p/-u on unrelated programs (mkdir -p, cp -p, scp -p, ssh -p,
  // docker -p, sort -u, git push -u, psql/redis-cli -p are a port or a flag, not a secret). One value shape for every
  // rule below: a quoted run (it may hold spaces) or the next whitespace-delimited word; a quote with no closer falls
  // back to the word. The separator between a long option and its value is a space OR `=`; a short option's value may
  // also be attached (`-uadmin:pw`). Every pattern is anchored at a whitespace/start boundary and uses only
  // single-level quantifiers, so a hostile run of flags or quotes stays linear (see the 20000-char test).
  // --password x / --password=x, --token, --api-key, --secret, --auth, curl's --oauth2-bearer and the wget/ftp/proxy
  // password options (any program):
  [/((?:^|\s)(?:--password|--passwd|--passphrase|--token|--api-key|--secret|--auth|--oauth2-bearer|--http-password|--ftp-password|--proxy-password)(?:\s+|=))("[^"]*"|'[^']*'|\S+)/gi, `$1${REDACTED}`],
  // wget/curl user names that only exist next to a password: any value.
  [/((?:^|\s)(?:--http-user|--ftp-user|--proxy-user|--proxy-username)(?:\s+|=))("[^"]*"|'[^']*'|\S+)/gi, `$1${REDACTED}`],
  // -u/-U and --user/--username only for a user:pass shape (a bare `--user x`, `-U app`, `sort -u`, `git push -u` are not
  // credentials). A standalone flag takes any program, as before. The numeric `uid:gid` form is not a credential.
  [/((?:^|\s)(?:-[uU]\s+|--user(?:name)?(?:\s+|=)))("[^":]{0,256}:[^"]*"|'[^':]{0,256}:[^']*'|(?!\d+:\d+(?:[\s"']|$))\S*:\S+)/g, `$1${REDACTED}`],
  // A curl-bundled user:pw (`-sSu user:pw`) or attached value (`-uuser:pw`). Only under curl: `ls -lu a:b` is not a
  // credential. The gap runs to the next `curl` word, so each character is scanned once (linear) and a flag anywhere in the
  // command is still caught.
  [/(\bcurl\b(?:(?!\bcurl\b)[^|;&\n])*?(?:^|\s)-[sSvkLgfnqNiJ]{0,8}[uU]\s*)("[^":]{0,256}:[^"]*"|'[^':]{0,256}:[^']*'|(?!\d+:\d+(?:[\s"']|$))\S*:\S+)/g, `$1${REDACTED}`],
  // Cookie headers: `-H 'Cookie: a=b'`, `-HCookie:`, `--header Cookie:`, or a `Set-Cookie:` line at a line start. Prose such
  // as `echo "fix: cookie: expiry"` is not a header and stays. The value runs to the end of the line or the closing quote.
  [/((?:^[ \t]*|(?:^|\s)-H[ \t]*["']?|(?:^|\s)--header(?:[ \t]+|=)["']?)(?:set-)?cookie[ \t]*:[ \t]*)[^\r\n"']+/gim, `$1${REDACTED}`],
  // --cookie takes a name=value string anywhere. Short -b is curl-only: `make -b a=b` and `git checkout -b x=y` are flags.
  [/((?:^|\s)--cookie(?:\s+|=))("[^"=]*=[^"]*"|'[^'=]*=[^']*'|[^\s"']*=\S*)/g, `$1${REDACTED}`],
  [/(\bcurl\b(?:(?!\bcurl\b)[^|;&\n])*?(?:^|\s)-b(?!ench)\s*)("[^"=]*=[^"]*"|'[^'=]*=[^']*'|[^\s"']*=\S*)/g, `$1${REDACTED}`],
  // docker login -p / --password: `-p` is the password only under `docker login` (docker run -p is a port map). The gap runs
  // to the next docker word, so each character is scanned once (linear).
  [/(\bdocker\s+login\b(?:(?!\bdocker\b)[^|;&\n])*?\s-p(?:\s+|=))("[^"]*"|'[^']*'|\S+)/gi, `$1${REDACTED}`],
  // redis-cli -a / --pass is its password option (`-h host` and `ping` are not). The gap runs to the next redis-cli word.
  [/(\bredis-cli\b(?:(?!\bredis-cli\b)[^|;&\n])*?\s(?:-a|--pass)(?:\s+|=))("[^"]*"|'[^']*'|\S+)/gi, `$1${REDACTED}`],
  // npm's space-separated `//host/:_authToken value` (the `=` form is caught by the name rule above).
  [/(_authtoken\s+)(\S+)/gi, `$1${REDACTED}`],
  // The gap runs to the next mysql-family word, not a fixed length. Each `mysql` scan therefore covers only the text up to the
  // next family word, so every character is scanned once (linear). A `-p` anywhere before the next family word is still caught.
  [/(\b(?:mysql|mariadb|mysqldump|mongosh|sshpass|smbclient)\b(?:(?!\b(?:mysql|mariadb|mysqldump|mongosh|sshpass|smbclient)\b)[^|;&\n])*?\s-p\s*)("[^"]*"|'[^']*'|\S+)/gi, `$1${REDACTED}`],
  [/((?:aws_)?secret_access_key\s+)(\S+)/gi, `$1${REDACTED}`],
  [/\b([a-z][a-z0-9+.-]{0,63}:\/\/)[^\s/@:]*:[^\s/]+@/gi, `$1${REDACTED}@`],
  [/\bsk-[A-Za-z0-9_-]{8,}/g, REDACTED],
  [/\bapikey_[A-Za-z0-9_]+/g, REDACTED],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}/g, REDACTED],
  [/\bnpm_[A-Za-z0-9]{30,}/g, REDACTED],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, REDACTED],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, REDACTED],
  [/\bAKIA[0-9A-Z]{16}\b/g, REDACTED],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, REDACTED],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, REDACTED],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, REDACTED],
];

/** Scrub credentials before anything is sent to Jev. Never throws; over-redacts on failure. */
function redact(text) {
  if (typeof text !== 'string') return '';
  try {
    let out = text;
    for (const [re, rep] of SECRET_RULES) out = out.replace(re, rep);
    return out;
  } catch { return REDACTED; }
}

/** Redact first, truncate second, so a secret straddling the cut is not half-leaked. */
const redactCap = (text, limit) => redact(text).slice(0, limit);

module.exports = { redact, redactCap };
