// GET /health. The body is always "ok" (install.sh --doctor and every uptime check read it). A caller that proved it holds the bearer
// token also gets the rules fingerprint in a header, so a hook can tell whether the rules it runs locally are the ones this Worker runs.
// An unauthenticated caller, or one with a wrong token, learns nothing about the deployed rules.
import { RULES_FINGERPRINT } from "./rules-fingerprint.mjs";

export const FINGERPRINT_HEADER = "x-jev-rules-fingerprint";

const enc = new TextEncoder();
async function sha(s) { return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))); }

/** Constant-time comparison of the Authorization header's bearer token with the expected one (compared as SHA-256 digests). */
export async function tokenOk(header, expected) {
  if (!expected) return false;
  const given = header && header.startsWith("Bearer ") ? header.slice(7) : "";
  const [a, b] = await Promise.all([sha(given), sha(expected)]);
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export async function handleHealth(request, env) {
  const authorized = await tokenOk(request.headers.get("authorization"), env?.MCP_BEARER_TOKEN);
  return new Response("ok", authorized ? { headers: { [FINGERPRINT_HEADER]: RULES_FINGERPRINT, "cache-control": "no-store" } } : undefined);
}
