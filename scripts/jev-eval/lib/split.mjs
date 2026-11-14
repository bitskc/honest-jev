// Stable train/holdout split. A row is holdout iff the first four bytes (big-endian uint32) of
// sha256(salt ? `${salt}:${key}` : key), taken mod 100, are below holdout_pct. Adding rows never moves an existing row;
// rows sharing a split key (a thread, a session) always land together. With salt "" and key `${channel}:${thread}` this is a
// thread-level split, so a deployment can reproduce an existing thread-level split of the same form.
import { createHash } from "node:crypto";
import { pointerGet } from "./pointer.mjs";

export function bucket(key, salt = "") {
  const text = salt ? `${salt}:${key}` : String(key);
  return createHash("sha256").update(text).digest().readUInt32BE(0) % 100;
}

/** "train" | "holdout". A precomputed split field (suite.split.field) wins when it holds one of those two words. */
export function splitOf(row, suite, id = row.id) {
  const s = suite.split;
  if (s.field) {
    const v = pointerGet(row, s.field);
    if (v === "train" || v === "holdout") return v;
  }
  const key = pointerGet(row, s.key);
  return bucket(typeof key === "string" || typeof key === "number" ? key : id, s.salt) < s.holdout_pct ? "holdout" : "train";
}
