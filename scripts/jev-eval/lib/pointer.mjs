// RFC 6901 JSON Pointer read access. "" is the whole document; a missing path is undefined.
export function pointerGet(doc, pointer) {
  if (pointer === "" || pointer === undefined) return doc;
  if (typeof pointer !== "string" || pointer[0] !== "/") throw new Error(`not a JSON pointer: ${String(pointer).slice(0, 40)}`);
  let cur = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (cur === null || typeof cur !== "object" || !Object.hasOwn(cur, key)) return undefined;
    cur = cur[key];
  }
  return cur;
}
