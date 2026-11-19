// The 12 jev_* tools server/build-vendor.sh vendors from jkudish/jev-mcp, by name. The vendor script pins the commit;
// this pins what that commit must expose. server/test/tools-doc.test.mjs checks this list against the live tools/list,
// so a pin bump that adds, drops or renames a tool fails there instead of only on a deployed Worker.
export const UPSTREAM_TOOL_NAMES = [
  "jev_verify", "jev_screen", "jev_noul", "jev_find", "jev_classify", "jev_decide",
  "jev_rerank", "jev_compare", "jev_extract", "jev_audit", "jev_review", "jev_gate",
];
