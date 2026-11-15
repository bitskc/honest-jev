#!/usr/bin/env node
// PreToolUse: redact jev_classify item text before it reaches upstream (Q7 redact-or-refuse).
// Matcher should include MCP tool names that end in jev_classify. Fails open on parse errors.
'use strict';
const fs = require('fs');
const { redact } = require('./jev-redact.js');

function readStdin() {
  return new Promise((resolve) => {
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.resume();
  });
}

function toolName(input) {
  return String(input.tool_name || input.toolName || input.name || '');
}

function isClassify(name) {
  return /(^|__)jev_classify$/.test(name) || name === 'jev_classify';
}

(async () => {
  let raw = '';
  try { raw = await readStdin(); } catch { process.exit(0); }
  let input;
  try { input = JSON.parse(raw || '{}'); } catch { process.exit(0); }
  if (!isClassify(toolName(input))) {
    process.stdout.write(JSON.stringify({ decision: 'allow' }));
    process.exit(0);
  }
  const args = input.tool_input || input.arguments || input.input || {};
  const items = Array.isArray(args.items) ? args.items : null;
  if (!items) {
    process.stdout.write(JSON.stringify({ decision: 'allow' }));
    process.exit(0);
  }
  let dropped = 0;
  const next = [];
  for (const it of items) {
    if (!it || typeof it !== 'object') continue;
    const text = redact(String(it.text || ''));
    // Refuse empty/secret-stripped-only evidence: if redact emptied a non-empty claim body, drop as not verified.
    if (!text.trim()) { dropped++; continue; }
    next.push({ ...it, text });
  }
  const outArgs = { ...args, items: next };
  // Claude Code PreToolUse updatedInput shape
  const payload = {
    decision: 'allow',
    updatedInput: outArgs,
  };
  if (dropped) payload.systemMessage = `honest-jev: dropped ${dropped} jev_classify item(s) after redact-or-refuse`;
  process.stdout.write(JSON.stringify(payload));
})().catch(() => process.exit(0));
