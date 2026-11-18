import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";

// DROP statements a SQL client reads on stdin. Data only: every string is handed to guardCommand(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, noJev);
const expectAll = async (cmds, want) => { for (const c of cmds) { const r = await g(c); assert.equal(r.decision, want, `${JSON.stringify(c)} -> ${r.decision} ${r.rule ?? ""}`); } };

test("a DROP fed to a SQL client through a heredoc or a pipe asks, like `psql -c 'DROP TABLE x'`", async () => {
  await expectAll([
    "psql <<EOF\nDROP TABLE users;\nEOF", "psql \"$DATABASE_URL\" <<'SQL'\ndrop schema public cascade;\nSQL", "mysql -u root app <<-EOF\n\tDROP DATABASE prod;\nEOF",
    "echo 'DROP TABLE x' | psql", "printf 'DROP TABLE x;' | psql", "echo 'drop database prod' | mysql -u root", "echo 'DROP TABLE x' | sqlite3 app.db",
    "cat <<< 'DROP TABLE users' | mysql", "echo 'DROP TABLE x' | tee /dev/stderr | psql", "cat <<EOF | psql\nDROP TABLE x;\nEOF",
  ], "ask");
});
test("non-destructive SQL on stdin, and DROP text that never reaches a client, stay allowed", async () => {
  await expectAll([
    "echo 'select 1' | psql", "psql <<EOF\nSELECT * FROM users;\nEOF", "grep -n 'DROP TABLE' migrations/*.sql", "echo 'DROP TABLE x' > notes.txt",
    "cat <<EOF > drop.sql\nDROP TABLE x;\nEOF", "echo 'DROP TABLE x' | wc -c", "psql -c 'select 1'; echo 'DROP TABLE is dangerous'",
  ], "allow");
});
