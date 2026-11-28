import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";

// Secret-manager / keychain CLIs that print a stored secret. Data only: every string is handed to guardCommand(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, noJev);
const expectAll = async (cmds, want) => { for (const c of cmds) { const r = await g(c); assert.equal(r.decision, want, `${c} -> ${r.decision} ${r.rule ?? ""}`); } };

test("CLIs whose job is printing a stored secret no longer ask (owner shrink; store reads still block)", async () => {
  await expectAll([
    "pass show github", "pass github/token", "gopass show -o db/prod", "vault kv get secret/app", "vault kv get -field=token kv/app", "vault read secret/x",
    "aws secretsmanager get-secret-value --secret-id prod/db", "aws --profile p secretsmanager get-secret-value --secret-id x",
    "aws ssm get-parameter --name /app/key --with-decryption", "gcloud secrets versions access latest --secret=db",
    "az keyvault secret show --vault-name v --name n", "security find-generic-password -s svc -w", "security find-internet-password -gs host",
    "security dump-keychain -d", "gpg --export-secret-keys -a", "gpg --armor --export-secret-key me", "printf 'protocol=https\\nhost=github.com\\n' | git credential fill",
    "op item get Login --reveal", "bw get password github", "lpass show github", "doppler secrets", "doppler secrets download --no-file",
    "kubectl get secret app -o yaml", "kubectl get secrets -o json", "env VAULT_ADDR=x vault kv get k/v",
  ], "allow");
});
test("listing, writing, clipboard-only and capture-into-a-variable forms stay allowed", async () => {
  await expectAll([
    "pass ls", "pass insert github", "pass -c github", "pass show -c github", "pass generate x 20", "vault kv list secret/", "vault kv put secret/x a=b", "vault status",
    "aws secretsmanager list-secrets", "aws ssm get-parameter --name /app/region", "az keyvault secret list --vault-name v",
    "security find-generic-password -s svc", "gpg --list-secret-keys", "gpg --export -a me", "git credential approve", "bw list items --search x",
    "doppler run -- npm start", "X=$(vault kv get -field=token kv/app)", "export T=\"$(op read op://v/item/field)\"",
  ], "allow");
});
