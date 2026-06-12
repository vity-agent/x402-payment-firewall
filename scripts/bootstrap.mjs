import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, writeFile } from "node:fs/promises";
import { Client } from "pg";

import { loadLocalEnv } from "./env.mjs";

loadLocalEnv();
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required in .env.local");

if (!process.env.FIREWALL_SIGNING_SECRET) {
  const secret = randomBytes(48).toString("base64url");
  await appendFile(".env.local", `\nFIREWALL_SIGNING_SECRET=${secret}\n`, { encoding: "utf8" });
  process.env.FIREWALL_SIGNING_SECRET = secret;
}

if (existsSync(".firewall-credentials.json")) {
  process.stdout.write("Credentials already exist at .firewall-credentials.json; bootstrap skipped.\n");
  process.exit(0);
}

const apiKey = `x402fw_live_${randomBytes(32).toString("base64url")}`;
const keyHash = createHash("sha256").update(apiKey).digest("hex");
const client = new Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
try {
  await client.query("BEGIN");
  const tenant = await client.query(
    "INSERT INTO tenants (name) VALUES ($1) RETURNING id, name",
    ["vity-agent"],
  );
  const tenantRow = tenant.rows[0];
  await client.query(
    `INSERT INTO api_keys (tenant_id, name, key_prefix, key_hash)
     VALUES ($1, $2, $3, $4)`,
    [tenantRow.id, "initial", apiKey.slice(0, 20), keyHash],
  );
  await client.query("COMMIT");
  await writeFile(".firewall-credentials.json", JSON.stringify({
    tenantId: tenantRow.id,
    tenantName: tenantRow.name,
    apiKey,
    createdAt: new Date().toISOString(),
  }, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  process.stdout.write("Initial tenant and API key created in .firewall-credentials.json.\n");
} catch (error) {
  await client.query("ROLLBACK");
  throw error;
} finally {
  await client.end();
}
