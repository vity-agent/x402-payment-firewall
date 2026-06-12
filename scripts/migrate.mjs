import { readFile } from "node:fs/promises";
import { Client } from "pg";

import { loadLocalEnv } from "./env.mjs";

loadLocalEnv();
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required in .env.local");

const client = new Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
try {
  const migration = await readFile(new URL("../migrations/001_full_firewall.sql", import.meta.url), "utf8");
  await client.query(migration);
  process.stdout.write("Database migration completed.\n");
} finally {
  await client.end();
}
