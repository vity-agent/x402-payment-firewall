import { Pool, type PoolClient } from "pg";

declare global {
  // eslint-disable-next-line no-var
  var __x402FirewallPool: Pool | undefined;
}

export function getDatabasePool(env: NodeJS.ProcessEnv = process.env): Pool {
  const connectionString = env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error("DATABASE_URL is required");

  if (!globalThis.__x402FirewallPool) {
    globalThis.__x402FirewallPool = new Pool({
      connectionString,
      max: 5,
      idleTimeoutMillis: 20_000,
      connectionTimeoutMillis: 10_000,
    });
  }
  return globalThis.__x402FirewallPool;
}

export async function withTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await getDatabasePool().connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
