import { createHash } from "node:crypto";

import type { ApiRequest } from "./api-types.js";
import { getDatabasePool } from "./database.js";

export interface AuthenticatedTenant {
  tenantId: string;
  apiKeyId: string;
}

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

export function hashApiKey(apiKey: string): string {
  return createHash("sha256").update(apiKey).digest("hex");
}

export async function authenticateRequest(request: ApiRequest): Promise<AuthenticatedTenant> {
  const header = request.headers.authorization;
  const authorization = Array.isArray(header) ? header[0] : header;
  if (!authorization?.startsWith("Bearer ")) {
    throw new ApiError(401, "unauthorized", "Authorization: Bearer <api-key> is required");
  }

  const apiKey = authorization.slice("Bearer ".length).trim();
  if (!apiKey.startsWith("x402fw_live_") || apiKey.length < 32) {
    throw new ApiError(401, "unauthorized", "invalid API key");
  }

  const result = await getDatabasePool().query<{
    id: string;
    tenant_id: string;
  }>(
    `UPDATE api_keys
       SET last_used_at = now()
     WHERE key_hash = $1 AND revoked_at IS NULL
     RETURNING id, tenant_id`,
    [hashApiKey(apiKey)],
  );
  const row = result.rows[0];
  if (!row) throw new ApiError(401, "unauthorized", "invalid or revoked API key");
  return { tenantId: row.tenant_id, apiKeyId: row.id };
}
