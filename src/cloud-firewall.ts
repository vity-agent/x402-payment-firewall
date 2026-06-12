import type { PoolClient } from "pg";

import { createAuthorizationToken, verifyAuthorizationToken } from "./authorization-token.js";
import { ApiError, type AuthenticatedTenant } from "./cloud-auth.js";
import { withTransaction } from "./database.js";
import { PaymentFirewall } from "./firewall.js";
import { createPaymentFingerprint } from "./fingerprint.js";
import { parseFirewallPolicy, parsePaymentEvaluationInput } from "./hosted-api.js";
import type { AmountLimit, FirewallDecision, FirewallPolicy, PaymentEvaluationInput } from "./types.js";

interface PolicyRow {
  id: string;
  name: string;
  config: FirewallPolicy;
  active: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface CloudEvaluationResponse {
  mode: "enforced";
  policyId: string;
  decision: FirewallDecision;
  authorizationToken?: string;
  reservation?: {
    amount: string;
    expiresAt: string;
  };
}

export async function createPolicy(
  auth: AuthenticatedTenant,
  body: unknown,
): Promise<Record<string, unknown>> {
  assertBodySize(body);
  if (!isRecord(body)) throw new ApiError(400, "invalid_request", "request body must be an object");
  rejectUnknownFields(body, ["name", "policy"]);
  const name = parseName(body.name);
  const policy = parseUserInput(() => parseFirewallPolicy(body.policy));
  if (Object.keys(policy).length === 0) {
    throw new ApiError(400, "invalid_policy", "policy must contain at least one rule");
  }
  if (policy.duplicateTtlMs !== undefined && policy.duplicateTtlMs < 30_000) {
    throw new ApiError(400, "invalid_policy", "cloud duplicateTtlMs must be at least 30000");
  }

  const result = await withTransaction(async client => {
    const inserted = await client.query<PolicyRow>(
      `INSERT INTO policies (tenant_id, name, config)
       VALUES ($1, $2, $3)
       RETURNING id, name, config, active, created_at, updated_at`,
      [auth.tenantId, name, policy],
    );
    const row = inserted.rows[0];
    if (!row) throw new Error("policy insert returned no row");
    await writeAudit(client, auth.tenantId, null, "policy.created", { policyId: row.id, name });
    return row;
  });

  return serializePolicy(result);
}

export async function getPolicy(
  auth: AuthenticatedTenant,
  policyId: string,
): Promise<Record<string, unknown>> {
  assertUuid(policyId, "policyId");
  const result = await withTransaction(client => client.query<PolicyRow>(
    `SELECT id, name, config, active, created_at, updated_at
       FROM policies
      WHERE id = $1 AND tenant_id = $2`,
    [policyId, auth.tenantId],
  ));
  const row = result.rows[0];
  if (!row) throw new ApiError(404, "policy_not_found", "policy not found");
  return serializePolicy(row);
}

export async function evaluateCloudPayment(
  auth: AuthenticatedTenant,
  body: unknown,
): Promise<CloudEvaluationResponse> {
  assertBodySize(body);
  if (!isRecord(body)) throw new ApiError(400, "invalid_request", "request body must be an object");
  rejectUnknownFields(body, ["policyId", "input"]);
  const policyId = parseUuid(body.policyId, "policyId");
  const input = parseUserInput(() => parsePaymentEvaluationInput(body.input));
  const signingSecret = process.env.FIREWALL_SIGNING_SECRET;
  if (!signingSecret || signingSecret.length < 32) {
    throw new ApiError(503, "service_not_configured", "firewall signing is not configured");
  }

  const result = await withTransaction(async client => {
    const policy = await lockPolicy(client, auth.tenantId, policyId);
    const fingerprint = createPaymentFingerprint(input);
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
      `${auth.tenantId}:${fingerprint}`,
    ]);
    await client.query(
      `UPDATE decisions
          SET status = 'expired'
        WHERE tenant_id = $1 AND status = 'reserved' AND reserved_until <= now()`,
      [auth.tenantId],
    );

    const { dailyBudgets: _daily, duplicateTtlMs: _ttl, ...statelessPolicy } = policy.config;
    const firewall = new PaymentFirewall({ policy: statelessPolicy });
    let decision = await firewall.evaluate(input);

    const duplicate = await client.query<{ id: string }>(
      `SELECT id FROM decisions
        WHERE tenant_id = $1 AND fingerprint = $2 AND status IN ('reserved', 'settled')
        LIMIT 1`,
      [auth.tenantId, fingerprint],
    );
    if (decision.decision === "allow" && duplicate.rowCount) {
      decision = denyDecision(decision, "duplicate payment request");
    }

    const dailyLimit = findLimit(policy.config.dailyBudgets, input);
    if (decision.decision === "allow" && dailyLimit) {
      const spent = await sumDailySpend(client, policy.id, input);
      if (spent + BigInt(input.selectedRequirements.amount) > BigInt(dailyLimit.amount)) {
        decision = denyDecision(decision, "daily budget exceeded");
      }
    }

    if (decision.decision !== "allow") {
      await insertDecision(client, auth.tenantId, policy, input, decision, "denied", null);
      await writeAudit(client, auth.tenantId, decision.decisionId, "decision.denied", {
        fingerprint,
        reasons: decision.reasons,
      });
      return { policy, decision };
    }

    const ttlMs = Math.min(Math.max(policy.config.duplicateTtlMs ?? 300_000, 30_000), 900_000);
    const expiresAt = new Date(Date.now() + ttlMs);
    await insertDecision(client, auth.tenantId, policy, input, decision, "reserved", expiresAt);
    await writeAudit(client, auth.tenantId, decision.decisionId, "decision.reserved", {
      fingerprint,
      expiresAt: expiresAt.toISOString(),
    });
    return { policy, decision, expiresAt };
  });

  if (!result.expiresAt) {
    return { mode: "enforced", policyId, decision: result.decision };
  }

  const claims = {
    decisionId: result.decision.decisionId,
    tenantId: auth.tenantId,
    policyId,
    fingerprint: result.decision.fingerprint,
    exp: Math.floor(result.expiresAt.getTime() / 1000),
  };
  return {
    mode: "enforced",
    policyId,
    decision: result.decision,
    authorizationToken: createAuthorizationToken(claims),
    reservation: {
      amount: input.selectedRequirements.amount,
      expiresAt: result.expiresAt.toISOString(),
    },
  };
}

export async function finalizeCloudDecision(
  auth: AuthenticatedTenant,
  body: unknown,
): Promise<Record<string, unknown>> {
  assertBodySize(body);
  if (!isRecord(body)) throw new ApiError(400, "invalid_request", "request body must be an object");
  rejectUnknownFields(body, ["decisionId", "authorizationToken", "outcome"]);
  const decisionId = parseUuid(body.decisionId, "decisionId");
  if (typeof body.authorizationToken !== "string" || body.authorizationToken.length > 4096) {
    throw new ApiError(400, "invalid_request", "authorizationToken is required");
  }
  if (body.outcome !== "settled" && body.outcome !== "cancelled") {
    throw new ApiError(400, "invalid_request", "outcome must be settled or cancelled");
  }
  const claims = verifyAuthorizationToken(body.authorizationToken);
  if (claims.decisionId !== decisionId || claims.tenantId !== auth.tenantId) {
    throw new ApiError(401, "invalid_authorization", "authorization token does not match decision");
  }

  return withTransaction(async client => {
    const result = await client.query<{
      id: string;
      status: string;
      fingerprint: string;
      policy_id: string;
    }>(
      `SELECT id, status, fingerprint, policy_id
         FROM decisions
        WHERE id = $1 AND tenant_id = $2
        FOR UPDATE`,
      [decisionId, auth.tenantId],
    );
    const decision = result.rows[0];
    if (!decision) throw new ApiError(404, "decision_not_found", "decision not found");
    if (decision.policy_id !== claims.policyId || decision.fingerprint !== claims.fingerprint) {
      throw new ApiError(401, "invalid_authorization", "authorization token does not match decision");
    }
    if (decision.status !== "reserved") {
      throw new ApiError(409, "invalid_decision_state", `decision is already ${decision.status}`);
    }

    const status = body.outcome;
    await client.query(
      status === "settled"
        ? `UPDATE decisions SET status = 'settled', settled_at = now() WHERE id = $1`
        : `UPDATE decisions SET status = 'cancelled', cancelled_at = now() WHERE id = $1`,
      [decisionId],
    );
    await writeAudit(client, auth.tenantId, decisionId, `decision.${status}`, {});
    return { decisionId, status };
  });
}

async function lockPolicy(client: PoolClient, tenantId: string, policyId: string): Promise<PolicyRow> {
  const result = await client.query<PolicyRow>(
    `SELECT id, name, config, active, created_at, updated_at
       FROM policies
      WHERE id = $1 AND tenant_id = $2
      FOR UPDATE`,
    [policyId, tenantId],
  );
  const policy = result.rows[0];
  if (!policy) throw new ApiError(404, "policy_not_found", "policy not found");
  if (!policy.active) throw new ApiError(409, "policy_inactive", "policy is inactive");
  policy.config = parseFirewallPolicy(policy.config);
  return policy;
}

async function insertDecision(
  client: PoolClient,
  tenantId: string,
  policy: PolicyRow,
  input: PaymentEvaluationInput,
  decision: FirewallDecision,
  status: "denied" | "reserved",
  expiresAt: Date | null,
): Promise<void> {
  const requirement = input.selectedRequirements;
  await client.query(
    `INSERT INTO decisions (
       id, tenant_id, policy_id, fingerprint, decision, status, risk_score, reasons,
       network, asset, amount, pay_to, request_context, policy_snapshot,
       reserved_until, authorization_expires_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`,
    [
      decision.decisionId,
      tenantId,
      policy.id,
      decision.fingerprint,
      decision.decision,
      status,
      decision.riskScore,
      JSON.stringify(decision.reasons),
      requirement.network,
      requirement.asset,
      requirement.amount,
      requirement.payTo,
      input.request,
      policy.config,
      expiresAt,
    ],
  );
}

async function sumDailySpend(
  client: PoolClient,
  policyId: string,
  input: PaymentEvaluationInput,
): Promise<bigint> {
  const requirement = input.selectedRequirements;
  const result = await client.query<{ total: string }>(
    `SELECT COALESCE(SUM(amount), 0)::text AS total
       FROM decisions
      WHERE policy_id = $1
        AND network = $2
        AND lower(asset) = lower($3)
        AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
        AND (status = 'settled' OR (status = 'reserved' AND reserved_until > now()))`,
    [policyId, requirement.network, requirement.asset],
  );
  return BigInt(result.rows[0]?.total ?? "0");
}

function findLimit(limits: AmountLimit[] | undefined, input: PaymentEvaluationInput): AmountLimit | undefined {
  const requirement = input.selectedRequirements;
  return limits?.find(limit => limit.network === requirement.network &&
    limit.asset.toLowerCase() === requirement.asset.toLowerCase());
}

function denyDecision(decision: FirewallDecision, reason: string): FirewallDecision {
  return {
    ...decision,
    decision: "deny",
    riskScore: Math.max(decision.riskScore, 70),
    reasons: [...decision.reasons, reason],
  };
}

async function writeAudit(
  client: PoolClient,
  tenantId: string,
  decisionId: string | null,
  eventType: string,
  details: Record<string, unknown>,
): Promise<void> {
  await client.query(
    `INSERT INTO audit_events (tenant_id, decision_id, event_type, details)
     VALUES ($1, $2, $3, $4)`,
    [tenantId, decisionId, eventType, details],
  );
}

function serializePolicy(row: PolicyRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    policy: row.config,
    active: row.active,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

function parseName(value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 100) {
    throw new ApiError(400, "invalid_request", "name must be 1-100 characters");
  }
  return value.trim();
}

function parseUuid(value: unknown, field: string): string {
  if (typeof value !== "string") throw new ApiError(400, "invalid_request", `${field} is required`);
  assertUuid(value, field);
  return value;
}

function assertUuid(value: string, field: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new ApiError(400, "invalid_request", `${field} must be a UUID`);
  }
}

function rejectUnknownFields(value: Record<string, unknown>, allowed: string[]): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).find(key => !allowedSet.has(key));
  if (unknown) throw new ApiError(400, "invalid_request", `unknown field: ${unknown}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertBodySize(body: unknown): void {
  let bytes: number;
  try {
    bytes = Buffer.byteLength(JSON.stringify(body ?? null), "utf8");
  } catch {
    throw new ApiError(400, "invalid_request", "request body must be valid JSON");
  }
  if (bytes > 64 * 1024) throw new ApiError(413, "payload_too_large", "request body exceeds 64 KiB");
}

function parseUserInput<T>(parser: () => T): T {
  try {
    return parser();
  } catch (error) {
    throw new ApiError(400, "invalid_request", error instanceof Error ? error.message : "invalid request");
  }
}
