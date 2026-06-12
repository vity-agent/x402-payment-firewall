import { PaymentFirewall } from "./firewall.js";
import type { FirewallPolicy, PaymentEvaluationInput } from "./types.js";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_STRING_LENGTH = 2_048;
const MAX_LIST_LENGTH = 100;

export interface HostedEvaluateRequest {
  policy: FirewallPolicy;
  input: PaymentEvaluationInput;
}

export interface HostedApiConfig {
  paymentsEnabled: boolean;
  payToAddress?: string;
}

export interface HostedEvaluateResponse {
  mode: "free" | "paid";
  decision: Awaited<ReturnType<PaymentFirewall["evaluate"]>>;
  limitations: string[];
}

export function getHostedApiConfig(env: NodeJS.ProcessEnv = process.env): HostedApiConfig {
  const payToAddress = env.PAY_TO_ADDRESS?.trim();
  const paymentsEnabled = env.PAYMENTS_ENABLED?.toLowerCase() === "true"
    || (env.PAYMENTS_ENABLED === undefined && Boolean(payToAddress));

  if (payToAddress && !/^0x[a-fA-F0-9]{40}$/.test(payToAddress)) {
    throw new Error("PAY_TO_ADDRESS must be a valid EVM address");
  }

  return {
    paymentsEnabled,
    ...(payToAddress ? { payToAddress } : {}),
  };
}

export function parseHostedEvaluateRequest(body: unknown): HostedEvaluateRequest {
  if (Buffer.byteLength(JSON.stringify(body ?? null), "utf8") > MAX_BODY_BYTES) {
    throw new Error("request body exceeds 64 KiB");
  }
  if (!isRecord(body)) throw new Error("request body must be a JSON object");
  rejectUnknownFields(body, ["policy", "input"], "request body");
  if (!isRecord(body.policy)) throw new Error("policy must be an object");
  if (!isRecord(body.input)) throw new Error("input must be an object");

  parseFirewallPolicy(body.policy, true);
  parsePaymentEvaluationInput(body.input);
  return body as unknown as HostedEvaluateRequest;
}

export function parseFirewallPolicy(value: unknown, requireStatelessRule = false): FirewallPolicy {
  if (!isRecord(value)) throw new Error("policy must be an object");
  validatePolicy(value, requireStatelessRule);
  return value as unknown as FirewallPolicy;
}

export function parsePaymentEvaluationInput(value: unknown): PaymentEvaluationInput {
  if (!isRecord(value)) throw new Error("input must be an object");
  validateInput(value);
  return value as unknown as PaymentEvaluationInput;
}

export async function evaluateHostedRequest(
  request: HostedEvaluateRequest,
): Promise<HostedEvaluateResponse> {
  // Hosted mode intentionally excludes stateful controls. Those remain in the local SDK.
  const { dailyBudgets: _dailyBudgets, duplicateTtlMs: _duplicateTtlMs, ...staticPolicy } = request.policy;
  const statelessPolicy: FirewallPolicy = {
    ...staticPolicy,
  };
  const firewall = new PaymentFirewall({ policy: statelessPolicy });
  const decision = await firewall.evaluate(request.input);

  return {
    mode: "free",
    decision,
    limitations: [
      "daily budget enforcement is available only in the local SDK",
      "duplicate prevention is available only in the local SDK",
      "hosted decisions do not create or sign payment payloads",
    ],
  };
}

function validatePolicy(policy: Record<string, unknown>, requireStatelessRule: boolean): void {
  rejectUnknownFields(policy, [
    "allowedDomains",
    "allowedNetworks",
    "allowedAssets",
    "allowedSchemes",
    "allowedRecipients",
    "recipientPins",
    "maxPerRequest",
    "dailyBudgets",
    "bindRequestDomain",
    "duplicateTtlMs",
  ], "policy");
  validateStringArray(policy.allowedDomains, "allowedDomains");
  validateStringArray(policy.allowedNetworks, "allowedNetworks");
  validateStringArray(policy.allowedAssets, "allowedAssets");
  validateStringArray(policy.allowedSchemes, "allowedSchemes");
  validateStringArray(policy.allowedRecipients, "allowedRecipients");
  validateAmountLimits(policy.maxPerRequest, "maxPerRequest");
  validateAmountLimits(policy.dailyBudgets, "dailyBudgets");

  if (policy.bindRequestDomain !== undefined && typeof policy.bindRequestDomain !== "boolean") {
    throw new Error("bindRequestDomain must be a boolean");
  }
  if (policy.duplicateTtlMs !== undefined &&
      (!Number.isInteger(policy.duplicateTtlMs) || (policy.duplicateTtlMs as number) < 0 ||
       (policy.duplicateTtlMs as number) > 900_000)) {
    throw new Error("duplicateTtlMs must be an integer between 0 and 900000");
  }
  if (policy.recipientPins !== undefined) {
    if (!isRecord(policy.recipientPins)) throw new Error("recipientPins must be an object");
    for (const [domain, recipients] of Object.entries(policy.recipientPins)) {
      validateString(domain, "recipientPins domain");
      validateStringArray(recipients, `recipientPins.${domain}`, true);
    }
  }

  const hasEnforceableRule = [
    policy.allowedDomains,
    policy.allowedNetworks,
    policy.allowedAssets,
    policy.allowedSchemes,
    policy.allowedRecipients,
    policy.maxPerRequest,
  ].some(value => Array.isArray(value) && value.length > 0) ||
    (isRecord(policy.recipientPins) && Object.keys(policy.recipientPins).length > 0);

  if (requireStatelessRule && !hasEnforceableRule) {
    throw new Error("policy must include at least one stateless hosted rule");
  }
}

function validateInput(input: Record<string, unknown>): void {
  rejectUnknownFields(input, ["paymentRequired", "selectedRequirements", "request"], "input");
  if (!isRecord(input.paymentRequired)) throw new Error("input.paymentRequired must be an object");
  if (!isRecord(input.selectedRequirements)) throw new Error("input.selectedRequirements must be an object");
  if (!isRecord(input.request)) throw new Error("input.request must be an object");

  const paymentRequired = input.paymentRequired;
  rejectUnknownFields(paymentRequired, ["x402Version", "resource", "accepts", "extensions"], "paymentRequired");
  if (paymentRequired.x402Version !== 2) throw new Error("only x402Version 2 is supported");
  if (!isRecord(paymentRequired.resource)) throw new Error("paymentRequired.resource must be an object");
  rejectUnknownFields(paymentRequired.resource, ["url", "description", "mimeType"], "paymentRequired.resource");
  validateUrl(paymentRequired.resource.url, "paymentRequired.resource.url");
  validateOptionalString(paymentRequired.resource.description, "paymentRequired.resource.description");
  validateOptionalString(paymentRequired.resource.mimeType, "paymentRequired.resource.mimeType");

  if (!Array.isArray(paymentRequired.accepts) || paymentRequired.accepts.length === 0 ||
      paymentRequired.accepts.length > 20) {
    throw new Error("paymentRequired.accepts must contain 1-20 requirements");
  }
  for (const requirement of paymentRequired.accepts) validateRequirement(requirement);
  validateRequirement(input.selectedRequirements);
  if (paymentRequired.extensions !== undefined && !isRecord(paymentRequired.extensions)) {
    throw new Error("paymentRequired.extensions must be an object");
  }

  rejectUnknownFields(input.request, [
    "agentId",
    "sessionId",
    "tool",
    "intent",
    "method",
    "url",
    "bodyHash",
  ], "request");
  validateString(input.request.agentId, "request.agentId");
  validateOptionalString(input.request.sessionId, "request.sessionId");
  validateOptionalString(input.request.tool, "request.tool");
  validateOptionalString(input.request.intent, "request.intent");
  validateOptionalString(input.request.method, "request.method");
  validateUrl(input.request.url, "request.url");
  validateOptionalString(input.request.bodyHash, "request.bodyHash");
}

function validateRequirement(value: unknown): void {
  if (!isRecord(value)) throw new Error("payment requirement must be an object");
  rejectUnknownFields(value, [
    "scheme",
    "network",
    "amount",
    "asset",
    "payTo",
    "maxTimeoutSeconds",
    "extra",
  ], "payment requirement");
  validateString(value.scheme, "requirement.scheme");
  validateString(value.network, "requirement.network");
  validateAtomicAmount(value.amount, "requirement.amount");
  validateString(value.asset, "requirement.asset");
  validateString(value.payTo, "requirement.payTo");
  if (value.maxTimeoutSeconds !== undefined &&
      (!Number.isInteger(value.maxTimeoutSeconds) || (value.maxTimeoutSeconds as number) <= 0)) {
    throw new Error("requirement.maxTimeoutSeconds must be a positive integer");
  }
  if (value.extra !== undefined && !isRecord(value.extra)) {
    throw new Error("requirement.extra must be an object");
  }
}

function validateAmountLimits(value: unknown, field: string): void {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.length > MAX_LIST_LENGTH) {
    throw new Error(`${field} must be an array with at most ${MAX_LIST_LENGTH} entries`);
  }
  for (const limit of value) {
    if (!isRecord(limit)) throw new Error(`${field} entries must be objects`);
    rejectUnknownFields(limit, ["network", "asset", "amount"], `${field} entry`);
    validateString(limit.network, `${field}.network`);
    validateString(limit.asset, `${field}.asset`);
    validateAtomicAmount(limit.amount, `${field}.amount`);
  }
}

function validateStringArray(value: unknown, field: string, required = false): void {
  if (value === undefined && !required) return;
  if (!Array.isArray(value) || value.length > MAX_LIST_LENGTH) {
    throw new Error(`${field} must be an array with at most ${MAX_LIST_LENGTH} entries`);
  }
  for (const item of value) validateString(item, field);
}

function validateAtomicAmount(value: unknown, field: string): void {
  validateString(value, field);
  if (!/^(0|[1-9]\d*)$/.test(value as string)) throw new Error(`${field} must use atomic units`);
}

function validateUrl(value: unknown, field: string): void {
  validateString(value, field);
  const url = new URL(value as string);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`${field} must use http or https`);
  }
}

function validateOptionalString(value: unknown, field: string): void {
  if (value !== undefined) validateString(value, field);
}

function validateString(value: unknown, field: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_STRING_LENGTH) {
    throw new Error(`${field} must be a non-empty string up to ${MAX_STRING_LENGTH} characters`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownFields(value: Record<string, unknown>, allowed: string[], field: string): void {
  const allowedFields = new Set(allowed);
  const unknown = Object.keys(value).filter(key => !allowedFields.has(key));
  if (unknown.length > 0) throw new Error(`${field} contains unknown field: ${unknown[0]}`);
}
