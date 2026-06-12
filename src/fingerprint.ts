import { createHash } from "node:crypto";

import { canonicalizeUrl } from "./canonicalize.js";
import type { PaymentEvaluationInput } from "./types.js";

export function createPaymentFingerprint(input: PaymentEvaluationInput): string {
  const requirement = input.selectedRequirements;
  const requestUrl = input.request.url ?? input.paymentRequired.resource.url;
  const material = JSON.stringify({
    agentId: input.request.agentId,
    sessionId: input.request.sessionId ?? "",
    tool: input.request.tool ?? "",
    method: (input.request.method ?? "GET").toUpperCase(),
    url: canonicalizeUrl(requestUrl),
    bodyHash: input.request.bodyHash ?? "",
    scheme: requirement.scheme,
    network: requirement.network,
    amount: requirement.amount,
    asset: requirement.asset.toLowerCase(),
    payTo: requirement.payTo.toLowerCase(),
    maxTimeoutSeconds: requirement.maxTimeoutSeconds ?? null,
    extra: canonicalizeJson(requirement.extra ?? null),
  });

  return `sha256:${createHash("sha256").update(material).digest("hex")}`;
}

function canonicalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, canonicalizeJson(nested)]));
  }
  return value;
}
