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
  });

  return `sha256:${createHash("sha256").update(material).digest("hex")}`;
}
