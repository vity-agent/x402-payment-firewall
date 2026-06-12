import { randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { canonicalizeUrl, domainMatches, normalizedHostname } from "./canonicalize.js";
import { createPaymentFingerprint } from "./fingerprint.js";
import { MemoryAuditSink, MemoryBudgetStore, MemoryDuplicateStore, parseAtomicAmount } from "./stores.js";
import type {
  AmountLimit,
  AuditEvent,
  AuditSink,
  FirewallDecision,
  FirewallPolicy,
  PaymentEvaluationInput,
  PaymentOutcome,
} from "./types.js";

interface PendingDecision {
  event: AuditEvent;
  fingerprint: string;
  budgetReserved: boolean;
}

export interface PaymentFirewallOptions {
  policy: FirewallPolicy;
  auditSink?: AuditSink;
  now?: () => Date;
}

export class PaymentFirewall {
  readonly #policy: FirewallPolicy;
  readonly #audit: AuditSink;
  readonly #now: () => Date;
  readonly #duplicates = new MemoryDuplicateStore();
  readonly #budgets = new MemoryBudgetStore();
  readonly #pending = new Map<string, PendingDecision>();

  constructor(options: PaymentFirewallOptions) {
    this.#policy = options.policy;
    this.#audit = options.auditSink ?? new MemoryAuditSink();
    this.#now = options.now ?? (() => new Date());
  }

  async evaluate(input: PaymentEvaluationInput): Promise<FirewallDecision> {
    const now = this.#now();
    const decisionId = randomUUID();
    const fingerprint = createPaymentFingerprint(input);
    const requirement = input.selectedRequirements;
    const reasons = this.validate(input);
    const ttlMs = this.#policy.duplicateTtlMs ?? 5 * 60_000;
    const expiresAtMs = now.getTime() + ttlMs;

    let duplicateReserved = false;
    let budgetReserved = false;

    if (reasons.length === 0) {
      duplicateReserved = this.#duplicates.reserve(fingerprint, expiresAtMs, now.getTime());
      if (!duplicateReserved) reasons.push("duplicate payment request");
    }

    const dailyLimit = findLimit(this.#policy.dailyBudgets, requirement.network, requirement.asset);
    if (reasons.length === 0 && dailyLimit) {
      budgetReserved = this.#budgets.reserve(decisionId, dailyLimit, requirement.amount, now);
      if (!budgetReserved) reasons.push("daily budget exceeded");
    }

    if (reasons.length > 0 && duplicateReserved) this.#duplicates.release(fingerprint);

    const decision: FirewallDecision = {
      decision: reasons.length === 0 ? "allow" : "deny",
      decisionId,
      riskScore: reasons.length === 0 ? 0 : Math.min(100, 60 + reasons.length * 10),
      reasons,
      fingerprint,
      expiresAt: new Date(expiresAtMs).toISOString(),
    };

    const event = this.createAuditEvent(input, decision, now);
    if (decision.decision === "allow") {
      this.#pending.set(decisionId, { event, fingerprint, budgetReserved });
    }
    await this.#audit.write(event);
    return decision;
  }

  async finalize(decisionId: string, outcome: PaymentOutcome): Promise<void> {
    const pending = this.#pending.get(decisionId);
    if (!pending) throw new Error(`Unknown or finalized decision: ${decisionId}`);

    if (outcome === "settled") {
      if (pending.budgetReserved) this.#budgets.settle(decisionId);
    } else {
      if (pending.budgetReserved) this.#budgets.release(decisionId);
      this.#duplicates.release(pending.fingerprint);
    }

    this.#pending.delete(decisionId);
    await this.#audit.write({ ...pending.event, timestamp: this.#now().toISOString(), outcome });
  }

  private validate(input: PaymentEvaluationInput): string[] {
    const reasons: string[] = [];
    const requirement = input.selectedRequirements;
    const policy = this.#policy;

    if (input.paymentRequired.x402Version !== 2) reasons.push("unsupported x402 version");
    if (!input.paymentRequired.accepts.some(accepted => requirementsEqual(accepted, requirement))) {
      reasons.push("selected payment requirements were not advertised by the server");
    }

    let resourceHost: string | undefined;
    try {
      resourceHost = normalizedHostname(input.paymentRequired.resource.url);
    } catch {
      reasons.push("invalid resource URL");
    }

    if (resourceHost && policy.allowedDomains?.length &&
        !policy.allowedDomains.some(domain => domainMatches(resourceHost!, domain))) {
      reasons.push("resource domain is not allowed");
    }

    if (resourceHost && (policy.bindRequestDomain ?? true)) {
      if (!input.request.url) {
        reasons.push("request URL is required for resource binding");
      } else {
        try {
          if (canonicalizeUrl(input.request.url) !== canonicalizeUrl(input.paymentRequired.resource.url)) {
            reasons.push("payment resource does not match request URL");
          }
        } catch {
          reasons.push("invalid request URL");
        }
      }
    }

    if (policy.allowedNetworks?.length && !policy.allowedNetworks.includes(requirement.network)) {
      reasons.push("network is not allowed");
    }
    if (policy.allowedAssets?.length && !includesCaseInsensitive(policy.allowedAssets, requirement.asset)) {
      reasons.push("asset is not allowed");
    }
    if (policy.allowedSchemes?.length && !policy.allowedSchemes.includes(requirement.scheme)) {
      reasons.push("scheme is not allowed");
    }
    if (policy.allowedRecipients?.length && !includesCaseInsensitive(policy.allowedRecipients, requirement.payTo)) {
      reasons.push("recipient is not allowed");
    }

    if (resourceHost && policy.recipientPins) {
      const pins = Object.entries(policy.recipientPins)
        .find(([domain]) => domainMatches(resourceHost!, domain))?.[1];
      if (pins && !includesCaseInsensitive(pins, requirement.payTo)) {
        reasons.push("recipient does not match domain pin");
      }
    }

    const requestLimit = findLimit(policy.maxPerRequest, requirement.network, requirement.asset);
    if (requestLimit) {
      try {
        if (parseAtomicAmount(requirement.amount) > parseAtomicAmount(requestLimit.amount)) {
          reasons.push("amount exceeds per-request limit");
        }
      } catch {
        reasons.push("invalid payment amount");
      }
    } else {
      try {
        parseAtomicAmount(requirement.amount);
      } catch {
        reasons.push("invalid payment amount");
      }
    }

    return reasons;
  }

  private createAuditEvent(
    input: PaymentEvaluationInput,
    decision: FirewallDecision,
    now: Date,
  ): AuditEvent {
    const requirement = input.selectedRequirements;
    return {
      timestamp: now.toISOString(),
      decisionId: decision.decisionId,
      decision: decision.decision,
      fingerprint: decision.fingerprint,
      agentId: input.request.agentId,
      resourceUrl: input.paymentRequired.resource.url,
      network: requirement.network,
      asset: requirement.asset,
      amount: requirement.amount,
      payTo: requirement.payTo,
      reasons: decision.reasons,
    };
  }
}

function requirementsEqual(left: PaymentEvaluationInput["selectedRequirements"], right: PaymentEvaluationInput["selectedRequirements"]): boolean {
  return left.scheme === right.scheme &&
    left.network === right.network &&
    left.amount === right.amount &&
    left.asset.toLowerCase() === right.asset.toLowerCase() &&
    left.payTo.toLowerCase() === right.payTo.toLowerCase() &&
    left.maxTimeoutSeconds === right.maxTimeoutSeconds &&
    isDeepStrictEqual(left.extra, right.extra);
}

function includesCaseInsensitive(values: string[], candidate: string): boolean {
  const normalized = candidate.toLowerCase();
  return values.some(value => value.toLowerCase() === normalized);
}

function findLimit(
  limits: AmountLimit[] | undefined,
  network: string,
  asset: string,
): AmountLimit | undefined {
  return limits?.find(limit =>
    limit.network === network && limit.asset.toLowerCase() === asset.toLowerCase());
}
