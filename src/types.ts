export interface PaymentRequirementsLike {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
}

export interface PaymentRequiredLike {
  x402Version: number;
  resource: {
    url: string;
    description?: string;
    mimeType?: string;
  };
  accepts: PaymentRequirementsLike[];
  extensions?: Record<string, unknown>;
}

export interface RequestContext {
  agentId: string;
  sessionId?: string;
  tool?: string;
  intent?: string;
  method?: string;
  url?: string;
  bodyHash?: string;
}

export interface PaymentEvaluationInput {
  paymentRequired: PaymentRequiredLike;
  selectedRequirements: PaymentRequirementsLike;
  request: RequestContext;
}

export interface AmountLimit {
  network: string;
  asset: string;
  amount: string;
}

export interface FirewallPolicy {
  allowedDomains?: string[];
  allowedNetworks?: string[];
  allowedAssets?: string[];
  allowedSchemes?: string[];
  allowedRecipients?: string[];
  recipientPins?: Record<string, string[]>;
  maxPerRequest?: AmountLimit[];
  dailyBudgets?: AmountLimit[];
  bindRequestDomain?: boolean;
  duplicateTtlMs?: number;
}

export type DecisionKind = "allow" | "deny" | "review";

export interface FirewallDecision {
  decision: DecisionKind;
  decisionId: string;
  riskScore: number;
  reasons: string[];
  fingerprint: string;
  expiresAt: string;
}

export type PaymentOutcome = "settled" | "failed";

export interface AuditEvent {
  timestamp: string;
  decisionId: string;
  decision: DecisionKind;
  fingerprint: string;
  agentId: string;
  resourceUrl: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  reasons: string[];
  outcome?: PaymentOutcome;
}

export interface AuditSink {
  write(event: AuditEvent): Promise<void>;
}
