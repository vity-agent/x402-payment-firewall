import assert from "node:assert/strict";
import test from "node:test";

import { PaymentFirewall } from "../firewall.js";
import { MemoryAuditSink } from "../stores.js";
import type { PaymentEvaluationInput } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const MERCHANT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";

function payment(overrides: Partial<PaymentEvaluationInput["selectedRequirements"]> = {}): PaymentEvaluationInput {
  const selectedRequirements = {
    scheme: "exact",
    network: "eip155:84532",
    amount: "10000",
    asset: USDC,
    payTo: MERCHANT,
    ...overrides,
  };

  return {
    paymentRequired: {
      x402Version: 2,
      resource: { url: "https://api.example.com/weather", mimeType: "application/json" },
      accepts: [selectedRequirements],
    },
    selectedRequirements,
    request: {
      agentId: "agent-1",
      sessionId: "session-1",
      tool: "weather",
      method: "GET",
      url: "https://api.example.com/weather",
    },
  };
}

function createFirewall(auditSink = new MemoryAuditSink()): PaymentFirewall {
  return new PaymentFirewall({
    auditSink,
    policy: {
      allowedDomains: ["api.example.com"],
      allowedNetworks: ["eip155:84532"],
      allowedAssets: [USDC],
      allowedSchemes: ["exact"],
      allowedRecipients: [MERCHANT],
      recipientPins: { "api.example.com": [MERCHANT] },
      maxPerRequest: [{ network: "eip155:84532", asset: USDC, amount: "20000" }],
      dailyBudgets: [{ network: "eip155:84532", asset: USDC, amount: "25000" }],
    },
  });
}

test("allows a payment that satisfies every rule", async () => {
  const firewall = createFirewall();
  const decision = await firewall.evaluate(payment());

  assert.equal(decision.decision, "allow");
  assert.deepEqual(decision.reasons, []);
  await firewall.finalize(decision.decisionId, "settled");
});

test("denies an amount above the per-request limit", async () => {
  const firewall = createFirewall();
  const decision = await firewall.evaluate(payment({ amount: "20001" }));

  assert.equal(decision.decision, "deny");
  assert.ok(decision.reasons.includes("amount exceeds per-request limit"));
});

test("denies resource substitution across domains", async () => {
  const firewall = createFirewall();
  const input = payment();
  input.paymentRequired.resource.url = "https://evil.example/collect";

  const decision = await firewall.evaluate(input);

  assert.equal(decision.decision, "deny");
  assert.ok(decision.reasons.includes("resource domain is not allowed"));
  assert.ok(decision.reasons.includes("payment resource does not match request domain"));
});

test("denies a recipient that differs from the pinned address", async () => {
  const firewall = createFirewall();
  const decision = await firewall.evaluate(payment({ payTo: "0x0000000000000000000000000000000000000001" }));

  assert.equal(decision.decision, "deny");
  assert.ok(decision.reasons.includes("recipient does not match domain pin"));
});

test("denies requirements that were not advertised by the server", async () => {
  const firewall = createFirewall();
  const input = payment();
  input.selectedRequirements = { ...input.selectedRequirements, amount: "12000" };

  const decision = await firewall.evaluate(input);

  assert.equal(decision.decision, "deny");
  assert.ok(decision.reasons.includes("selected payment requirements were not advertised by the server"));
});

test("blocks a duplicate until a failed attempt is released", async () => {
  const firewall = createFirewall();
  const first = await firewall.evaluate(payment());
  const duplicate = await firewall.evaluate(payment());

  assert.equal(first.decision, "allow");
  assert.equal(duplicate.decision, "deny");
  assert.ok(duplicate.reasons.includes("duplicate payment request"));

  await firewall.finalize(first.decisionId, "failed");
  const retry = await firewall.evaluate(payment());
  assert.equal(retry.decision, "allow");
});

test("reserves daily budget before settlement to prevent concurrent overspend", async () => {
  const firewall = createFirewall();
  const firstInput = payment({ amount: "15000" });
  const secondInput = payment({ amount: "15000" });
  secondInput.request.sessionId = "session-2";

  const first = await firewall.evaluate(firstInput);
  const second = await firewall.evaluate(secondInput);

  assert.equal(first.decision, "allow");
  assert.equal(second.decision, "deny");
  assert.ok(second.reasons.includes("daily budget exceeded"));
});

test("writes decision and settlement audit events", async () => {
  const audit = new MemoryAuditSink();
  const firewall = createFirewall(audit);
  const decision = await firewall.evaluate(payment());
  await firewall.finalize(decision.decisionId, "settled");

  assert.equal(audit.events.length, 2);
  assert.equal(audit.events[0]?.decision, "allow");
  assert.equal(audit.events[1]?.outcome, "settled");
});
