import { readFile } from "node:fs/promises";

import { loadLocalEnv } from "./env.mjs";

loadLocalEnv();
const credentials = JSON.parse(await readFile(".firewall-credentials.json", "utf8"));
const { authenticateRequest } = await import("../dist/cloud-auth.js");
const { createPolicy, evaluateCloudPayment, finalizeCloudDecision } = await import("../dist/cloud-firewall.js");

const auth = await authenticateRequest({
  headers: { authorization: `Bearer ${credentials.apiKey}` },
});
const suffix = Date.now().toString(36);
const asset = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const merchant = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const policy = await createPolicy(auth, {
  name: `smoke-${suffix}`,
  policy: {
    allowedDomains: ["api.example.com"],
    allowedNetworks: ["eip155:8453"],
    allowedAssets: [asset],
    allowedSchemes: ["exact"],
    allowedRecipients: [merchant],
    maxPerRequest: [{ network: "eip155:8453", asset, amount: "20000" }],
    dailyBudgets: [{ network: "eip155:8453", asset, amount: "30000" }],
  },
});

const requirement = {
  scheme: "exact",
  network: "eip155:8453",
  amount: "10000",
  asset,
  payTo: merchant,
  maxTimeoutSeconds: 300,
  extra: { name: "USD Coin", version: "2" },
};
const body = {
  policyId: policy.id,
  input: {
    paymentRequired: {
      x402Version: 2,
      resource: { url: `https://api.example.com/weather?run=${suffix}` },
      accepts: [requirement],
    },
    selectedRequirements: requirement,
    request: {
      agentId: "smoke-test",
      sessionId: suffix,
      method: "GET",
      url: `https://api.example.com/weather?run=${suffix}`,
    },
  },
};

const first = await evaluateCloudPayment(auth, body);
if (first.decision.decision !== "allow" || !first.authorizationToken) throw new Error("first reservation failed");
const duplicate = await evaluateCloudPayment(auth, body);
if (!duplicate.decision.reasons.includes("duplicate payment request")) throw new Error("replay was not blocked");
await finalizeCloudDecision(auth, {
  decisionId: first.decision.decisionId,
  authorizationToken: first.authorizationToken,
  outcome: "cancelled",
});
const retry = await evaluateCloudPayment(auth, body);
if (retry.decision.decision !== "allow" || !retry.authorizationToken) throw new Error("retry after cancel failed");
await finalizeCloudDecision(auth, {
  decisionId: retry.decision.decisionId,
  authorizationToken: retry.authorizationToken,
  outcome: "settled",
});
const settledReplay = await evaluateCloudPayment(auth, body);
if (!settledReplay.decision.reasons.includes("duplicate payment request")) throw new Error("settled replay was not blocked");

const concurrencyPolicy = await createPolicy(auth, {
  name: `concurrency-${suffix}`,
  policy: {
    allowedDomains: ["api.example.com"],
    allowedNetworks: ["eip155:8453"],
    allowedAssets: [asset],
    allowedSchemes: ["exact"],
    dailyBudgets: [{ network: "eip155:8453", asset, amount: "15000" }],
  },
});
const concurrentBodies = ["a", "b"].map(marker => ({
  ...body,
  policyId: concurrencyPolicy.id,
  input: {
    ...body.input,
    paymentRequired: {
      ...body.input.paymentRequired,
      resource: { url: `https://api.example.com/weather?run=${suffix}&request=${marker}` },
    },
    request: {
      ...body.input.request,
      sessionId: `${suffix}-${marker}`,
      url: `https://api.example.com/weather?run=${suffix}&request=${marker}`,
    },
  },
}));
const concurrent = await Promise.all(concurrentBodies.map(candidate => evaluateCloudPayment(auth, candidate)));
if (concurrent.filter(result => result.decision.decision === "allow").length !== 1 ||
    concurrent.filter(result => result.decision.reasons.includes("daily budget exceeded")).length !== 1) {
  throw new Error("concurrent daily budget enforcement failed");
}

process.stdout.write("Neon smoke test passed: auth, policy, atomic budget, replay, cancel, retry, and settle.\n");
