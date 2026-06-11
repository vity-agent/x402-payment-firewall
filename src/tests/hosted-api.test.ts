import assert from "node:assert/strict";
import test from "node:test";

import {
  evaluateHostedRequest,
  getHostedApiConfig,
  parseHostedEvaluateRequest,
} from "../hosted-api.js";
import { getX402ServerConfig } from "../x402-server.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const MERCHANT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";

function requestBody(): unknown {
  const requirement = {
    scheme: "exact",
    network: "eip155:84532",
    amount: "10000",
    asset: USDC,
    payTo: MERCHANT,
  };
  return {
    policy: {
      allowedDomains: ["api.example.com"],
      allowedNetworks: ["eip155:84532"],
      allowedAssets: [USDC],
      maxPerRequest: [{ network: "eip155:84532", asset: USDC, amount: "20000" }],
    },
    input: {
      paymentRequired: {
        x402Version: 2,
        resource: { url: "https://api.example.com/weather" },
        accepts: [requirement],
      },
      selectedRequirements: requirement,
      request: {
        agentId: "hosted-test",
        method: "GET",
        url: "https://api.example.com/weather",
      },
    },
  };
}

test("parses and evaluates a valid hosted request", async () => {
  const parsed = parseHostedEvaluateRequest(requestBody());
  const result = await evaluateHostedRequest(parsed);

  assert.equal(result.mode, "free");
  assert.equal(result.decision.decision, "allow");
  assert.equal(result.limitations.length, 3);
});

test("rejects malformed atomic amounts", () => {
  const body = requestBody() as {
    input: { selectedRequirements: { amount: string } };
  };
  body.input.selectedRequirements.amount = "0.01";

  assert.throws(() => parseHostedEvaluateRequest(body), /atomic units/);
});

test("loads the configured public pay-to address while payments stay disabled", () => {
  const config = getHostedApiConfig({
    PAYMENTS_ENABLED: "false",
    PAY_TO_ADDRESS: "0xe3f47081bc0419cf6c41de287a813622c3e893b2",
  });

  assert.equal(config.paymentsEnabled, false);
  assert.equal(config.payToAddress, "0xe3f47081bc0419cf6c41de287a813622c3e893b2");
});

test("enables payment mode when pay-to is configured and PAYMENTS_ENABLED is omitted", () => {
  const config = getHostedApiConfig({
    PAY_TO_ADDRESS: "0xe3f47081bc0419cf6c41de287a813622c3e893b2",
  });

  assert.equal(config.paymentsEnabled, true);
  assert.equal(config.payToAddress, "0xe3f47081bc0419cf6c41de287a813622c3e893b2");
});

test("rejects an invalid configured pay-to address", () => {
  assert.throws(
    () => getHostedApiConfig({ PAY_TO_ADDRESS: "not-an-address" }),
    /valid EVM address/,
  );
});

test("builds a Base Sepolia x402 seller configuration by default", () => {
  const hosted = getHostedApiConfig({
    PAYMENTS_ENABLED: "true",
    PAY_TO_ADDRESS: "0xe3f47081bc0419cf6c41de287a813622c3e893b2",
  });
  const config = getX402ServerConfig(hosted, {});

  assert.equal(config.network, "eip155:84532");
  assert.equal(config.price, "$0.001");
  assert.equal(config.facilitatorUrl, "https://x402.org/facilitator");
  assert.equal(config.resourceUrl, "https://x402-payment-firewall.vercel.app/api/evaluate");
});

test("requires a pay-to address before payment mode can start", () => {
  assert.throws(
    () => getX402ServerConfig({ paymentsEnabled: true }, {}),
    /PAY_TO_ADDRESS is required/,
  );
});

test("rejects invalid paid endpoint configuration", () => {
  const hosted = {
    paymentsEnabled: true,
    payToAddress: "0xe3f47081bc0419cf6c41de287a813622c3e893b2",
  };
  assert.throws(() => getX402ServerConfig(hosted, { X402_PRICE: "free" }), /X402_PRICE/);
  assert.throws(() => getX402ServerConfig(hosted, { X402_NETWORK: "base" }), /CAIP-2/);
});
