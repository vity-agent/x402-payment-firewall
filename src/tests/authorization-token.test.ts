import assert from "node:assert/strict";
import test from "node:test";

import { createAuthorizationToken, verifyAuthorizationToken } from "../authorization-token.js";

const env = { FIREWALL_SIGNING_SECRET: "test-secret-that-is-at-least-thirty-two-characters" };

test("creates and verifies a bound authorization token", () => {
  const claims = {
    decisionId: "80d49d82-c214-4f7e-832c-363eaceda108",
    tenantId: "a3e6edb5-b732-4df8-8ca7-6986120cdf4f",
    policyId: "cc5274fb-d4b4-43e9-9948-90cf048045fd",
    fingerprint: `sha256:${"a".repeat(64)}`,
    exp: Math.floor(Date.now() / 1000) + 60,
  };
  const token = createAuthorizationToken(claims, env);
  assert.deepEqual(verifyAuthorizationToken(token, env), claims);
});

test("rejects modified and expired authorization tokens", () => {
  const claims = {
    decisionId: "80d49d82-c214-4f7e-832c-363eaceda108",
    tenantId: "a3e6edb5-b732-4df8-8ca7-6986120cdf4f",
    policyId: "cc5274fb-d4b4-43e9-9948-90cf048045fd",
    fingerprint: `sha256:${"a".repeat(64)}`,
    exp: Math.floor(Date.now() / 1000) + 60,
  };
  const token = createAuthorizationToken(claims, env);
  const [payload, signature] = token.split(".") as [string, string];
  const replacement = payload[0] === "a" ? "b" : "a";
  assert.throws(() => verifyAuthorizationToken(`${replacement}${payload.slice(1)}.${signature}`, env), /invalid authorization/);
  assert.throws(() => verifyAuthorizationToken(createAuthorizationToken({
    ...claims,
    exp: Math.floor(Date.now() / 1000) - 1,
  }, env), env), /expired/);
});
