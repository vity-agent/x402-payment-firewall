import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

interface OpenApiOperation {
  security?: Array<Record<string, unknown[]>>;
  requestBody?: unknown;
  responses?: Record<string, unknown>;
  "x-payment-info"?: {
    price?: { mode?: string; currency?: string; amount?: string };
    protocols?: Array<Record<string, unknown>>;
  };
}

interface OpenApiDocument {
  openapi?: string;
  info?: { title?: string; version?: string; "x-guidance"?: string; contact?: { email?: string } };
  paths?: Record<string, Record<string, OpenApiOperation>>;
}

async function loadOpenApi(): Promise<OpenApiDocument> {
  const contents = await readFile(new URL("../../public/openapi.json", import.meta.url), "utf8");
  return JSON.parse(contents) as OpenApiDocument;
}

test("publishes the x402scan-required OpenAPI metadata", async () => {
  const document = await loadOpenApi();

  assert.equal(document.openapi, "3.1.0");
  assert.equal(document.info?.title, "x402 Payment Firewall API");
  assert.equal(document.info?.version, "0.1.0");
  assert.ok(document.info?.["x-guidance"]);
  assert.equal(document.info?.contact?.email, "yaumglyy@gmail.com");
});

test("marks health as free and evaluate as paid and invocable", async () => {
  const document = await loadOpenApi();
  const health = document.paths?.["/api/health"]?.get;
  const evaluate = document.paths?.["/api/evaluate"]?.post;

  assert.deepEqual(health?.security, []);
  assert.ok(health?.responses?.["200"]);
  assert.ok(evaluate?.requestBody);
  assert.ok(evaluate?.responses?.["200"]);
  assert.ok(evaluate?.responses?.["402"]);
  assert.equal(evaluate?.["x-payment-info"]?.price?.mode, "fixed");
  assert.equal(evaluate?.["x-payment-info"]?.price?.currency, "USD");
  assert.equal(evaluate?.["x-payment-info"]?.price?.amount, "0.100000");
  assert.deepEqual(evaluate?.["x-payment-info"]?.protocols, [{ x402: {} }]);
});
