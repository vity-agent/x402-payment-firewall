import { HTTPFacilitatorClient, x402HTTPResourceServer, x402ResourceServer } from "@x402/core/server";
import type {
  HTTPAdapter,
  HTTPProcessResult,
  HTTPRequestContext,
  HTTPResponseInstructions,
  ProcessSettleResultResponse,
} from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";

import type { ApiRequest, ApiResponse } from "./api-types.js";
import type { HostedApiConfig } from "./hosted-api.js";

const EVALUATE_PATH = "/api/evaluate";

export interface X402ServerConfig {
  network: `${string}:${string}`;
  price: string;
  facilitatorUrl: string;
  resourceUrl: string;
  payToAddress: string;
}

export type VerifiedPayment = Extract<HTTPProcessResult, { type: "payment-verified" }>;

let cachedServer: Promise<x402HTTPResourceServer> | undefined;
let cachedKey: string | undefined;

export function getX402ServerConfig(
  config: HostedApiConfig,
  env: NodeJS.ProcessEnv = process.env,
): X402ServerConfig {
  if (!config.payToAddress) throw new Error("PAY_TO_ADDRESS is required when payments are enabled");

  const network = env.X402_NETWORK?.trim() || "eip155:8453";
  if (!/^[a-z0-9-]+:[A-Za-z0-9_-]+$/.test(network)) throw new Error("X402_NETWORK must use CAIP-2 format");

  const price = env.X402_PRICE?.trim() || "$0.10";
  if (!/^\$?(0|[1-9]\d*)(\.\d{1,6})?$/.test(price)) throw new Error("X402_PRICE must be a non-negative USD amount");

  const facilitatorUrl = validateHttpUrl(
    env.X402_FACILITATOR_URL?.trim() || "https://facilitator.payai.network",
    "X402_FACILITATOR_URL",
  );
  const publicBaseUrl = validateHttpUrl(
    env.PUBLIC_BASE_URL?.trim() || "https://x402-payment-firewall.vercel.app",
    "PUBLIC_BASE_URL",
  ).replace(/\/$/, "");

  return {
    network: network as `${string}:${string}`,
    price,
    facilitatorUrl,
    resourceUrl: `${publicBaseUrl}${EVALUATE_PATH}`,
    payToAddress: config.payToAddress,
  };
}

export async function processX402Request(
  request: ApiRequest,
  config: X402ServerConfig,
): Promise<HTTPProcessResult> {
  const server = await getResourceServer(config);
  return server.processHTTPRequest(createRequestContext(request, config.resourceUrl));
}

export async function settleX402Payment(
  verified: VerifiedPayment,
  request: ApiRequest,
  responseBody: unknown,
  config: X402ServerConfig,
): Promise<ProcessSettleResultResponse> {
  const server = await getResourceServer(config);
  return server.processSettlement(
    verified.paymentPayload,
    verified.paymentRequirements,
    verified.declaredExtensions,
    {
      request: createRequestContext(request, config.resourceUrl),
      responseBody: Buffer.from(JSON.stringify(responseBody)),
      responseHeaders: { "content-type": "application/json" },
    },
  );
}

export function writeX402Instructions(response: ApiResponse, instructions: HTTPResponseInstructions): void {
  for (const [name, value] of Object.entries(instructions.headers)) response.setHeader(name, value);
  if (instructions.body === undefined) {
    response.status(instructions.status).end();
  } else if (typeof instructions.body === "string") {
    response.status(instructions.status).send(instructions.body);
  } else {
    response.status(instructions.status).json(instructions.body);
  }
}

export function applySettlementHeaders(response: ApiResponse, settlement: ProcessSettleResultResponse): void {
  for (const [name, value] of Object.entries(settlement.headers)) response.setHeader(name, value);
}

export function resetX402ServerCacheForTests(): void {
  cachedServer = undefined;
  cachedKey = undefined;
}

async function getResourceServer(config: X402ServerConfig): Promise<x402HTTPResourceServer> {
  const key = JSON.stringify(config);
  if (!cachedServer || cachedKey !== key) {
    cachedKey = key;
    cachedServer = createResourceServer(config);
  }
  return cachedServer;
}

async function createResourceServer(config: X402ServerConfig): Promise<x402HTTPResourceServer> {
  const facilitator = new HTTPFacilitatorClient({ url: config.facilitatorUrl });
  const core = new x402ResourceServer(facilitator)
    .register(config.network, new ExactEvmScheme())
    .registerExtension(bazaarResourceServerExtension);
  const routes = {
    [`POST ${EVALUATE_PATH}`]: {
      accepts: {
        scheme: "exact",
        price: config.price,
        network: config.network,
        payTo: config.payToAddress,
      },
      resource: config.resourceUrl,
      description: "Evaluate an x402 payment request against caller-supplied security policy",
      mimeType: "application/json",
      serviceName: "x402 Payment Firewall",
      tags: ["x402", "security", "payments", "ai-agents", "risk"],
      iconUrl: `${new URL(config.resourceUrl).origin}/favicon-192.png`,
      extensions: {
        ...declareDiscoveryExtension({
          bodyType: "json",
          input: {
            policy: { allowedDomains: ["api.example.com"] },
            input: { paymentRequired: {}, selectedRequirements: {}, request: { agentId: "agent-1" } },
          },
          inputSchema: hostedEvaluateInputSchema,
          output: {
            example: {
              mode: "paid",
              decision: { decision: "allow", riskScore: 0, reasons: [] },
            },
            schema: hostedEvaluateOutputSchema,
          },
        }),
      },
      unpaidResponseBody: async () => ({
        contentType: "application/json",
        body: {
          error: "payment_required",
          service: "x402-payment-firewall",
          documentation: "https://github.com/vity-agent/x402-payment-firewall",
        },
      }),
    },
  };

  const server = new x402HTTPResourceServer(core, routes);
  await server.initialize();
  return server;
}

function createRequestContext(request: ApiRequest, resourceUrl: string): HTTPRequestContext {
  const url = new URL(resourceUrl);
  const adapter: HTTPAdapter = {
    getHeader: name => getHeader(request, name),
    getMethod: () => request.method ?? "POST",
    getPath: () => url.pathname,
    getUrl: () => resourceUrl,
    getAcceptHeader: () => getHeader(request, "accept") ?? "application/json",
    getUserAgent: () => getHeader(request, "user-agent") ?? "",
    getBody: () => request.body,
  };
  const paymentHeader = getHeader(request, "payment-signature");
  return {
    adapter,
    path: url.pathname,
    method: request.method ?? "POST",
    ...(paymentHeader ? { paymentHeader } : {}),
  };
}

function getHeader(request: ApiRequest, name: string): string | undefined {
  const value = request.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function validateHttpUrl(value: string, field: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`${field} must use http or https`);
  return url.toString();
}

const paymentRequirementSchema = {
  type: "object",
  required: ["scheme", "network", "amount", "asset", "payTo"],
  properties: {
    scheme: { type: "string" },
    network: { type: "string" },
    amount: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
    asset: { type: "string" },
    payTo: { type: "string" },
  },
} as const;

const hostedEvaluateInputSchema = {
  type: "object",
  required: ["policy", "input"],
  properties: {
    policy: { type: "object", description: "Firewall allowlists and spending limits" },
    input: {
      type: "object",
      required: ["paymentRequired", "selectedRequirements", "request"],
      properties: {
        paymentRequired: {
          type: "object",
          required: ["x402Version", "resource", "accepts"],
          properties: {
            x402Version: { type: "number", const: 2 },
            resource: { type: "object", required: ["url"], properties: { url: { type: "string", format: "uri" } } },
            accepts: { type: "array", minItems: 1, items: paymentRequirementSchema },
          },
        },
        selectedRequirements: paymentRequirementSchema,
        request: {
          type: "object",
          required: ["agentId"],
          properties: {
            agentId: { type: "string" },
            method: { type: "string" },
            url: { type: "string", format: "uri" },
          },
        },
      },
    },
  },
} as const;

const hostedEvaluateOutputSchema = {
  type: "object",
  required: ["mode", "decision", "limitations"],
  properties: {
    mode: { type: "string", enum: ["paid"] },
    decision: {
      type: "object",
      required: ["decision", "riskScore", "reasons", "fingerprint"],
      properties: {
        decision: { type: "string", enum: ["allow", "deny", "review"] },
        riskScore: { type: "number" },
        reasons: { type: "array", items: { type: "string" } },
        fingerprint: { type: "string" },
      },
    },
    limitations: { type: "array", items: { type: "string" } },
  },
} as const;
