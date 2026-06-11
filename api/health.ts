import { getHostedApiConfig } from "../src/hosted-api.js";
import { getX402ServerConfig } from "../src/x402-server.js";
import type { ApiRequest, ApiResponse } from "../src/api-types.js";

export default function handler(request: ApiRequest, response: ApiResponse): void {
  setCommonHeaders(response);
  if (request.method === "OPTIONS") {
    response.status(204).end();
    return;
  }
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET, OPTIONS");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const config = getHostedApiConfig();
    const x402 = config.payToAddress ? getX402ServerConfig(config) : undefined;
    response.status(200).json({
      status: "ok",
      service: "x402-payment-firewall",
      version: "0.1.0",
      payments: {
        enabled: config.paymentsEnabled,
        configured: Boolean(config.payToAddress),
        mode: config.paymentsEnabled ? "x402" : "free",
        network: x402?.network,
        price: x402?.price,
        resource: x402?.resourceUrl,
      },
    });
  } catch (error) {
    response.status(500).json({
      error: "invalid_server_configuration",
      message: error instanceof Error ? error.message : "unknown configuration error",
    });
  }
}

function setCommonHeaders(response: ApiResponse): void {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
}
