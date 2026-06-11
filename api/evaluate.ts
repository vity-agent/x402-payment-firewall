import {
  evaluateHostedRequest,
  getHostedApiConfig,
  parseHostedEvaluateRequest,
} from "../src/hosted-api.js";
import {
  applySettlementHeaders,
  getX402ServerConfig,
  processX402Request,
  settleX402Payment,
  writeX402Instructions,
} from "../src/x402-server.js";
import type { ApiRequest, ApiResponse } from "../src/api-types.js";

export default async function handler(request: ApiRequest, response: ApiResponse): Promise<void> {
  setCommonHeaders(response);
  if (request.method === "OPTIONS") {
    response.status(204).end();
    return;
  }
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST, OPTIONS");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const config = getHostedApiConfig();
    if (config.paymentsEnabled) {
      const x402Config = getX402ServerConfig(config);
      const paymentResult = await processX402Request(request, x402Config);
      if (paymentResult.type === "payment-error") {
        writeX402Instructions(response, paymentResult.response);
        return;
      }
      if (paymentResult.type !== "payment-verified") {
        response.status(500).json({ error: "payment_route_not_protected" });
        return;
      }

      try {
        const body = parseHostedEvaluateRequest(request.body);
        const result = await evaluateHostedRequest(body);
        const paidResult = { ...result, mode: "paid" as const };
        const settlement = await settleX402Payment(paymentResult, request, paidResult, x402Config);
        if (!settlement.success) {
          writeX402Instructions(response, settlement.response);
          return;
        }
        applySettlementHeaders(response, settlement);
        response.status(200).json(paidResult);
        return;
      } catch (error) {
        await paymentResult.cancellationDispatcher.cancel({
          reason: "handler_failed",
          error,
          responseStatus: 400,
        });
        throw error;
      }
    }

    const body = parseHostedEvaluateRequest(request.body);
    response.status(200).json(await evaluateHostedRequest(body));
  } catch (error) {
    response.status(400).json({
      error: "invalid_request",
      message: error instanceof Error ? error.message : "unknown request error",
    });
  }
}

function setCommonHeaders(response: ApiResponse): void {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
}
