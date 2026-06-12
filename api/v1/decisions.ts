import { setApiHeaders, writeApiError } from "../../src/api-response.js";
import type { ApiRequest, ApiResponse } from "../../src/api-types.js";
import { authenticateRequest } from "../../src/cloud-auth.js";
import { finalizeCloudDecision } from "../../src/cloud-firewall.js";

export default async function handler(request: ApiRequest, response: ApiResponse): Promise<void> {
  setApiHeaders(response, "POST, OPTIONS");
  if (request.method === "OPTIONS") return response.status(204).end();
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST, OPTIONS");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const auth = await authenticateRequest(request);
    response.status(200).json(await finalizeCloudDecision(auth, request.body));
  } catch (error) {
    writeApiError(response, error);
  }
}
