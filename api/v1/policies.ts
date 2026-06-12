import { setApiHeaders, writeApiError } from "../../src/api-response.js";
import type { ApiRequest, ApiResponse } from "../../src/api-types.js";
import { ApiError, authenticateRequest } from "../../src/cloud-auth.js";
import { createPolicy, getPolicy } from "../../src/cloud-firewall.js";

export default async function handler(request: ApiRequest, response: ApiResponse): Promise<void> {
  setApiHeaders(response, "GET, POST, OPTIONS");
  if (request.method === "OPTIONS") return response.status(204).end();
  try {
    const auth = await authenticateRequest(request);
    if (request.method === "POST") {
      response.status(201).json(await createPolicy(auth, request.body));
      return;
    }
    if (request.method === "GET") {
      const policyId = getQueryString(request, "id");
      response.status(200).json(await getPolicy(auth, policyId));
      return;
    }
    response.setHeader("Allow", "GET, POST, OPTIONS");
    response.status(405).json({ error: "method_not_allowed" });
  } catch (error) {
    writeApiError(response, error);
  }
}

function getQueryString(request: ApiRequest, field: string): string {
  const value = request.query?.[field];
  if (typeof value !== "string") throw new ApiError(400, "invalid_request", `${field} query parameter is required`);
  return value;
}
