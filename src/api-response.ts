import type { ApiResponse } from "./api-types.js";
import { ApiError } from "./cloud-auth.js";

export function setApiHeaders(response: ApiResponse, methods: string): void {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", methods);
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

export function writeApiError(response: ApiResponse, error: unknown): void {
  if (error instanceof ApiError) {
    response.status(error.status).json({ error: error.code, message: error.message });
    return;
  }
  response.status(500).json({ error: "internal_error", message: "internal service error" });
}
