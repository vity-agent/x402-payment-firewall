import type { IncomingHttpHeaders } from "node:http";

export interface ApiRequest {
  method?: string;
  headers: IncomingHttpHeaders;
  body?: unknown;
}

export interface ApiResponse {
  setHeader(name: string, value: string): void;
  status(code: number): ApiResponse;
  json(body: unknown): void;
  send(body: string): void;
  end(): void;
}
