import type { IncomingHttpHeaders } from "node:http";

export interface ApiRequest {
  method?: string;
  headers: IncomingHttpHeaders;
  body?: unknown;
  query?: Record<string, string | string[] | undefined>;
}

export interface ApiResponse {
  setHeader(name: string, value: string): void;
  status(code: number): ApiResponse;
  json(body: unknown): void;
  send(body: string): void;
  end(): void;
}
