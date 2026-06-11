import { appendFile } from "node:fs/promises";

import type { AmountLimit, AuditEvent, AuditSink } from "./types.js";

function keyFor(network: string, asset: string): string {
  return `${network}:${asset.toLowerCase()}`;
}

export class MemoryDuplicateStore {
  readonly #entries = new Map<string, number>();

  reserve(fingerprint: string, expiresAtMs: number, nowMs = Date.now()): boolean {
    this.prune(nowMs);
    if (this.#entries.has(fingerprint)) return false;
    this.#entries.set(fingerprint, expiresAtMs);
    return true;
  }

  release(fingerprint: string): void {
    this.#entries.delete(fingerprint);
  }

  private prune(nowMs: number): void {
    for (const [fingerprint, expiresAt] of this.#entries) {
      if (expiresAt <= nowMs) this.#entries.delete(fingerprint);
    }
  }
}

interface Reservation {
  key: string;
  amount: bigint;
  day: string;
}

export class MemoryBudgetStore {
  readonly #spent = new Map<string, bigint>();
  readonly #reserved = new Map<string, Reservation>();

  reserve(
    decisionId: string,
    limit: AmountLimit,
    requestedAmount: string,
    now = new Date(),
  ): boolean {
    const day = now.toISOString().slice(0, 10);
    const assetKey = keyFor(limit.network, limit.asset);
    const dailyKey = `${day}:${assetKey}`;
    const amount = parseAtomicAmount(requestedAmount);
    const maximum = parseAtomicAmount(limit.amount);
    const spent = this.#spent.get(dailyKey) ?? 0n;
    let pending = 0n;

    for (const reservation of this.#reserved.values()) {
      if (reservation.key === assetKey && reservation.day === day) pending += reservation.amount;
    }

    if (spent + pending + amount > maximum) return false;
    this.#reserved.set(decisionId, { key: assetKey, amount, day });
    return true;
  }

  settle(decisionId: string): void {
    const reservation = this.#reserved.get(decisionId);
    if (!reservation) return;
    const dailyKey = `${reservation.day}:${reservation.key}`;
    this.#spent.set(dailyKey, (this.#spent.get(dailyKey) ?? 0n) + reservation.amount);
    this.#reserved.delete(decisionId);
  }

  release(decisionId: string): void {
    this.#reserved.delete(decisionId);
  }
}

export class MemoryAuditSink implements AuditSink {
  readonly events: AuditEvent[] = [];

  async write(event: AuditEvent): Promise<void> {
    this.events.push(structuredClone(event));
  }
}

export class JsonlAuditSink implements AuditSink {
  constructor(private readonly filePath: string) {}

  async write(event: AuditEvent): Promise<void> {
    await appendFile(this.filePath, `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
  }
}

export function parseAtomicAmount(value: string): bigint {
  if (!/^(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`Invalid atomic amount: ${value}`);
  }
  return BigInt(value);
}
