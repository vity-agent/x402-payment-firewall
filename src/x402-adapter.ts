import type { PaymentFirewall } from "./firewall.js";
import type {
  PaymentRequiredLike,
  PaymentRequirementsLike,
  RequestContext,
} from "./types.js";

interface PaymentCreationContextLike {
  paymentRequired: PaymentRequiredLike;
  selectedRequirements: PaymentRequirementsLike;
}

interface X402ClientLike {
  onBeforePaymentCreation(
    hook: (context: PaymentCreationContextLike) => Promise<void | { abort: true; reason: string }>,
  ): unknown;
}

export interface FirewallHookOptions {
  getRequestContext: () => RequestContext | Promise<RequestContext>;
  onAllowed?: (decisionId: string) => void | Promise<void>;
}

export function installPaymentFirewall(
  client: X402ClientLike,
  firewall: PaymentFirewall,
  options: FirewallHookOptions,
): void {
  client.onBeforePaymentCreation(async context => {
    const request = await options.getRequestContext();
    const decision = await firewall.evaluate({
      paymentRequired: context.paymentRequired,
      selectedRequirements: context.selectedRequirements,
      request,
    });

    if (decision.decision !== "allow") {
      return { abort: true, reason: decision.reasons.join("; ") };
    }

    await options.onAllowed?.(decision.decisionId);
  });
}
