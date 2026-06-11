# x402 Payment Firewall

Local-first policy enforcement before an x402 client creates a payment signature.
The firewall never receives or stores a wallet private key.

## Status

Early MVP. Use testnet and explicit limits while evaluating the package.

## Current protections

- Domain, network, asset, scheme, and recipient allowlists
- Domain-to-recipient pinning
- Per-request atomic-unit limits
- Atomic daily budget reservations
- Request fingerprinting and duplicate prevention
- Request/resource domain binding
- In-memory or JSONL audit logs
- Structural adapter for the x402 V2 `onBeforePaymentCreation` hook

## Install for development

```bash
npm install
npm test
```

## Free hosted API

The repository includes two Vercel functions:

```text
GET  /api/health
POST /api/evaluate
```

Hosted evaluation is stateless. It supports allowlists, recipient pinning,
per-request limits, and request/resource binding. Daily budgets and duplicate
protection stay in the local SDK because serverless memory is not durable.

Set these Vercel environment variables:

```text
PAYMENTS_ENABLED=false
PAY_TO_ADDRESS=0xe3f47081bc0419cf6c41de287a813622c3e893b2
```

`PAY_TO_ADDRESS` is stored now for the future paid endpoint. Setting
`PAYMENTS_ENABLED=true` activates the x402 V2 seller flow.

Paid mode defaults to Base Sepolia and the public x402 test facilitator:

```text
X402_NETWORK=eip155:84532
X402_PRICE=$0.001
X402_FACILITATOR_URL=https://x402.org/facilitator
PUBLIC_BASE_URL=https://x402-payment-firewall.vercel.app
```

The paid route includes the Bazaar discovery extension, service metadata,
and JSON input/output schemas. Requests without a payment signature receive
an x402 V2 `402 Payment Required` response. Verified payments are settled only
after evaluation succeeds; invalid request bodies are canceled before settlement.

To test the full payment flow safely, change only:

```text
PAYMENTS_ENABLED=true
```

Keep `X402_NETWORK=eip155:84532` until the endpoint has been tested with Base
Sepolia USDC. Mainnet activation requires an explicit network/facilitator review.

Example request:

```bash
curl -X POST https://YOUR-DEPLOYMENT.vercel.app/api/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/evaluate-request.json
```

## Basic policy

```ts
import { PaymentFirewall } from "x402-payment-firewall";

const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

const firewall = new PaymentFirewall({
  policy: {
    allowedDomains: ["api.example.com"],
    allowedNetworks: ["eip155:84532"],
    allowedAssets: [USDC_BASE_SEPOLIA],
    allowedSchemes: ["exact"],
    maxPerRequest: [{
      network: "eip155:84532",
      asset: USDC_BASE_SEPOLIA,
      amount: "50000"
    }],
    dailyBudgets: [{
      network: "eip155:84532",
      asset: USDC_BASE_SEPOLIA,
      amount: "500000"
    }]
  }
});
```

Amounts are integer atomic token units. Never use floating-point values for money.

## Attach to x402 V2

```ts
import { installPaymentFirewall } from "x402-payment-firewall";

let pendingDecisionId: string | undefined;

installPaymentFirewall(client, firewall, {
  getRequestContext: () => ({
    agentId: "research-agent",
    sessionId: crypto.randomUUID(),
    tool: "weather",
    method: "GET",
    url: "https://api.example.com/weather"
  }),
  onAllowed: decisionId => {
    pendingDecisionId = decisionId;
  }
});
```

The official x402 hook runs before payment payload creation and can abort signing.
After the HTTP payment attempt completes, finalize the reserved decision:

```ts
await firewall.finalize(pendingDecisionId, response.ok ? "settled" : "failed");
```

Do not treat signature creation as settlement. A production fetch adapter should read
the x402 settlement response and finalize automatically.

## Non-goals for this MVP

- Custody or wallet signing
- Facilitator or blockchain settlement
- Merchant reputation scoring
- Hosted policy dashboard
- Claiming complete protection against all x402 protocol attacks

## Security model

The firewall is a policy gate, not a wallet. Keep signing local, fail closed for
high-value payments, and bind policy decisions to the request that initiated them.
