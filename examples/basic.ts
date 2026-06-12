import { PaymentFirewall } from "x402-payment-firewall";

const firewall = new PaymentFirewall({
  policy: {
    allowedDomains: ["api.example.com"],
    allowedNetworks: ["eip155:8453"],
    allowedAssets: ["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"],
    allowedSchemes: ["exact"],
    maxPerRequest: [{
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      amount: "50000",
    }],
  },
});

// Pass this firewall to installPaymentFirewall with an x402Client instance.
void firewall;
