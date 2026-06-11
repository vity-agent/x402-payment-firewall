import { PaymentFirewall } from "x402-payment-firewall";

const firewall = new PaymentFirewall({
  policy: {
    allowedDomains: ["api.example.com"],
    allowedNetworks: ["eip155:84532"],
    allowedAssets: ["0x036CbD53842c5426634e7929541eC2318f3dCF7e"],
    allowedSchemes: ["exact"],
    maxPerRequest: [{
      network: "eip155:84532",
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      amount: "50000",
    }],
  },
});

// Pass this firewall to installPaymentFirewall with an x402Client instance.
void firewall;
