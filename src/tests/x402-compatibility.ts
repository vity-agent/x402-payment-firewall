import { x402Client } from "@x402/core/client";

import { PaymentFirewall } from "../firewall.js";
import { installPaymentFirewall } from "../x402-adapter.js";

// Compile-time check against the current official x402 V2 client hook API.
const client = new x402Client();
const firewall = new PaymentFirewall({ policy: {} });

installPaymentFirewall(client, firewall, {
  getRequestContext: () => ({ agentId: "compile-check" }),
});
