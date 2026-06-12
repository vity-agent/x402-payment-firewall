import { createHmac, timingSafeEqual } from "node:crypto";

import { ApiError } from "./cloud-auth.js";

export interface AuthorizationClaims {
  decisionId: string;
  tenantId: string;
  policyId: string;
  fingerprint: string;
  exp: number;
}

export function createAuthorizationToken(
  claims: AuthorizationClaims,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const secret = getSigningSecret(env);
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function verifyAuthorizationToken(
  token: string,
  env: NodeJS.ProcessEnv = process.env,
): AuthorizationClaims {
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra !== undefined) {
    throw new ApiError(401, "invalid_authorization", "invalid authorization token");
  }

  const expected = createHmac("sha256", getSigningSecret(env)).update(payload).digest();
  let supplied: Buffer;
  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    throw new ApiError(401, "invalid_authorization", "invalid authorization token");
  }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new ApiError(401, "invalid_authorization", "invalid authorization token");
  }

  let claims: AuthorizationClaims;
  try {
    claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as AuthorizationClaims;
  } catch {
    throw new ApiError(401, "invalid_authorization", "invalid authorization token");
  }
  if (!claims.decisionId || !claims.tenantId || !claims.policyId || !claims.fingerprint ||
      !Number.isInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new ApiError(401, "authorization_expired", "authorization token is invalid or expired");
  }
  return claims;
}

function getSigningSecret(env: NodeJS.ProcessEnv): string {
  const secret = env.FIREWALL_SIGNING_SECRET?.trim();
  if (!secret || secret.length < 32) {
    throw new Error("FIREWALL_SIGNING_SECRET must contain at least 32 characters");
  }
  return secret;
}
