CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  key_prefix text NOT NULL,
  key_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  config jsonb NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS decisions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
  fingerprint text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('allow', 'deny', 'review')),
  status text NOT NULL CHECK (status IN ('denied', 'reserved', 'settled', 'cancelled', 'expired')),
  risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  network text NOT NULL,
  asset text NOT NULL,
  amount numeric(78, 0) NOT NULL CHECK (amount >= 0),
  pay_to text NOT NULL,
  request_context jsonb NOT NULL,
  policy_snapshot jsonb NOT NULL,
  reserved_until timestamptz,
  authorization_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  settled_at timestamptz,
  cancelled_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS decisions_active_fingerprint_unique
  ON decisions (tenant_id, fingerprint)
  WHERE status IN ('reserved', 'settled');

CREATE INDEX IF NOT EXISTS decisions_policy_budget_idx
  ON decisions (policy_id, network, asset, created_at)
  WHERE status IN ('reserved', 'settled');

CREATE TABLE IF NOT EXISTS audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  decision_id uuid REFERENCES decisions(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_tenant_created_idx
  ON audit_events (tenant_id, created_at DESC);
