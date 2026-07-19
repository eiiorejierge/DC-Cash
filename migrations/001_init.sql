CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username VARCHAR(16) NOT NULL,
  username_key VARCHAR(16) NOT NULL UNIQUE,
  pin_hash TEXT NOT NULL,
  firm_verified_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind VARCHAR(16) NOT NULL CHECK (kind IN ('checking', 'savings')),
  balance_cents BIGINT NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, kind)
);

CREATE TABLE IF NOT EXISTS verification_sessions (
  id UUID PRIMARY KEY,
  username VARCHAR(16) NOT NULL,
  username_key VARCHAR(16) NOT NULL,
  amount_cents SMALLINT NOT NULL CHECK (amount_cents BETWEEN 1 AND 99),
  status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'matched', 'completed', 'expired', 'cancelled')),
  firm_transaction_id TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  matched_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS verification_match_idx
  ON verification_sessions (username_key, amount_cents, status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS verification_firm_transaction_idx
  ON verification_sessions (firm_transaction_id)
  WHERE firm_transaction_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS deposit_requests (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
  status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'expired', 'cancelled')),
  firm_transaction_id TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS deposit_match_idx
  ON deposit_requests (user_id, amount_cents, status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS deposit_firm_transaction_idx
  ON deposit_requests (firm_transaction_id)
  WHERE firm_transaction_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id UUID REFERENCES accounts(id) ON DELETE SET NULL,
  type VARCHAR(24) NOT NULL CHECK (type IN ('deposit', 'withdrawal', 'payment', 'request', 'transfer_in', 'transfer_out')),
  status VARCHAR(16) NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  amount_cents BIGINT NOT NULL,
  counterparty TEXT,
  note TEXT,
  related_transaction_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS transactions_user_created_idx
  ON transactions (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS payment_requests (
  id UUID PRIMARY KEY,
  requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_username VARCHAR(16) NOT NULL,
  amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
  note TEXT,
  status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'declined', 'cancelled', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS firm_webhook_events (
  transaction_id TEXT PRIMARY KEY,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_type VARCHAR(24),
  matched_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

