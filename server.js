require('dotenv').config();

const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { pool, migrate, withTransaction } = require('./db');

const app = express();
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const allowDemo = process.env.ALLOW_DEMO_VERIFICATION === 'true' && !isProduction;

if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error('SESSION_SECRET must contain at least 32 characters in production.');
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  }
}));
app.use(express.json({ limit: '100kb' }));

const PgSession = connectPgSimple(session);
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'development-only-session-secret-change-me',
  resave: false,
  saveUninitialized: false,
  name: 'dc_cash_session',
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: 'draft-8', legacyHeaders: false });
const pinLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false });

const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
const uuid = () => crypto.randomUUID();
const usernameKey = value => String(value || '').trim().toLowerCase();
const validUsername = value => /^[A-Za-z0-9_]{3,16}$/.test(String(value || '').trim());
const validPin = value => /^\d{5}$/.test(String(value || ''));
const centsFrom = value => {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Math.round(number * 100);
};
const moneyFromCents = cents => (Number(cents) / 100).toFixed(2);
const safeNote = value => String(value || '').trim().slice(0, 180);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Authentication required.' });
  next();
}

function webhookAuthorized(req) {
  const expected = process.env.FIRM_WEBHOOK_SECRET || '';
  const provided = String(req.get('x-firm-secret') || '');
  if (!expected || expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
}

async function userState(userId, db = pool) {
  const userResult = await db.query('SELECT id, username, firm_verified_at FROM users WHERE id = $1', [userId]);
  if (!userResult.rowCount) return null;
  const accountsResult = await db.query('SELECT id, kind, balance_cents FROM accounts WHERE user_id = $1 ORDER BY kind', [userId]);
  return {
    user: {
      id: userResult.rows[0].id,
      username: userResult.rows[0].username,
      firmVerifiedAt: userResult.rows[0].firm_verified_at
    },
    accounts: Object.fromEntries(accountsResult.rows.map(row => [row.kind, { id: row.id, balance: Number(row.balance_cents) / 100 }]))
  };
}

async function accountFor(client, userId, kind, lock = false) {
  if (!['checking', 'savings'].includes(kind)) return null;
  const result = await client.query(
    `SELECT id, kind, balance_cents FROM accounts WHERE user_id = $1 AND kind = $2 ${lock ? 'FOR UPDATE' : ''}`,
    [userId, kind]
  );
  return result.rows[0] || null;
}

async function confirmDepositWithClient(client, requestId, firmTransactionId) {
  const requestResult = await client.query(
    `SELECT d.*, a.kind FROM deposit_requests d JOIN accounts a ON a.id = d.account_id
     WHERE d.id = $1 FOR UPDATE`,
    [requestId]
  );
  const deposit = requestResult.rows[0];
  if (!deposit) throw Object.assign(new Error('Deposit request not found.'), { status: 404 });
  if (deposit.status === 'completed') return deposit;
  if (deposit.status !== 'pending' || new Date(deposit.expires_at) <= new Date()) {
    throw Object.assign(new Error('Deposit request expired or is no longer active.'), { status: 409 });
  }
  await client.query('UPDATE accounts SET balance_cents = balance_cents + $1, updated_at = NOW() WHERE id = $2', [deposit.amount_cents, deposit.account_id]);
  await client.query(
    `UPDATE deposit_requests SET status = 'completed', firm_transaction_id = $1, completed_at = NOW() WHERE id = $2`,
    [firmTransactionId, deposit.id]
  );
  await client.query(
    `INSERT INTO transactions (id, user_id, account_id, type, status, amount_cents, counterparty, note, metadata)
     VALUES ($1, $2, $3, 'deposit', 'completed', $4, 'Hiss', 'Firm deposit', $5::jsonb)`,
    [uuid(), deposit.user_id, deposit.account_id, deposit.amount_cents, JSON.stringify({ firmTransactionId })]
  );
  return deposit;
}

async function confirmDeposit(requestId, firmTransactionId) {
  return withTransaction(client => confirmDepositWithClient(client, requestId, firmTransactionId));
}

app.get('/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'healthy', database: 'connected', timestamp: new Date().toISOString() });
}));

app.post('/api/auth/start', authLimiter, asyncRoute(async (req, res) => {
  const username = String(req.body.username || '').trim();
  const forceVerification = req.body.forceVerification === true;
  if (!validUsername(username)) return res.status(400).json({ error: 'Use a valid 3-16 character Minecraft username.' });

  const existing = await pool.query('SELECT id FROM users WHERE username_key = $1', [usernameKey(username)]);
  const canForce = forceVerification && existing.rowCount && req.session.userId === existing.rows[0].id;
  if (existing.rowCount && !canForce) return res.json({ mode: 'login' });

  await pool.query(
    `UPDATE verification_sessions SET status = 'expired'
     WHERE username_key = $1 AND status = 'pending' AND expires_at <= NOW()`,
    [usernameKey(username)]
  );
  const amountCents = crypto.randomInt(1, 100);
  const id = uuid();
  await pool.query(
    `INSERT INTO verification_sessions (id, username, username_key, amount_cents, expires_at)
     VALUES ($1, $2, $3, $4, NOW() + INTERVAL '5 minutes')`,
    [id, username, usernameKey(username), amountCents]
  );
  res.status(201).json({
    mode: 'verify',
    verificationId: id,
    amount: Number(moneyFromCents(amountCents)),
    command: `firm pay hiss ${moneyFromCents(amountCents)}`,
    expiresInSeconds: 300,
    demoEnabled: allowDemo
  });
}));

app.get('/api/auth/verifications/:id', asyncRoute(async (req, res) => {
  const result = await pool.query('SELECT status, expires_at, matched_at FROM verification_sessions WHERE id = $1', [req.params.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'Verification not found.' });
  const row = result.rows[0];
  if (row.status === 'pending' && new Date(row.expires_at) <= new Date()) {
    await pool.query("UPDATE verification_sessions SET status = 'expired' WHERE id = $1", [req.params.id]);
    row.status = 'expired';
  }
  res.json({ status: row.status, expiresAt: row.expires_at, matchedAt: row.matched_at });
}));

app.post('/api/auth/verifications/:id/simulate', asyncRoute(async (req, res) => {
  if (!allowDemo) return res.status(404).json({ error: 'Demo verification is disabled.' });
  const result = await pool.query(
    `UPDATE verification_sessions SET status = 'matched', matched_at = NOW(), firm_transaction_id = $1
     WHERE id = $2 AND status = 'pending' AND expires_at > NOW() RETURNING id`,
    [`demo-${uuid()}`, req.params.id]
  );
  if (!result.rowCount) return res.status(409).json({ error: 'Verification is expired or unavailable.' });
  res.json({ status: 'matched' });
}));

app.post('/api/auth/set-pin', pinLimiter, asyncRoute(async (req, res) => {
  const { verificationId, pin } = req.body;
  if (!validPin(pin)) return res.status(400).json({ error: 'PIN must contain exactly five numbers.' });
  const pinHash = await bcrypt.hash(String(pin), 12);
  const result = await withTransaction(async client => {
    const verificationResult = await client.query(
      `SELECT * FROM verification_sessions WHERE id = $1 FOR UPDATE`,
      [verificationId]
    );
    const verification = verificationResult.rows[0];
    if (!verification || verification.status !== 'matched' || new Date(verification.expires_at) <= new Date()) {
      throw Object.assign(new Error('Complete a valid Firm verification before creating a PIN.'), { status: 409 });
    }
    const userId = uuid();
    const userResult = await client.query(
      `INSERT INTO users (id, username, username_key, pin_hash, firm_verified_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (username_key) DO UPDATE SET username = EXCLUDED.username, pin_hash = EXCLUDED.pin_hash, firm_verified_at = NOW(), updated_at = NOW()
       RETURNING id, username`,
      [userId, verification.username, verification.username_key, pinHash]
    );
    const actualUserId = userResult.rows[0].id;
    await client.query(
      `INSERT INTO accounts (id, user_id, kind) VALUES ($1, $2, 'checking'), ($3, $2, 'savings')
       ON CONFLICT (user_id, kind) DO NOTHING`,
      [uuid(), actualUserId, uuid()]
    );
    await client.query("UPDATE verification_sessions SET status = 'completed' WHERE id = $1", [verificationId]);
    return { id: actualUserId, username: userResult.rows[0].username };
  });
  req.session.userId = result.id;
  res.status(201).json(await userState(result.id));
}));

app.post('/api/auth/login', pinLimiter, asyncRoute(async (req, res) => {
  const username = String(req.body.username || '').trim();
  const pin = String(req.body.pin || '');
  if (!validUsername(username) || !validPin(pin)) return res.status(400).json({ error: 'Enter a valid username and five-digit PIN.' });
  const result = await pool.query('SELECT id, pin_hash FROM users WHERE username_key = $1', [usernameKey(username)]);
  const matches = result.rowCount && await bcrypt.compare(pin, result.rows[0].pin_hash);
  if (!matches) return res.status(401).json({ error: 'Username or PIN is incorrect.' });
  req.session.userId = result.rows[0].id;
  res.json(await userState(result.rows[0].id));
}));

app.post('/api/auth/change-pin', requireAuth, pinLimiter, asyncRoute(async (req, res) => {
  const currentPin = String(req.body.currentPin || '');
  const newPin = String(req.body.newPin || '');
  if (!validPin(currentPin) || !validPin(newPin)) return res.status(400).json({ error: 'Both PINs must contain exactly five numbers.' });
  const result = await pool.query('SELECT pin_hash FROM users WHERE id = $1', [req.session.userId]);
  if (!result.rowCount || !await bcrypt.compare(currentPin, result.rows[0].pin_hash)) {
    return res.status(401).json({ error: 'Your current PIN is incorrect.' });
  }
  const newHash = await bcrypt.hash(newPin, 12);
  await pool.query('UPDATE users SET pin_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, req.session.userId]);
  res.status(204).end();
}));

app.post('/api/auth/logout', (req, res, next) => {
  req.session.destroy(error => error ? next(error) : res.status(204).end());
});

app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const state = await userState(req.session.userId);
  if (!state) return res.status(401).json({ error: 'Session user no longer exists.' });
  res.json(state);
}));

app.get('/api/transactions', requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT t.id, t.type, t.status, t.amount_cents, t.counterparty, t.note, t.metadata, t.created_at, a.kind AS account
     FROM transactions t LEFT JOIN accounts a ON a.id = t.account_id
     WHERE t.user_id = $1 ORDER BY t.created_at DESC LIMIT 200`,
    [req.session.userId]
  );
  res.json(result.rows.map(row => ({
    id: row.id,
    type: row.type,
    status: row.status,
    amount: Number(row.amount_cents) / 100,
    counterparty: row.counterparty,
    note: row.note,
    metadata: row.metadata,
    account: row.account,
    createdAt: row.created_at
  })));
}));

app.post('/api/transfers/internal', requireAuth, asyncRoute(async (req, res) => {
  const fromKind = req.body.from;
  const toKind = req.body.to;
  const amountCents = centsFrom(req.body.amount);
  if (!['checking', 'savings'].includes(fromKind) || !['checking', 'savings'].includes(toKind) || fromKind === toKind) {
    return res.status(400).json({ error: 'Choose two different valid accounts.' });
  }
  if (!amountCents || amountCents < 1) return res.status(400).json({ error: 'Enter a valid transfer amount.' });

  await withTransaction(async client => {
    const from = await accountFor(client, req.session.userId, fromKind);
    const to = await accountFor(client, req.session.userId, toKind);
    if (!from || !to) throw Object.assign(new Error('Account not found.'), { status: 404 });
    const lockedAccounts = await client.query(
      'SELECT id, balance_cents FROM accounts WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE',
      [[from.id, to.id]]
    );
    const lockedFrom = lockedAccounts.rows.find(row => row.id === from.id);
    if (!lockedFrom || Number(lockedFrom.balance_cents) < amountCents) throw Object.assign(new Error(`Insufficient ${fromKind} balance.`), { status: 409 });
    await client.query('UPDATE accounts SET balance_cents = balance_cents - $1, updated_at = NOW() WHERE id = $2', [amountCents, from.id]);
    await client.query('UPDATE accounts SET balance_cents = balance_cents + $1, updated_at = NOW() WHERE id = $2', [amountCents, to.id]);
    const outId = uuid();
    const inId = uuid();
    await client.query(
      `INSERT INTO transactions (id, user_id, account_id, type, amount_cents, counterparty, note, related_transaction_id)
       VALUES ($1,$2,$3,'transfer_out',$4,$5,'Internal transfer',$6), ($6,$2,$7,'transfer_in',$8,$9,'Internal transfer',$1)`,
      [outId, req.session.userId, from.id, -amountCents, toKind, inId, to.id, amountCents, fromKind]
    );
  });
  res.json(await userState(req.session.userId));
}));

app.post('/api/deposits', requireAuth, asyncRoute(async (req, res) => {
  const amountCents = centsFrom(req.body.amount);
  const kind = req.body.account;
  if (!amountCents || amountCents < 100) return res.status(400).json({ error: 'Deposits must be at least $1.00.' });
  const account = await accountFor(pool, req.session.userId, kind);
  if (!account) return res.status(404).json({ error: 'Account not found.' });
  const id = uuid();
  await pool.query(
    `INSERT INTO deposit_requests (id, user_id, account_id, amount_cents, expires_at)
     VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')`,
    [id, req.session.userId, account.id, amountCents]
  );
  res.status(201).json({
    id,
    status: 'pending',
    account: kind,
    amount: amountCents / 100,
    command: `firm pay hiss ${moneyFromCents(amountCents)}`,
    demoEnabled: allowDemo
  });
}));

app.get('/api/deposits/:id', requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query('SELECT status, amount_cents, expires_at, completed_at FROM deposit_requests WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
  if (!result.rowCount) return res.status(404).json({ error: 'Deposit request not found.' });
  const row = result.rows[0];
  res.json({ status: row.status, amount: Number(row.amount_cents) / 100, expiresAt: row.expires_at, completedAt: row.completed_at });
}));

app.post('/api/deposits/:id/simulate', requireAuth, asyncRoute(async (req, res) => {
  if (!allowDemo) return res.status(404).json({ error: 'Demo deposit confirmation is disabled.' });
  const ownership = await pool.query('SELECT id FROM deposit_requests WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
  if (!ownership.rowCount) return res.status(404).json({ error: 'Deposit request not found.' });
  await confirmDeposit(req.params.id, `demo-${uuid()}`);
  res.json(await userState(req.session.userId));
}));

app.post('/api/withdrawals', requireAuth, asyncRoute(async (req, res) => {
  const amountCents = centsFrom(req.body.amount);
  const kind = req.body.account;
  if (!amountCents || amountCents < 100) return res.status(400).json({ error: 'Withdrawals must be at least $1.00.' });
  await withTransaction(async client => {
    const account = await accountFor(client, req.session.userId, kind, true);
    if (!account) throw Object.assign(new Error('Account not found.'), { status: 404 });
    if (Number(account.balance_cents) < amountCents) throw Object.assign(new Error(`Insufficient ${kind} balance.`), { status: 409 });
    await client.query('UPDATE accounts SET balance_cents = balance_cents - $1, updated_at = NOW() WHERE id = $2', [amountCents, account.id]);
    await client.query(
      `INSERT INTO transactions (id,user_id,account_id,type,status,amount_cents,counterparty,note)
       VALUES ($1,$2,$3,'withdrawal','pending',$4,$5,'Awaiting Firm payout integration')`,
      [uuid(), req.session.userId, account.id, -amountCents, req.body.username || 'Minecraft account']
    );
  });
  res.json(await userState(req.session.userId));
}));

app.post('/api/payments', requireAuth, asyncRoute(async (req, res) => {
  const type = req.body.type;
  const recipient = String(req.body.recipient || '').replace(/^@/, '').trim();
  const amountCents = centsFrom(req.body.amount);
  const note = safeNote(req.body.note);
  if (!['send', 'request'].includes(type) || !validUsername(recipient) || !amountCents || amountCents < 1) {
    return res.status(400).json({ error: 'Enter a valid recipient, transfer type, and amount.' });
  }
  if (type === 'request') {
    const requestId = uuid();
    await pool.query(
      `INSERT INTO payment_requests (id, requester_id, recipient_username, amount_cents, note) VALUES ($1,$2,$3,$4,$5)`,
      [requestId, req.session.userId, recipient, amountCents, note]
    );
    await pool.query(
      `INSERT INTO transactions (id,user_id,type,status,amount_cents,counterparty,note,metadata)
       VALUES ($1,$2,'request','pending',$3,$4,$5,$6::jsonb)`,
      [uuid(), req.session.userId, amountCents, recipient, note, JSON.stringify({ requestId })]
    );
    return res.status(201).json({ requestId, status: 'pending' });
  }

  const kind = req.body.account;
  await withTransaction(async client => {
    const senderAccount = await accountFor(client, req.session.userId, kind);
    if (!senderAccount) throw Object.assign(new Error('Account not found.'), { status: 404 });
    const recipientResult = await client.query(
      `SELECT u.id AS user_id, u.username, a.id AS account_id
       FROM users u JOIN accounts a ON a.user_id = u.id AND a.kind = 'checking'
       WHERE u.username_key = $1`,
      [usernameKey(recipient)]
    );
    if (!recipientResult.rowCount) throw Object.assign(new Error('That citizen does not have a DC Cash account yet.'), { status: 404 });
    const recipientAccount = recipientResult.rows[0];
    if (recipientAccount.user_id === req.session.userId) throw Object.assign(new Error('Choose another citizen as the recipient.'), { status: 400 });
    const lockedAccounts = await client.query(
      'SELECT id, balance_cents FROM accounts WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE',
      [[senderAccount.id, recipientAccount.account_id]]
    );
    const lockedSender = lockedAccounts.rows.find(row => row.id === senderAccount.id);
    if (!lockedSender || Number(lockedSender.balance_cents) < amountCents) {
      throw Object.assign(new Error(`Insufficient ${kind} balance.`), { status: 409 });
    }
    const senderResult = await client.query('SELECT username FROM users WHERE id = $1', [req.session.userId]);
    await client.query('UPDATE accounts SET balance_cents = balance_cents - $1, updated_at = NOW() WHERE id = $2', [amountCents, senderAccount.id]);
    await client.query('UPDATE accounts SET balance_cents = balance_cents + $1, updated_at = NOW() WHERE id = $2', [amountCents, recipientAccount.account_id]);
    const senderTransactionId = uuid();
    const recipientTransactionId = uuid();
    await client.query(
      `INSERT INTO transactions (id,user_id,account_id,type,status,amount_cents,counterparty,note,related_transaction_id)
       VALUES ($1,$2,$3,'payment','completed',$4,$5,$6,$7),
              ($7,$8,$9,'payment','completed',$10,$11,$6,$1)`,
      [senderTransactionId, req.session.userId, senderAccount.id, -amountCents, recipientAccount.username, note, recipientTransactionId,
        recipientAccount.user_id, recipientAccount.account_id, amountCents, senderResult.rows[0].username]
    );
  });
  res.status(201).json(await userState(req.session.userId));
}));

app.post('/api/integrations/firm/webhook', asyncRoute(async (req, res) => {
  if (!webhookAuthorized(req)) return res.status(401).json({ error: 'Invalid webhook secret.' });
  const payer = String(req.body.payer || '').trim();
  const payee = usernameKey(req.body.payee);
  const amountCents = centsFrom(req.body.amount);
  const firmTransactionId = String(req.body.transactionId || uuid());
  if (!validUsername(payer) || payee !== 'hiss' || !amountCents || amountCents < 1) {
    return res.status(400).json({ error: 'Invalid Firm transaction payload.' });
  }

  const outcome = await withTransaction(async client => {
    const event = await client.query(
      `INSERT INTO firm_webhook_events (transaction_id, payload)
       VALUES ($1, $2::jsonb) ON CONFLICT (transaction_id) DO NOTHING RETURNING transaction_id`,
      [firmTransactionId, JSON.stringify(req.body)]
    );
    if (!event.rowCount) return { matched: false, duplicate: true };

    if (amountCents <= 99) {
      const match = await client.query(
        `UPDATE verification_sessions SET status = 'matched', matched_at = NOW(), firm_transaction_id = $1
         WHERE id = (
           SELECT id FROM verification_sessions
           WHERE username_key = $2 AND amount_cents = $3 AND status = 'pending' AND expires_at > NOW()
           ORDER BY created_at DESC LIMIT 1
         ) RETURNING id`,
        [firmTransactionId, usernameKey(payer), amountCents]
      );
      const matchedId = match.rows[0]?.id || null;
      await client.query("UPDATE firm_webhook_events SET result_type = 'verification', matched_id = $1 WHERE transaction_id = $2", [matchedId, firmTransactionId]);
      return { matched: match.rowCount === 1, type: 'verification', verificationId: matchedId };
    }

    const depositMatch = await client.query(
      `SELECT d.id FROM deposit_requests d JOIN users u ON u.id = d.user_id
       WHERE u.username_key = $1 AND d.amount_cents = $2 AND d.status = 'pending' AND d.expires_at > NOW()
       ORDER BY d.created_at DESC LIMIT 1`,
      [usernameKey(payer), amountCents]
    );
    const depositId = depositMatch.rows[0]?.id || null;
    if (depositId) await confirmDepositWithClient(client, depositId, firmTransactionId);
    await client.query("UPDATE firm_webhook_events SET result_type = 'deposit', matched_id = $1 WHERE transaction_id = $2", [depositId, firmTransactionId]);
    return { matched: Boolean(depositId), type: 'deposit', depositId };
  });
  res.json(outcome);
}));

const sendApp = (_req, res) => res.sendFile(path.join(__dirname, 'index.html'));
app.get('/', sendApp);
app.get('/index.html', sendApp);
app.get('/favicon.ico', (_req, res) => res.status(204).end());

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((error, _req, res, _next) => {
  const status = Number(error.status || 500);
  if (status >= 500) console.error(error);
  res.status(status).json({ error: status >= 500 ? 'An unexpected server error occurred.' : error.message });
});

async function start() {
  await migrate();
  app.listen(port, '0.0.0.0', () => console.log(`DC Cash listening on 0.0.0.0:${port}`));
}

start().catch(error => {
  console.error('Failed to start DC Cash', error);
  process.exit(1);
});

