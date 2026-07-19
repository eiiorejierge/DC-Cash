# DemocracyCraft Cash

A Railway-ready Node.js and PostgreSQL banking portal for DemocracyCraft. The website supports Firm payment verification, five-digit PIN login, checking and savings accounts, deposits, withdrawals, citizen payments, requests, and an account ledger.

## What is connected

- PostgreSQL stores users, hashed PINs, sessions, both account balances, verification attempts, deposit listeners, payment requests, and transactions.
- Browser sessions are stored in PostgreSQL, so signing in survives a server restart.
- Firm verification listens for `firm pay hiss 0.01` through `firm pay hiss 0.99`.
- Deposits create a ten-minute listener for the exact `firm pay hiss <amount>` payment.
- Duplicate Firm transaction IDs are recorded once and cannot credit an account twice.
- Payments between two registered DC Cash users move money into the recipient's checking account in one database transaction.
- Database migrations run automatically whenever the server starts.
- Railway can monitor `GET /health` before routing traffic to a new deployment.

Withdrawals are currently recorded as pending and reserve the balance. Connect the real Firm payout API before treating them as completed in-game payouts.

## Deploy on Railway

1. Put this folder in a GitHub repository. If the repository contains other folders, set the Railway service's **Root Directory** to `/outputs/democracycraft-cash`.
2. In Railway, create a project and deploy the repository as a service.
3. Add a **PostgreSQL** service to the same Railway project.
4. Add these variables to the website service:

   - `DATABASE_URL=${{Postgres.DATABASE_URL}}`
   - `NODE_ENV=production`
   - `SESSION_SECRET=<a random value at least 32 characters long>`
   - `FIRM_WEBHOOK_SECRET=<a separate long random value>`
   - `ALLOW_DEMO_VERIFICATION=false`
   - `PGSSL=false`

5. Open the website service's **Networking** settings and generate a public domain.

Railway uses the included `Dockerfile`, passes its assigned `PORT`, and checks `/health`. No build or start command needs to be entered manually.

## Firm webhook contract

Configure the future Firm API listener to send completed incoming payments to:

`POST https://<your-domain>/api/integrations/firm/webhook`

Headers:

```text
Content-Type: application/json
x-firm-secret: <the FIRM_WEBHOOK_SECRET value>
```

Example body:

```json
{
  "transactionId": "firm-unique-transaction-id",
  "payer": "MinecraftUsername",
  "payee": "hiss",
  "amount": 25.5
}
```

The `transactionId` must be stable and unique. Payments below $1 match login verification attempts. Payments of $1 or more match deposit requests.

## Run locally

Requirements: Node.js 20+ and PostgreSQL.

1. Copy `.env.example` to `.env` and update the values.
2. Create the database named in `DATABASE_URL`.
3. Run `npm install`.
4. Run `npm run dev`.
5. Open `http://localhost:3000`.

With `NODE_ENV=development` and `ALLOW_DEMO_VERIFICATION=true`, verification and deposit screens include simulation controls so the whole flow can be tested without the Firm API.

## Before real-money use

This is a deployable application foundation, not a finished regulated banking system. Before using it for valuable in-game funds, add the real Firm withdrawal/payout adapter, administrator reconciliation tools, automated PostgreSQL backups, audit monitoring, and server-specific fraud and account-recovery rules.

