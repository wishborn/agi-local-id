/**
 * Plaid Link Routes — implements Plaid Link (OAuth-style) for connecting
 * bank accounts to the local node.
 *
 * Architecturally parallel to device-flow.ts:
 *   - Local-ID hosts the user-facing "Connect Bank Account" UI in the
 *     dashboard
 *   - Plaid Link's browser-side widget initiates the flow
 *   - Local-ID exchanges the resulting public_token for a long-lived
 *     access_token and stores it encrypted in the connections table
 *   - agi-side plugin (s147 t615, future) consumes brokered tokens via
 *     GET /api/auth/plaid-link/token
 *
 * Multi-bank support: the connections table's unique index is
 * (user_id, provider, role). For Plaid, we encode the Plaid item_id into
 * the role field as `plaid-item:<item_id>` so a single user can link
 * multiple banks without schema migration.
 *
 * Secret handling: PLAID_CLIENT_ID + PLAID_SECRET live as Vault entries
 * (gateway-scoped, TPM2-sealed via the existing ~/.agi/secrets/vault/
 * pipeline). The Vault entry IDs come from env vars
 * (PLAID_CLIENT_ID_VAULT_REF + PLAID_SECRET_VAULT_REF). Local-ID resolves
 * them on demand by calling the agi gateway's Vault API on the private
 * network. Per `feedback_localid_private_be_careful_what_ships_in_agi`,
 * nothing Plaid-related is hardcoded in source.
 *
 * CSRF: not registered — `/api/auth/plaid-link/*` is exempt the same way
 * `/api/auth/device-flow/*` is. The private-network owner gate inside
 * each handler is the credential.
 *
 * Routes:
 *   POST /api/auth/plaid-link/create-link-token
 *   POST /api/auth/plaid-link/exchange-public-token
 *   GET  /api/auth/plaid-link/token?provider=plaid&role=plaid-item:<id>
 *   POST /api/auth/plaid-link/items/:itemId/remove
 */

import { randomBytes } from "node:crypto";
import { eq, and, like } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections, users } from "../db/schema.js";
import { encrypt, decrypt } from "../crypto.js";
import { getConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type PlaidLinkEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

interface PlaidCreds {
  clientId: string;
  secret: string;
}

// ---------------------------------------------------------------------------
// Plaid environment URLs
// ---------------------------------------------------------------------------

function plaidApiBase(env: "sandbox" | "development" | "production"): string {
  switch (env) {
    case "sandbox": return "https://sandbox.plaid.com";
    case "development": return "https://development.plaid.com";
    case "production": return "https://production.plaid.com";
  }
}

// ---------------------------------------------------------------------------
// Vault helper — fetches PLAID_CLIENT_ID + PLAID_SECRET from agi gateway
// ---------------------------------------------------------------------------

/**
 * Fetch a single Vault entry's value from the agi gateway.
 * Vault entries are gateway-scoped (no requestingProject param) for
 * Plaid credentials — they're system-level secrets used by Local-ID
 * during OAuth + by agi plugin tools during API calls.
 */
async function fetchVaultValue(vaultEntryId: string): Promise<string> {
  const cfg = getConfig();
  const url = `${cfg.gatewayUrl}/api/vault/${encodeURIComponent(vaultEntryId)}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`vault read failed (${res.status}): ${text.slice(0, 200)}`);
  }
  const body = await res.json() as { entry?: { id: string }; value?: string };
  if (typeof body.value !== "string" || body.value.length === 0) {
    throw new Error("vault entry returned empty value");
  }
  return body.value;
}

/**
 * Resolve PLAID_CLIENT_ID + PLAID_SECRET from Vault. Throws if either
 * env var holding the Vault entry ID is missing or if the Vault read
 * fails. Surface the error to the caller so the dashboard can render a
 * helpful message ("Configure Plaid in Vault first").
 */
async function resolvePlaidCreds(): Promise<PlaidCreds> {
  const cfg = getConfig();
  if (!cfg.plaid.clientIdVaultRef) {
    throw new Error("PLAID_CLIENT_ID_VAULT_REF env var not set; configure Plaid client ID in Vault first");
  }
  if (!cfg.plaid.secretVaultRef) {
    throw new Error("PLAID_SECRET_VAULT_REF env var not set; configure Plaid secret in Vault first");
  }
  const [clientId, secret] = await Promise.all([
    fetchVaultValue(cfg.plaid.clientIdVaultRef),
    fetchVaultValue(cfg.plaid.secretVaultRef),
  ]);
  return { clientId, secret };
}

// ---------------------------------------------------------------------------
// Local owner resolution — mirrors device-flow.ts
// ---------------------------------------------------------------------------

async function resolveOrCreateLocalOwner(db: DrizzleDb, accountLabelHint: string): Promise<string> {
  const [firstUser] = await db.select({ id: users.id }).from(users).limit(1);
  if (firstUser) return firstUser.id;

  const principal = (accountLabelHint?.toLowerCase() || "owner").replace(/[^a-z0-9_-]/g, "") || "owner";
  const id = randomBytes(16).toString("hex");
  try {
    await db.insert(users).values({
      id,
      authBackend: "virtual",
      principal,
      username: principal,
      displayName: accountLabelHint || "Owner",
      dashboardRole: "admin",
    });
  } catch {
    const [again] = await db.select({ id: users.id }).from(users).limit(1);
    return again?.id ?? id;
  }
  return id;
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function plaidLinkRoutes(db: DrizzleDb) {
  const app = new Hono<PlaidLinkEnv>();

  /**
   * POST /create-link-token
   *
   * Creates a Plaid `link_token` server-side. The browser uses this token
   * to initialize the Plaid Link widget. Token is short-lived (~30 min).
   *
   * Body: { role?: string }  (default "owner"; not used for ownership
   *   distinction in Plaid — multi-bank uses role="plaid-item:<id>" once
   *   exchange happens.)
   *
   * Returns: { linkToken, expiration }
   */
  app.post("/create-link-token", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    let creds: PlaidCreds;
    try {
      creds = await resolvePlaidCreds();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: msg, reason: "vault_unavailable" }, 503);
    }

    const cfg = getConfig();
    const userId = user?.id ?? "owner";

    const body = {
      client_id: creds.clientId,
      secret: creds.secret,
      user: { client_user_id: userId },
      client_name: "Aionima",
      products: ["transactions"],
      country_codes: ["US"],
      language: "en",
    };

    let data: { link_token?: string; expiration?: string; error_code?: string; error_message?: string };
    try {
      const res = await fetch(`${plaidApiBase(cfg.plaid.env)}/link/token/create`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
      data = await res.json() as typeof data;
      if (!res.ok || !data.link_token) {
        return c.json({
          error: data.error_message ?? `Plaid returned ${res.status}`,
          plaidErrorCode: data.error_code,
        }, 502);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: `Failed to reach Plaid: ${msg}` }, 502);
    }

    return c.json({
      linkToken: data.link_token,
      expiration: data.expiration ?? null,
    });
  });

  /**
   * POST /exchange-public-token
   *
   * After the user completes the Plaid Link widget in the browser,
   * Plaid returns a `public_token` + institution metadata. The browser
   * POSTs them here; we exchange for a long-lived `access_token` and
   * store it encrypted in the connections table.
   *
   * Body: { publicToken, institutionName?, institutionId? }
   * Returns: { itemId, accountLabel }
   */
  app.post("/exchange-public-token", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const body = await c.req.json().catch(() => ({})) as {
      publicToken?: string;
      institutionName?: string;
      institutionId?: string;
    };
    if (!body.publicToken) {
      return c.json({ error: "publicToken is required" }, 400);
    }

    let creds: PlaidCreds;
    try {
      creds = await resolvePlaidCreds();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: msg, reason: "vault_unavailable" }, 503);
    }

    const cfg = getConfig();

    let data: { access_token?: string; item_id?: string; error_code?: string; error_message?: string };
    try {
      const res = await fetch(`${plaidApiBase(cfg.plaid.env)}/item/public_token/exchange`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          client_id: creds.clientId,
          secret: creds.secret,
          public_token: body.publicToken,
        }),
        signal: AbortSignal.timeout(10_000),
      });
      data = await res.json() as typeof data;
      if (!res.ok || !data.access_token || !data.item_id) {
        return c.json({
          error: data.error_message ?? `Plaid returned ${res.status}`,
          plaidErrorCode: data.error_code,
        }, 502);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: `Failed to reach Plaid: ${msg}` }, 502);
    }

    const accessToken = data.access_token;
    const itemId = data.item_id;
    const accountLabel = body.institutionName ?? "Plaid Item";

    const userId = await resolveOrCreateLocalOwner(db, accountLabel);
    const role = `plaid-item:${itemId}`;
    const now = new Date();
    const encAccessToken = encrypt(accessToken);

    const [existing] = await db
      .select()
      .from(connections)
      .where(and(
        eq(connections.userId, userId),
        eq(connections.provider, "plaid"),
        eq(connections.role, role),
      ))
      .limit(1);

    if (existing) {
      await db
        .update(connections)
        .set({
          accountLabel,
          accessToken: encAccessToken,
          tokenExpiresAt: null,
          scopes: body.institutionId ?? null,
          updatedAt: now,
        })
        .where(eq(connections.id, existing.id));
    } else {
      await db.insert(connections).values({
        id: randomBytes(16).toString("hex"),
        userId,
        provider: "plaid",
        role,
        accountLabel,
        accessToken: encAccessToken,
        refreshToken: null,
        tokenExpiresAt: null,
        scopes: body.institutionId ?? null,
        createdAt: now,
        updatedAt: now,
      });
    }

    return c.json({ itemId, accountLabel });
  });

  /**
   * GET /token?provider=plaid&role=plaid-item:<itemId>
   *
   * Mirrors device-flow's /token broker shape exactly so the agi-side
   * plugin can use the same caller pattern as dev-mode-auth.ts. Returns
   * the decrypted Plaid access_token to private-network owner callers.
   *
   * Plaid access_tokens never expire (Plaid's design — they're invalidated
   * by `/item/remove` or by the user revoking access in their bank
   * portal), so tokenExpiresAt is always null in the response.
   *
   * Response: { provider, role, accountLabel, accessToken, tokenType,
   *   tokenExpiresAt, scopes }
   * On miss: 404 { error: "no such connection" }
   */
  app.get("/token", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const provider = c.req.query("provider");
    const role = c.req.query("role") ?? "owner";

    if (!provider || provider !== "plaid") {
      return c.json({ error: 'provider query param must be "plaid"' }, 400);
    }

    const [row] = await db
      .select()
      .from(connections)
      .where(and(eq(connections.provider, "plaid"), eq(connections.role, role)))
      .limit(1);

    if (!row || !row.accessToken) {
      return c.json({ error: "no such connection" }, 404);
    }

    let accessToken: string;
    try {
      accessToken = decrypt(row.accessToken);
    } catch {
      return c.json({ error: "connection token corrupt" }, 500);
    }

    return c.json({
      provider: row.provider,
      role: row.role,
      accountLabel: row.accountLabel,
      accessToken,
      tokenType: "Bearer",
      tokenExpiresAt: null,
      scopes: row.scopes,
    });
  });

  /**
   * POST /items/:itemId/remove
   *
   * Disconnect a linked Plaid item: tells Plaid to revoke the access_token
   * server-side via /item/remove, then deletes the connections row. This
   * is the Plaid-specific cleanup path; GitHub has no equivalent.
   *
   * Returns: { ok: true }
   * On miss: 404 { error: "no such item" }
   */
  app.post("/items/:itemId/remove", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const itemId = c.req.param("itemId");
    if (!itemId) return c.json({ error: "itemId is required" }, 400);

    const role = `plaid-item:${itemId}`;
    const [row] = await db
      .select()
      .from(connections)
      .where(and(eq(connections.provider, "plaid"), eq(connections.role, role)))
      .limit(1);

    if (!row || !row.accessToken) {
      return c.json({ error: "no such item" }, 404);
    }

    let accessToken: string;
    try {
      accessToken = decrypt(row.accessToken);
    } catch {
      // Token corrupt — best-effort: drop the row anyway, can't notify Plaid
      await db.delete(connections).where(eq(connections.id, row.id));
      return c.json({ ok: true, note: "local row removed; Plaid not notified (token corrupt)" });
    }

    let creds: PlaidCreds;
    try {
      creds = await resolvePlaidCreds();
    } catch {
      // Vault unavailable — drop the local row anyway, log that Plaid
      // wasn't notified. The owner can manually revoke at Plaid if needed.
      await db.delete(connections).where(eq(connections.id, row.id));
      return c.json({ ok: true, note: "local row removed; Plaid not notified (vault unavailable)" });
    }

    const cfg = getConfig();
    try {
      await fetch(`${plaidApiBase(cfg.plaid.env)}/item/remove`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          client_id: creds.clientId,
          secret: creds.secret,
          access_token: accessToken,
        }),
        signal: AbortSignal.timeout(10_000),
      });
      // Treat any HTTP response as "Plaid notified" — even 4xx means the
      // item is invalidated on their side. We always drop the local row.
    } catch {
      // Network failure — proceed with local cleanup, owner can manually
      // revoke at Plaid if needed.
    }

    await db.delete(connections).where(eq(connections.id, row.id));
    return c.json({ ok: true });
  });

  /**
   * GET /items
   *
   * List all linked Plaid items (metadata only — no access_tokens).
   * Used by the dashboard to render the "Banks (Plaid)" section.
   *
   * Returns: [{ itemId, accountLabel, institutionId, connectedAt }]
   */
  app.get("/items", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const rows = await db
      .select({
        role: connections.role,
        accountLabel: connections.accountLabel,
        scopes: connections.scopes,
        createdAt: connections.createdAt,
        updatedAt: connections.updatedAt,
      })
      .from(connections)
      .where(and(
        eq(connections.provider, "plaid"),
        like(connections.role, "plaid-item:%"),
      ));

    return c.json(rows.map((r) => ({
      itemId: r.role.startsWith("plaid-item:") ? r.role.slice("plaid-item:".length) : r.role,
      accountLabel: r.accountLabel ?? "Plaid Item",
      institutionId: r.scopes ?? null,
      connectedAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    })));
  });

  return app;
}
