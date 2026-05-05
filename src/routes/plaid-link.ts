/**
 * Plaid Link Routes (s149 t624 + t626 — REWRITTEN cycle 220).
 *
 * Architectural correction from cycle 215: Plaid integration only works
 * via Hive-ID (it's the only publicly-accessible piece of the stack;
 * Plaid requires public HTTPS for webhook + OAuth-redirect institutions;
 * client_id+secret never ship in agi/Local-ID source per
 * `feedback_localid_private_be_careful_what_ships_in_agi`).
 *
 * The cycle 211 implementation called Plaid directly + read PLAID_*_VAULT
 * refs from agi Vault. That's now obsolete. This file flips to a
 * pure-forwarding shape: routes here delegate to Hive-ID's
 * /api/oauth/plaid-link/* + store the DToken Hive-ID returns, never
 * touching Plaid's API directly.
 *
 * Routes (unchanged URL surface from cycle 211 — the dashboard.html JS
 * doesn't need updating):
 *   POST /create-link-token       — forwards to Hive-ID, returns linkToken
 *   POST /exchange-public-token    — forwards to Hive-ID; receives DToken;
 *                                    stores in connections; returns
 *                                    { itemId, accountLabel } to caller
 *   POST /items/:itemId/remove     — forwards proxy call to Hive-ID
 *                                    /api/proxy/plaid/item-remove
 *                                    + drops local connection row
 *   GET  /items                    — lists local connections (from local
 *                                    DB — no need to round-trip Hive-ID)
 *   GET  /token                    — DEPRECATED. Returns 410 with note
 *                                    that the agi-side flips to per-tool
 *                                    proxy routes (t627).
 */

import { eq, and, like } from "drizzle-orm";
import { Hono, type Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { nanoid } from "nanoid";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections, users } from "../db/schema.js";
import { getCookie } from "hono/cookie";
import {
  forwardToHive,
  forwardToHiveProxy,
  storeDTokenOnConnection,
} from "../services/hive-forward.js";

type PlaidLinkEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

async function resolveOrCreateLocalOwner(db: DrizzleDb, accountLabelHint: string): Promise<string> {
  const [firstUser] = await db.select({ id: users.id }).from(users).limit(1);
  if (firstUser) return firstUser.id;
  const principal = (accountLabelHint?.toLowerCase() || "owner").replace(/[^a-z0-9_-]/g, "") || "owner";
  const id = randomId();
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

function randomId(): string {
  // Reuse nanoid for consistency with rest of codebase
  return nanoid();
}

function captureCookieHeader(c: Context): string | undefined {
  const cookies: string[] = [];
  for (const name of [
    "aionima_session", "auth_session", "session",
  ]) {
    const v = getCookie(c, name);
    if (v) cookies.push(`${name}=${v}`);
  }
  return cookies.length ? cookies.join("; ") : undefined;
}

export function plaidLinkRoutes(db: DrizzleDb) {
  const app = new Hono<PlaidLinkEnv>();

  // ---------------------------------------------------------------------
  // POST /create-link-token — forward to Hive-ID
  // ---------------------------------------------------------------------
  app.post("/create-link-token", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const body = (await c.req.json().catch(() => ({}))) as { clientUserId?: string };
    const cookieHeader = captureCookieHeader(c);

    const result = await forwardToHive(
      "/api/oauth/plaid-link/create-link-token",
      body,
      cookieHeader,
    );

    return c.json(result.body as Record<string, unknown>, result.status as ContentfulStatusCode);
  });

  // ---------------------------------------------------------------------
  // POST /exchange-public-token — forward + store DToken locally
  // ---------------------------------------------------------------------
  app.post("/exchange-public-token", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const body = (await c.req.json().catch(() => ({}))) as {
      publicToken?: string;
      institutionName?: string;
      institutionId?: string;
    };
    if (!body.publicToken) return c.json({ error: "publicToken required" }, 400);

    const cookieHeader = captureCookieHeader(c);
    const result = await forwardToHive(
      "/api/oauth/plaid-link/exchange-public-token",
      { ...body, nodeId: "local-id" },
      cookieHeader,
    );

    if (!result.ok) {
      return c.json(result.body as Record<string, unknown>, result.status as ContentfulStatusCode);
    }

    const hiveResp = result.body as { dtoken?: string; itemId?: string; accountLabel?: string };
    if (!hiveResp.dtoken || !hiveResp.itemId) {
      return c.json({ error: "Hive-ID response missing dtoken or itemId" }, 502);
    }

    // Mirror the connection row at Local-ID — multi-bank role-encoding
    // matches Hive-ID's pattern (role="plaid-item:<itemId>"). DToken
    // stored encrypted in connections.dtoken.
    const userId = await resolveOrCreateLocalOwner(db, hiveResp.accountLabel ?? "Plaid Item");
    const role = `plaid-item:${hiveResp.itemId}`;
    const accountLabel = hiveResp.accountLabel ?? "Plaid Item";

    const [existing] = await db
      .select()
      .from(connections)
      .where(
        and(
          eq(connections.userId, userId),
          eq(connections.provider, "plaid"),
          eq(connections.role, role),
        ),
      )
      .limit(1);

    let connectionId: string;
    if (existing) {
      connectionId = existing.id;
      await db
        .update(connections)
        .set({ accountLabel, scopes: body.institutionId ?? null, updatedAt: new Date() })
        .where(eq(connections.id, existing.id));
    } else {
      connectionId = randomId();
      await db.insert(connections).values({
        id: connectionId,
        userId,
        provider: "plaid",
        role,
        accountLabel,
        accessToken: null, // raw access_token NEVER stored at Local-ID for Plaid
        refreshToken: null,
        tokenExpiresAt: null,
        scopes: body.institutionId ?? null,
      });
    }

    // Store the DToken (encrypted)
    await storeDTokenOnConnection(db, connectionId, hiveResp.dtoken);

    return c.json({ itemId: hiveResp.itemId, accountLabel });
  });

  // ---------------------------------------------------------------------
  // POST /items/:itemId/remove — forward via proxy + drop local row
  // ---------------------------------------------------------------------
  app.post("/items/:itemId/remove", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) return c.json({ error: "Unauthorized" }, 401);

    const itemId = c.req.param("itemId");
    if (!itemId) return c.json({ error: "itemId required" }, 400);

    const role = `plaid-item:${itemId}`;
    const [conn] = await db
      .select()
      .from(connections)
      .where(and(eq(connections.provider, "plaid"), eq(connections.role, role)))
      .limit(1);

    if (!conn) return c.json({ error: "no such item" }, 404);

    // Forward proxy call to Hive-ID — best effort. If it fails (Hive-ID
    // unreachable, DToken expired), still drop the local row so user can
    // re-link.
    const hiveResult = await forwardToHiveProxy(
      db,
      conn.userId,
      "plaid",
      role,
      "item-remove",
      {},
    );

    await db.delete(connections).where(eq(connections.id, conn.id));

    return c.json({
      ok: true,
      hiveStatus: hiveResult.status,
      note: hiveResult.ok ? "item removed at Plaid + locally" : "local row dropped; Plaid notification may have failed",
    });
  });

  // ---------------------------------------------------------------------
  // GET /items — list locally-known Plaid items (no Hive-ID round-trip)
  // ---------------------------------------------------------------------
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
      .where(and(eq(connections.provider, "plaid"), like(connections.role, "plaid-item:%")));

    return c.json(
      rows.map((r) => ({
        itemId: r.role.startsWith("plaid-item:") ? r.role.slice("plaid-item:".length) : r.role,
        accountLabel: r.accountLabel ?? "Plaid Item",
        institutionId: r.scopes ?? null,
        connectedAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
      })),
    );
  });

  // ---------------------------------------------------------------------
  // GET /token — DEPRECATED (cycle 211 used this for raw access_token
  // broker; cycle 220 architecture eliminates raw-token transfer)
  // ---------------------------------------------------------------------
  app.get("/token", (c) =>
    c.json(
      {
        error:
          "deprecated — Plaid integration uses DToken proxy via /api/proxy/plaid/<endpoint> (s149 t627 wires the agi-side plugin to call Local-ID per-tool routes which forward to Hive-ID's gateway). Raw access_tokens are never transferred under the unified Hive-ID-brokered architecture.",
        reason: "deprecated",
        replacedBy: "/api/proxy/plaid/<endpoint>",
      },
      410,
    ),
  );

  return app;
}
