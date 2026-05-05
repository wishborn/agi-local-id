/**
 * Generic /api/proxy/<provider>/<endpoint> forwarding (s149 t626).
 *
 * Local-ID's outward-facing proxy surface for the agi gateway. Each
 * call is forwarded to Hive-ID with the appropriate DToken bearer auth.
 * This is the route shape the agi plugin (t627) will call.
 *
 * Auth model: gateway → Local-ID is private-network only (per
 * `feedback_id_owns_identity_not_agi` + the LAN-IS-the-credential
 * pattern from network-identity.ts). Local-ID → Hive-ID uses Bearer
 * DToken (issued by Hive-ID at OAuth completion, stored encrypted in
 * Local-ID's connections.dtoken).
 *
 * Body shape: any JSON; Local-ID adds nothing — passes through to Hive-ID.
 *
 * For multi-instance providers (Plaid items, Google channels), the
 * caller must specify which connection to use via the `role` query param
 * (e.g. ?role=plaid-item:<itemId>). Default role="owner".
 */

import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { forwardToHiveProxy } from "../services/hive-forward.js";

type ProxyEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

export function proxyForwardRoutes(db: DrizzleDb) {
  const app = new Hono<ProxyEnv>();

  // POST /:provider/:endpoint
  app.post("/:provider/:endpoint", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const provider = c.req.param("provider");
    const endpoint = c.req.param("endpoint");
    const role = c.req.query("role") ?? "owner";

    if (!user && !identity) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Identify the user-of-record. In private-network owner mode without
    // a Lucia session, fall back to "the first user" (single-tenant
    // assumption — same as device-flow.ts:resolveOrCreateLocalOwner).
    // For session-authenticated users, use their id directly.
    const userId = user?.id ?? null;
    if (!userId) {
      // Look up first user as the owner — Local-ID is single-tenant per
      // the existing pattern. If no user exists, return 404.
      const { users } = await import("../db/schema.js");
      const [first] = await db.select({ id: users.id }).from(users).limit(1);
      if (!first) {
        return c.json({ error: "no Local-ID user; complete bootstrap first" }, 404);
      }
      const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
      const result = await forwardToHiveProxy(db, first.id, provider, role, endpoint, body);
      return c.json(result.body as Record<string, unknown>, result.status as ContentfulStatusCode);
    }

    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const result = await forwardToHiveProxy(db, userId, provider, role, endpoint, body);
    return c.json(result.body as Record<string, unknown>, result.status as ContentfulStatusCode);
  });

  return app;
}
