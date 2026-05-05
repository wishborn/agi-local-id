/**
 * Hive-ID forwarding helpers (s149 t626).
 *
 * Local-ID forwards proxy + OAuth-bootstrap calls to Hive-ID. These
 * helpers wrap the fetch + DToken-auth pattern so route files don't
 * repeat it. Hive-ID is the public-internet service hosting third-party
 * brokering (Plaid + Google + Discord per the cycle-215 unification).
 *
 * Auth model: Local-ID is on the same private network as the AGI
 * gateway. Hive-ID is reachable over public HTTPS. Hive-ID validates
 * sessions for OAuth-bootstrap calls (user must be authenticated at
 * Hive-ID). For proxy calls, Hive-ID accepts DToken bearer auth.
 */

import { eq, and } from "drizzle-orm";
import type { DrizzleDb } from "../db/client.js";
import { connections } from "../db/schema.js";
import { encrypt, decrypt } from "../crypto.js";
import { getConfig } from "../config.js";

export interface HiveProxyResult {
  ok: boolean;
  status: number;
  body: unknown;
}

/**
 * Look up the DToken for a given (userId, provider, role) and forward a
 * proxy call to Hive-ID. Returns Hive-ID's response shape.
 */
export async function forwardToHiveProxy(
  db: DrizzleDb,
  userId: string,
  provider: string,
  role: string,
  endpoint: string,
  body: Record<string, unknown>,
): Promise<HiveProxyResult> {
  const [conn] = await db
    .select({ dtoken: connections.dtoken })
    .from(connections)
    .where(
      and(
        eq(connections.userId, userId),
        eq(connections.provider, provider),
        eq(connections.role, role),
      ),
    )
    .limit(1);

  if (!conn || !conn.dtoken) {
    return {
      ok: false,
      status: 404,
      body: { error: `no DToken for ${provider}:${role}; reconnect at Hive-ID` },
    };
  }

  let dtoken: string;
  try {
    dtoken = decrypt(conn.dtoken);
  } catch {
    return { ok: false, status: 500, body: { error: "DToken corrupt; re-link the account" } };
  }

  const cfg = getConfig();
  const url = `${cfg.hiveIdBaseUrl}/api/proxy/${provider}/${endpoint}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${dtoken}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { ok: res.ok, status: res.status, body: parsed };
}

/**
 * Store a DToken (encrypted) on a connection row. Used after Hive-ID
 * mints a DToken during OAuth completion and Local-ID receives it.
 */
export async function storeDTokenOnConnection(
  db: DrizzleDb,
  connectionId: string,
  dtoken: string,
): Promise<void> {
  await db
    .update(connections)
    .set({ dtoken: encrypt(dtoken), updatedAt: new Date() })
    .where(eq(connections.id, connectionId));
}

/**
 * Forward a generic POST to Hive-ID without DToken auth (used for
 * OAuth-bootstrap routes that authenticate via the calling user's Hive-ID
 * session cookie — owner authenticates at Hive-ID directly via the
 * Plaid Link UI redirect path; Local-ID isn't in the auth chain for
 * Hive-ID OAuth bootstrap).
 *
 * Returns { ok, status, body }.
 */
export async function forwardToHive(
  path: string,
  body: Record<string, unknown>,
  cookieHeader?: string,
): Promise<HiveProxyResult> {
  const cfg = getConfig();
  const url = `${cfg.hiveIdBaseUrl}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { ok: res.ok, status: res.status, body: parsed };
}
