/**
 * Device Flow Routes — implements RFC 8628 OAuth 2.0 Device Authorization Grant.
 *
 * Unlike the standard OAuth delegation flow (which requires a public callback
 * URL via Hive-ID), Device Flow is fully self-contained: the provider sends
 * the user to a verification URL and Local-ID polls for the token. This works
 * on any network without any public-facing redirect URI.
 *
 * Supported providers: GitHub, Google, Discord
 *
 * Flow:
 *   1. POST /api/auth/device-flow/start  → initiates with provider, returns
 *      user_code + verification_uri for the user to visit in a browser.
 *   2. GET  /api/auth/device-flow/poll?deviceCode=...  → polls the provider
 *      token endpoint. Returns pending/expired/completed status.
 *      On completion, stores encrypted tokens in the connections table.
 *   3. GET  /api/auth/device-flow/status → lists stored connections.
 *   4. POST /api/auth/device-flow/refresh → refreshes a Google access token
 *      using its stored refresh token.
 */

import { randomBytes } from "node:crypto";
import { eq, and } from "drizzle-orm";
import { Hono } from "hono";
import { nanoid } from "nanoid";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections, users, handoffs } from "../db/schema.js";
import { encrypt, decrypt } from "../crypto.js";
import { getConfig } from "../config.js";
// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type DeviceFlowEnv = AuthEnv & { Variables: AuthEnv["Variables"] & { identity?: NetworkIdentity } };

type ProviderName = "github" | "google" | "discord";

/** Data stored encrypted in handoffs.connectedServices for device-flow sessions. */
interface DeviceSessionData {
  provider: ProviderName;
  role: string;
  interval: number;
}

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

const PROVIDERS: Record<ProviderName, {
  deviceCodeUrl: string;
  tokenUrl: string;
  scopes: string;
  grantType: string;
}> = {
  github: {
    deviceCodeUrl: "https://github.com/login/device/code",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scopes: "repo read:user user:email",
    grantType: "urn:ietf:params:oauth:grant-type:device_code",
  },
  google: {
    deviceCodeUrl: "https://oauth2.googleapis.com/device/code",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: "https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email",
    grantType: "urn:ietf:params:oauth:grant-type:device_code",
  },
  discord: {
    deviceCodeUrl: "https://discord.com/api/v10/oauth2/device/authorize",
    tokenUrl: "https://discord.com/api/v10/oauth2/token",
    scopes: "identify guilds",
    grantType: "urn:ietf:params:oauth:grant-type:device_code",
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// GitHub: public client — device flow works without client_secret.
// Google/Discord: require client_secret held by Hive-ID. These providers
// delegate through Hive-ID which brokers the token exchange.
const GITHUB_CLIENT_ID = "Ov23liMC3zFFaNwtg58t";

// Providers that work locally (no Hive-ID dependency)
const LOCAL_PROVIDERS = new Set<ProviderName>(["github"]);

// Providers that require Hive-ID to broker the OAuth exchange
const HIVE_BROKERED_PROVIDERS = new Set<ProviderName>(["google", "discord"]);

/**
 * Resolve the local user ID to attach connections to. Local-ID is
 * single-tenant by default — the first user is "the owner" for purposes
 * of OAuth connection ownership.
 *
 * If no user row exists yet (fresh install, owner connecting GitHub
 * before they've created a dashboard login), auto-provision a minimal
 * virtual-backend owner row so the connections insert has a valid FK
 * target. The GitHub accountLabel is used as a display hint; the owner
 * can rename / set a password later via the /auth/register form and the
 * row will be adopted as their profile.
 */
async function resolveOrCreateLocalOwner(
  db: DrizzleDb,
  accountLabelHint: string,
): Promise<string> {
  const [firstUser] = await db.select({ id: users.id }).from(users).limit(1);
  if (firstUser) return firstUser.id;

  // No users yet — provision one. Principal/username are lowercased + fall
  // back to "owner" if GitHub didn't give us a label.
  const principal = (accountLabelHint?.toLowerCase() || "owner").replace(
    /[^a-z0-9_-]/g,
    "",
  ) || "owner";
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
    // Someone raced us — read whatever landed
    const [again] = await db.select({ id: users.id }).from(users).limit(1);
    return again?.id ?? id;
  }
  return id;
}

/**
 * Fetch the account label (username/email) from the provider's user info endpoint.
 * Non-fatal — returns empty string on failure.
 */
async function fetchAccountLabel(
  provider: ProviderName,
  accessToken: string,
  tokenType: string,
): Promise<string> {
  try {
    if (provider === "github") {
      const res = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `${tokenType} ${accessToken}`,
          "User-Agent": "Aionima-Local-ID",
        },
      });
      const user = await res.json() as { login?: string };
      return user.login ?? "";
    }

    if (provider === "google") {
      const res = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const user = await res.json() as { email?: string };
      return user.email ?? "";
    }

    if (provider === "discord") {
      const res = await fetch("https://discord.com/api/v10/users/@me", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const user = await res.json() as { global_name?: string; username?: string };
      return user.global_name ?? user.username ?? "";
    }
  } catch {
    // Non-fatal — account label is display-only
  }
  return "";
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function deviceFlowRoutes(db: DrizzleDb) {
  const app = new Hono<DeviceFlowEnv>();

  /**
   * POST /start
   *
   * Initiates a device authorization flow with the given provider.
   * Body: { provider: "github" | "google" | "discord", role?: string }
   * Returns: { deviceCode, userCode, verificationUri, expiresIn, interval }
   */
  app.post("/start", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as { provider?: string; role?: string };
    const provider = body.provider as ProviderName | undefined;
    const role = body.role ?? "owner";

    if (!provider || !(provider in PROVIDERS)) {
      return c.json(
        { error: `Invalid provider. Supported: ${Object.keys(PROVIDERS).join(", ")}` },
        400,
      );
    }

    // Google and Discord require Hive-ID to broker the OAuth exchange
    // (their client_secret is held by Hive-ID, not shipped in the codebase).
    if (HIVE_BROKERED_PROVIDERS.has(provider)) {
      const cfg = getConfig();
      const hiveUrl = cfg.hiveIdUrl;
      try {
        const healthRes = await fetch(`${hiveUrl}/health`, { signal: AbortSignal.timeout(3000) });
        if (!healthRes.ok) throw new Error("unhealthy");
      } catch {
        return c.json({
          error: `${provider} authentication requires Hive-ID (${hiveUrl}) which is not reachable. Hive-ID brokers Google and Discord OAuth on behalf of local nodes.`,
          reason: "hive_id_required",
        }, 503);
      }
      // Google + Discord use authorization-code flow (not RFC 8628 device-flow).
      // Redirect the dashboard to Hive-ID's OAuth start; Hive-ID will call back
      // to /api/auth/device-flow/hive-callback with a DToken after the user
      // authorizes. LOCAL_ID_URL must be set to a URL Hive-ID can reach
      // (same LAN or ngrok tunnel during dev).
      const localIdUrl = process.env.LOCAL_ID_URL ?? "https://id.ai.on";
      const callbackUrl = `${localIdUrl}/api/auth/device-flow/hive-callback`;
      const authUrl =
        `${hiveUrl}/oauth/${provider}/start?` +
        new URLSearchParams({ localCallback: callbackUrl, role }).toString();

      return c.json({
        authType: "hive_redirect",
        authUrl,
        provider,
        role,
      }, 200);
    }

    const clientId = provider === "github" ? GITHUB_CLIENT_ID : "";
    if (!clientId) {
      return c.json({ error: `${provider} OAuth client not configured.` }, 400);
    }

    const providerCfg = PROVIDERS[provider];

    const params = new URLSearchParams();
    params.set("client_id", clientId);
    params.set("scope", providerCfg.scopes);

    let data: {
      device_code: string;
      user_code: string;
      verification_uri?: string;
      verification_url?: string;
      expires_in: number;
      interval?: number;
    };

    try {
      const res = await fetch(providerCfg.deviceCodeUrl, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params.toString(),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return c.json({ error: `Provider returned ${res.status}: ${text.slice(0, 200)}` }, 502);
      }

      data = await res.json() as typeof data;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ error: `Failed to reach ${provider}: ${msg}` }, 502);
    }

    // Persist session to handoffs table — survives service restarts.
    await db.insert(handoffs).values({
      id: data.device_code,
      userId: null,
      status: "pending",
      connectedServices: encrypt(JSON.stringify({
        provider,
        role,
        interval: data.interval ?? 5,
      } satisfies DeviceSessionData)),
      purpose: "device-flow",
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + data.expires_in * 1000),
    });

    return c.json({
      deviceCode: data.device_code,
      userCode: data.user_code,
      verificationUri: data.verification_uri ?? data.verification_url ?? "",
      expiresIn: data.expires_in,
      interval: data.interval ?? 5,
    });
  });

  /**
   * GET /poll?deviceCode=...
   *
   * Polls the provider token endpoint to check if the user has authorized.
   * Returns: { status: "pending" | "expired" | "completed" | "error", ... }
   *
   * On "completed", tokens are encrypted and stored in the connections table.
   */
  app.get("/poll", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const deviceCode = c.req.query("deviceCode");
    if (!deviceCode) {
      return c.json({ error: "deviceCode query parameter is required" }, 400);
    }

    const [sessionRow] = await db
      .select()
      .from(handoffs)
      .where(and(
        eq(handoffs.id, deviceCode),
        eq(handoffs.purpose, "device-flow"),
      ))
      .limit(1);

    if (!sessionRow) {
      return c.json({ status: "expired" });
    }
    if (new Date() > sessionRow.expiresAt) {
      await db.delete(handoffs).where(eq(handoffs.id, deviceCode));
      return c.json({ status: "expired" });
    }

    const sessionData = JSON.parse(decrypt(sessionRow.connectedServices!)) as DeviceSessionData;
    const provider = sessionData.provider;
    const providerCfg = PROVIDERS[provider];
    const clientId = provider === "github" ? GITHUB_CLIENT_ID : "";

    const params = new URLSearchParams();
    params.set("client_id", clientId);
    params.set("device_code", deviceCode);
    params.set("grant_type", providerCfg.grantType);

    let data: Record<string, unknown>;
    try {
      const res = await fetch(providerCfg.tokenUrl, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params.toString(),
        signal: AbortSignal.timeout(10_000),
      });
      data = await res.json() as Record<string, unknown>;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ status: "error", error: `Token poll failed: ${msg}` });
    }

    const error = data.error as string | undefined;

    if (error === "authorization_pending") {
      return c.json({ status: "pending", interval: sessionData.interval });
    }

    if (error === "slow_down") {
      const newInterval = sessionData.interval + 5;
      await db
        .update(handoffs)
        .set({ connectedServices: encrypt(JSON.stringify({ ...sessionData, interval: newInterval } satisfies DeviceSessionData)) })
        .where(eq(handoffs.id, deviceCode));
      return c.json({ status: "pending", interval: newInterval });
    }

    if (error === "expired_token" || error === "access_denied") {
      await db.delete(handoffs).where(eq(handoffs.id, deviceCode));
      return c.json({ status: "expired", error });
    }

    if (error) {
      return c.json({
        status: "error",
        error: String(data.error_description ?? error),
      });
    }

    // Authorization granted
    const accessToken = data.access_token as string;
    const refreshToken = data.refresh_token as string | undefined;
    const tokenType = (data.token_type as string | undefined) ?? "Bearer";
    const scope = data.scope as string | undefined;
    const expiresIn = data.expires_in as number | undefined;

    // Fetch display label — non-fatal
    const accountLabel = await fetchAccountLabel(provider, accessToken, tokenType);

    // Persist to connections table. If no user exists yet, this
    // auto-provisions the owner from the GitHub account label so the
    // FK insert below succeeds (previously 500'd on fresh installs).
    const userId = await resolveOrCreateLocalOwner(db, accountLabel);
    const now = new Date();
    const encAccessToken = encrypt(accessToken);
    const encRefreshToken = refreshToken ? encrypt(refreshToken) : null;
    const tokenExpiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    const [existing] = await db
      .select()
      .from(connections)
      .where(and(
        eq(connections.userId, userId),
        eq(connections.provider, provider),
        eq(connections.role, sessionData.role),
      ))
      .limit(1);

    if (existing) {
      await db
        .update(connections)
        .set({
          accountLabel,
          accessToken: encAccessToken,
          refreshToken: encRefreshToken,
          tokenExpiresAt,
          scopes: scope ?? null,
          updatedAt: now,
        })
        .where(eq(connections.id, existing.id));
    } else {
      await db.insert(connections).values({
        id: randomBytes(16).toString("hex"),
        userId,
        provider,
        role: sessionData.role,
        accountLabel,
        accessToken: encAccessToken,
        refreshToken: encRefreshToken,
        tokenExpiresAt,
        scopes: scope ?? null,
        createdAt: now,
        updatedAt: now,
      });
    }

    await db.delete(handoffs).where(eq(handoffs.id, deviceCode));

    return c.json({
      status: "completed",
      provider,
      role: sessionData.role,
      accountLabel,
    });
  });

  /**
   * GET /status
   *
   * Lists all stored OAuth connections (provider, role, accountLabel).
   * Does not expose tokens.
   */
  app.get("/status", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const rows = await db.select({
      provider: connections.provider,
      role: connections.role,
      accountLabel: connections.accountLabel,
      scopes: connections.scopes,
      tokenExpiresAt: connections.tokenExpiresAt,
      updatedAt: connections.updatedAt,
    }).from(connections);

    return c.json(rows);
  });

  /**
   * GET /token?provider=github&role=owner
   *
   * Returns the decrypted OAuth token for the owner's connection on the
   * requested provider, so AGI (running in the private network) can
   * authenticate outbound git operations, API calls, etc.
   *
   * Private-network-guarded via `identity.isOwner` (same gate as /status).
   * Tokens never leave the LAN; a future Hive-ID bridge will handle
   * cross-node brokering.
   *
   * Response shape:
   *   { provider, role, accountLabel, accessToken, tokenType,
   *     tokenExpiresAt, scopes }
   * On miss:
   *   404 { error: "no such connection" }
   */
  app.get("/token", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const provider = c.req.query("provider");
    const role = c.req.query("role") ?? "owner";

    if (!provider || typeof provider !== "string") {
      return c.json({ error: "provider query param required" }, 400);
    }

    const [row] = await db
      .select()
      .from(connections)
      .where(and(eq(connections.provider, provider), eq(connections.role, role)))
      .limit(1);

    if (!row || !row.accessToken) {
      return c.json({ error: "no such connection" }, 404);
    }

    // `accessToken` is stored encrypted — see /poll where it's `encrypt()`-ed
    // before insert. Decrypt for the owner and return plaintext.
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
      tokenExpiresAt: row.tokenExpiresAt?.toISOString() ?? null,
      scopes: row.scopes,
    });
  });

  /**
   * POST /refresh
   *
   * Refreshes a Google access token using its stored refresh token.
   * Body: { provider: "google", role?: string }
   * Returns: { ok: true, expiresIn: number }
   */
  app.post("/refresh", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");

    if (!user && !identity?.isOwner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = await c.req.json().catch(() => ({})) as { provider?: string; role?: string };
    const provider = body.provider as ProviderName | undefined;
    const role = body.role ?? "owner";

    if (provider !== "google") {
      return c.json({ error: "Token refresh is only supported for Google" }, 400);
    }

    // Google token refresh requires client_secret held by Hive-ID
    const cfg = getConfig();
    try {
      const healthRes = await fetch(`${cfg.hiveIdUrl}/health`, { signal: AbortSignal.timeout(3000) });
      if (!healthRes.ok) throw new Error("unhealthy");
    } catch {
      return c.json({
        error: `Token refresh requires Hive-ID (${cfg.hiveIdUrl}) which is not reachable.`,
        reason: "hive_id_required",
      }, 503);
    }
    // Token refresh for proxied providers (Google) is handled transparently
    // by Hive-ID's proxy gateway at call time — the expired access_token is
    // renewed against Google's token endpoint and the connections row is
    // updated before the original API call is retried. No explicit Local-ID
    // refresh call is needed when using the /api/proxy/google/* path.
    return c.json({
      ok: true,
      message: "Google token refresh is handled transparently by Hive-ID at proxy call time.",
      reason: "transparent_via_hive_proxy",
    }, 200);
  });

  /**
   * GET /hive-callback
   *
   * Hive-ID redirects here after a successful Google or Discord
   * authorization-code OAuth dance. Receives the DToken Hive-ID minted,
   * stores it encrypted in Local-ID's connections table, then returns
   * an HTML page that closes the OAuth popup window.
   *
   * Expected query params from Hive-ID:
   *   ?dtoken=dtok_...&provider=google|discord&role=owner&accountLabel=user@example.com
   */
  app.get("/hive-callback", async (c) => {
    const provider = c.req.query("provider") as ProviderName | undefined;
    const role = c.req.query("role") ?? "owner";
    const dtoken = c.req.query("dtoken");
    const accountLabel = c.req.query("accountLabel") ?? "";

    if (!provider || !dtoken || !HIVE_BROKERED_PROVIDERS.has(provider)) {
      return c.json(
        { error: "Missing provider or dtoken, or unsupported provider" },
        400,
      );
    }

    const userId = await resolveOrCreateLocalOwner(db, accountLabel);

    const [existing] = await db
      .select({ id: connections.id })
      .from(connections)
      .where(
        and(
          eq(connections.userId, userId),
          eq(connections.provider, provider),
          eq(connections.role, role),
        ),
      )
      .limit(1);

    if (existing) {
      await db
        .update(connections)
        .set({ dtoken: encrypt(dtoken), accountLabel, updatedAt: new Date() })
        .where(eq(connections.id, existing.id));
    } else {
      await db.insert(connections).values({
        id: nanoid(),
        userId,
        provider,
        role,
        accountLabel,
        dtoken: encrypt(dtoken),
        accessToken: null,
        refreshToken: null,
        tokenExpiresAt: null,
        scopes: null,
      });
    }

    // Return a minimal page — the dashboard opened Hive-ID's OAuth start in
    // a popup; this response lands in that popup and closes it.
    return c.html(
      `<!DOCTYPE html><html><head><title>Connected</title></head><body>` +
        `<script>window.opener?.postMessage({type:"aionima:oauth-complete",provider:"${provider}",role:"${role}"},"*");window.close();</script>` +
        `<p>${provider} connected. You may close this window.</p>` +
        `</body></html>`,
    );
  });

  return app;
}
