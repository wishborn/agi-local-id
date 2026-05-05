import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { sessionMiddleware } from "./auth/middleware.js";
import { networkIdentityMiddleware, setPeerKeyResolver } from "./auth/network-identity.js";
import { createLucia } from "./auth/lucia.js";
import { AuthBackendRegistry } from "./auth/backend.js";
import { VirtualAuthBackend } from "./auth/virtual-backend.js";
import { PamAuthBackend } from "./auth/pam-backend.js";
import { db } from "./db/client.js";
import { VERSION } from "./version.js";
import { authRoutes } from "./routes/auth.js";
import { entityRoutes } from "./routes/entities/index.js";
import { connectRoutes } from "./routes/connect.js";
import { createEntityService } from "./services/entity-service.js";
import { dashboardRoutes } from "./routes/dashboard.js";
import { handoffRoutes } from "./routes/handoff.js";
import { channelRoutes } from "./routes/channels.js";
import { settingsRoutes } from "./routes/settings.js";
import { userRoutes } from "./routes/users.js";
import { oauthDelegateRoutes } from "./routes/oauth-delegate.js";
import { deviceFlowRoutes } from "./routes/device-flow.js";
import { plaidLinkRoutes } from "./routes/plaid-link.js";
import { proxyForwardRoutes } from "./routes/proxy-forward.js";
import { federationIdentityRoutes, buildNodeManifest } from "./routes/federation/identity.js";
import { csrfMiddleware } from "./security/csrf.js";
import { rateLimit } from "./security/rate-limit.js";
import { startHandoffCleanup } from "./jobs/cleanup.js";
import { loadConfig } from "./config.js";
import { startSnapshotRefresh } from "./services/snapshot-cache.js";
import type { AuthEnv } from "./auth/middleware.js";
import { readView } from "./views/loader.js";

// Load and validate config before anything else
const config = loadConfig();

const lucia = createLucia(db);
const entityService = createEntityService(db);

// Phase 3 auth — register backends in priority order. Virtual (password_hash)
// is the default for self-hosted installs; PAM lets system users log in
// when the helper script is provisioned on the host (/opt/agi-local-id/
// helpers/pam_auth.sh). LDAP + AD adapters plug into the same registry
// when the enterprise integrations land.
const authRegistry = new AuthBackendRegistry(db);
authRegistry.register(new VirtualAuthBackend(db, authRegistry));
authRegistry.register(new PamAuthBackend(db, authRegistry));

// Set up peer key resolver for federation auth.
// Local-ID only knows local peers — return null for all external nodes.
setPeerKeyResolver((_nodeId: string): string | null => null);

const app = new Hono<AuthEnv>();

// ---------------------------------------------------------------------------
// Global middleware (order matters)
// ---------------------------------------------------------------------------

// 1. Security headers — allow framing from the AGI dashboard (*.ai.on)
app.use("/*", secureHeaders({
  xFrameOptions: false,
  contentSecurityPolicy: {
    frameAncestors: ["'self'", "https://*.ai.on", "https://ai.on"],
  },
}));

// 2. Session middleware — cookie-based sessions, populates c.var.user
app.use("/*", sessionMiddleware(lucia));

// 3. Network identity — private network auto-IDENT, API key, Mycelium-Sig
//    Runs AFTER session middleware so it can check if Lucia already identified the user.
app.use("/*", networkIdentityMiddleware());

// ---------------------------------------------------------------------------
// CORS — scoped per route group
// ---------------------------------------------------------------------------

// Handoff poll/create: open CORS (gateways on any origin)
app.use(
  "/api/handoff/*/poll",
  cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], allowHeaders: ["Content-Type"], maxAge: 3600 }),
);
app.use(
  "/api/handoff/create",
  cors({ origin: "*", allowMethods: ["POST", "OPTIONS"], allowHeaders: ["Content-Type", "Authorization"], maxAge: 3600 }),
);

// Federation: open CORS
app.use("/api/providers", cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], allowHeaders: ["Content-Type"], maxAge: 3600 }));
app.use("/federation/*", cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["Content-Type", "Mycelium-Sig"], maxAge: 3600 }));
app.use("/.well-known/*", cors({ origin: "*", allowMethods: ["GET", "OPTIONS"], maxAge: 3600 }));

// Entity API: open CORS (AGI gateway calls these endpoints)
app.use("/api/entities/*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
  maxAge: 3600,
}));

// User API: open CORS (AGI gateway proxies admin user CRUD)
app.use("/api/users/*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
  maxAge: 3600,
}));

// ---------------------------------------------------------------------------
// CSRF — protects browser state-changing endpoints
// Handoff create/poll and federation endpoints are exempt (API-to-API, no cookies)
// ---------------------------------------------------------------------------

app.use("/auth/*", csrfMiddleware());
app.use("/api/connections/*", csrfMiddleware());
app.use("/api/handoff/*/approve", csrfMiddleware());
app.use("/api/channels/test", csrfMiddleware());
app.use("/api/channels/save", csrfMiddleware());
app.use("/api/oauth/delegate", csrfMiddleware());

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

app.use("/auth/login", rateLimit({ windowMs: 60_000, max: 5, keyPrefix: "login" }));
app.use("/auth/register", rateLimit({ windowMs: 60_000, max: 3, keyPrefix: "register" }));
app.use("/api/handoff/create", rateLimit({ windowMs: 60_000, max: 10, keyPrefix: "handoff" }));

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Auth routes — email/password with entity auto-creation
app.route("/auth", authRoutes(db, lucia, entityService, authRegistry));

// Entity routes — entity management, register-owner, bind-agent
app.route("/api/entities", entityRoutes(entityService));

app.route("/api/connections", connectRoutes(db));
app.route("/api/handoff", handoffRoutes(db, lucia));
app.route("/api/users", userRoutes(db, entityService));
app.route("/api/oauth/delegate", oauthDelegateRoutes(db));
app.route("/api/auth/device-flow", deviceFlowRoutes(db));
app.route("/api/auth/plaid-link", plaidLinkRoutes(db));

// s149 t626 — generic provider proxy forwarding to Hive-ID. Used by
// agi plugins (t627) calling per-tool proxy routes:
//   POST /api/proxy/plaid/accounts-get with role=plaid-item:<id>
//   POST /api/proxy/google/calendar.events.list with role=owner
// Local-ID looks up the encrypted DToken on connections + forwards to
// Hive-ID's /api/proxy/<provider>/<endpoint> with Bearer auth.
app.route("/api/proxy", proxyForwardRoutes(db));
app.route("/dashboard", dashboardRoutes(db));
app.route("/channels", channelRoutes(db));
app.route("/api/channels", channelRoutes(db));
app.route("/settings", settingsRoutes(db));
app.route("/api/settings", settingsRoutes(db));

// Federation identity routes — available in all modes
app.route("/federation", federationIdentityRoutes());

// Well-known node manifest
app.get("/.well-known/mycelium-node.json", (c) => c.json(buildNodeManifest()));

// Provider discovery endpoint — delegates to Hive-ID; returns empty list locally
app.get("/api/providers", (c) => {
  return c.json({ providers: [] });
});

// Login page (standalone — central mode primarily)
app.get("/auth/login", async (c) => {
  const loginHtml = await readView("login.html");
  const content = loginHtml.replace("{{handoff_id}}", "");
  const layout = await readView("layout.html");
  const html = layout
    .replace("{{title}}", "Aionima ID — Login")
    .replace("{{content}}", content);
  return c.html(html);
});

// Root redirect
app.get("/", (c) => c.redirect("/dashboard"));

// Health check
app.get("/health", (c) =>
  c.json({ status: "ok", service: "agi-local-id", mode: "local", version: VERSION }),
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const port = config.port;

// Start periodic cleanup of expired handoffs
startHandoffCleanup(db);

// Start Hive-ID registry snapshot cache (offline federation verification)
startSnapshotRefresh(Number(process.env.SNAPSHOT_REFRESH_MS ?? 300_000));
console.log("Hive-ID snapshot cache started");

const authModes = ["private-network"];
if (config.ownerNode.apiKey) authModes.push("node-api-key");
authModes.push("mycelium-sig", "session");

console.log(`Auth modes: ${authModes.join(", ")}`);
console.log(`Aionima Local-ID Service starting on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
