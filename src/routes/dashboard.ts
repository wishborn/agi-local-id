import { eq, and, like } from "drizzle-orm";
import { Hono } from "hono";
import type { AuthEnv } from "../auth/middleware.js";
import type { NetworkIdentity } from "../auth/network-identity.js";
import type { DrizzleDb } from "../db/client.js";
import { connections } from "../db/schema.js";
import { escapeHtml } from "../security/escape.js";
import { readView } from "../views/loader.js";
import { getConfig } from "../config.js";

export function dashboardRoutes(db: DrizzleDb) {
  const app = new Hono<AuthEnv & { Variables: { identity?: NetworkIdentity } }>();

  app.get("/", async (c) => {
    const user = c.get("user");
    const identity = c.get("identity");
    const isLocal = true;

    if (!user && !(isLocal && identity?.isOwner)) {
      return c.redirect("/auth/login");
    }

    // In local mode without session, show all connections (owner has full access)
    const userConnections = user
      ? await db.select().from(connections).where(eq(connections.userId, user.id))
      : await db.select().from(connections);

    const connectedMap = new Map(
      userConnections.map((conn) => [`${conn.provider}:${conn.role}`, conn]),
    );

    // Build slots for all OAuth providers — all connect via Hive-ID delegation
    const allSlots = [
      { provider: "google", role: "owner", label: "Google (Owner)" },
      { provider: "google", role: "agent", label: "Google (Agent)" },
      { provider: "github", role: "owner", label: "GitHub (Owner)" },
      { provider: "github", role: "agent", label: "GitHub (Agent)" },
      { provider: "discord", role: "owner", label: "Discord (Owner)" },
      { provider: "discord", role: "agent", label: "Discord (Agent)" },
    ];

    const serviceRows = allSlots
      .map((slot) => {
        const conn = connectedMap.get(`${slot.provider}:${slot.role}`);
        if (conn) {
          return `
          <tr>
            <td>${escapeHtml(slot.label)}</td>
            <td>${escapeHtml(conn.accountLabel ?? "—")}</td>
            <td><span class="badge badge-connected">Connected</span></td>
            <td>
              <form method="POST" action="/api/connections/${escapeHtml(conn.id)}/delete">
                <button type="submit" class="btn btn-sm btn-danger">Disconnect</button>
              </form>
            </td>
          </tr>`;
        }

        // GitHub — uses device flow (works locally, no Hive-ID needed)
        if (slot.provider === "github") {
          return `
          <tr>
            <td>${escapeHtml(slot.label)}</td>
            <td>—</td>
            <td><span class="badge badge-disconnected">Not connected</span></td>
            <td>
              <button class="btn btn-sm btn-primary" onclick="startGithubDeviceFlow('${escapeHtml(slot.role)}')">Connect</button>
            </td>
          </tr>`;
        }

        // Google, Discord — require Hive-ID
        return `
          <tr>
            <td>${escapeHtml(slot.label)}</td>
            <td>—</td>
            <td><span class="badge badge-disconnected">Requires Hive-ID</span></td>
            <td>
              <span style="font-size:0.8rem;color:var(--text-muted)">Available when Hive-ID is online</span>
            </td>
          </tr>`;
      })
      .join("\n");

    // Plaid items — separate section in the dashboard. Multi-bank support
    // via role-encoding: rows have provider="plaid" and role="plaid-item:<id>".
    const plaidRows = userConnections
      .filter((c) => c.provider === "plaid" && c.role.startsWith("plaid-item:"))
      .map((c) => {
        const itemId = c.role.slice("plaid-item:".length);
        return `
          <tr>
            <td>${escapeHtml(c.accountLabel ?? "Plaid Item")}</td>
            <td style="font-family: monospace; font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(itemId)}</td>
            <td><span class="badge badge-connected">Connected</span></td>
            <td>
              <button class="btn btn-sm btn-danger" onclick="disconnectPlaidItem('${escapeHtml(itemId)}')">Disconnect</button>
            </td>
          </tr>`;
      })
      .join("\n");

    const plaidEmpty = plaidRows.length === 0
      ? `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);font-size:0.9rem;padding:1.2rem;">No banks connected. Click "Connect Bank Account" to link one via Plaid.</td></tr>`
      : "";

    const config = getConfig();
    const plaidConfigured = !!(config.plaid.clientIdVaultRef && config.plaid.secretVaultRef);

    const dashboardHtml = await readView("dashboard.html");
    const content = dashboardHtml
      .replace("{{user_email}}", escapeHtml(user?.email ?? "Owner (local)"))
      .replace("{{service_rows}}", serviceRows)
      .replace("{{hive_id_url}}", escapeHtml(config.hiveIdUrl))
      .replace("{{plaid_rows}}", plaidRows + plaidEmpty)
      .replace("{{plaid_env}}", escapeHtml(config.plaid.env))
      .replace("{{plaid_configured}}", plaidConfigured ? "true" : "false");

    const layout = await readView("layout.html");
    const html = layout
      .replace("{{title}}", "Aionima ID — Dashboard")
      .replace("{{content}}", content);

    return c.html(html);
  });

  return app;
}
