/**
 * Local-ID Service Configuration — centralized config for the local-only
 * identity service running alongside AGI on a self-hosted node.
 *
 * All environment variables are read here and nowhere else.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IdServiceConfig {
  /** Public-facing base URL for OAuth redirects and handoff URLs */
  baseUrl: string;
  /** HTTP listen port */
  port: number;
  /** PostgreSQL connection string */
  databaseUrl: string;
  /** 64-char hex string (32 bytes) for AES-256-GCM encryption */
  encryptionKey: string;
  /** Public Hive-ID URL — used for OAuth delegation in Phase 2 */
  hiveIdUrl: string;
  /**
   * AGI gateway base URL on the private network. Default
   * `https://gateway.ai.on`; override via GATEWAY_URL env var.
   *
   * As of s149 cycle 220 the GATEWAY_URL is no longer used for Plaid
   * Vault lookups — Plaid creds live at Hive-ID under the cycle-215-
   * unified architecture. Kept for other future agi-side services that
   * Local-ID may need to reach.
   */
  gatewayUrl: string;
  /**
   * Hive-ID base URL — public HTTPS service that hosts third-party API
   * brokering (Plaid + Google + Discord per s149). Local-ID forwards
   * proxy calls here with Bearer DToken auth. Default
   * `https://id.aionima.ai`; override via HIVE_ID_URL env var.
   */
  hiveIdBaseUrl: string;
  /** Owner node connection — points back to the AGI gateway */
  ownerNode: {
    url: string | undefined;
    apiKey: string | undefined;
  };
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _config: IdServiceConfig | null = null;

/**
 * Load and validate configuration from environment variables.
 * Call once at startup — subsequent calls return the cached config.
 */
export function loadConfig(): IdServiceConfig {
  if (_config) return _config;

  const baseUrl =
    process.env.AIONIMA_ID_BASE_URL ??
    process.env.ID_BASE_URL ??
    "http://localhost:3000";

  const port = Number(process.env.PORT ?? 3000);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error(`PORT must be 1-65535, got "${process.env.PORT}"`);
  }

  const databaseUrl = process.env.DATABASE_URL ?? "";
  if (!databaseUrl) {
    throw new Error("DATABASE_URL environment variable is required");
  }

  const encryptionKey = process.env.ENCRYPTION_KEY ?? "";
  if (!encryptionKey || encryptionKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(encryptionKey)) {
    throw new Error("ENCRYPTION_KEY must be a 64-character hex string (32 bytes)");
  }

  _config = {
    baseUrl,
    port,
    databaseUrl,
    encryptionKey,
    hiveIdUrl: process.env.HIVE_ID_URL ?? "https://id.aionima.ai",
    hiveIdBaseUrl: process.env.HIVE_ID_URL ?? "https://id.aionima.ai",
    gatewayUrl: process.env.GATEWAY_URL ?? "https://gateway.ai.on",
    ownerNode: {
      url: process.env.OWNER_NODE_URL,
      apiKey: process.env.OWNER_NODE_API_KEY,
    },
  };

  return _config;
}

/**
 * Get the already-loaded config. Throws if loadConfig() hasn't been called.
 */
export function getConfig(): IdServiceConfig {
  if (!_config) throw new Error("Config not loaded — call loadConfig() first");
  return _config;
}

/**
 * Convenience: get the base URL (most common access pattern).
 * Backward-compatible with the old `ID_BASE_URL` export.
 */
export function getBaseUrl(): string {
  return getConfig().baseUrl;
}
