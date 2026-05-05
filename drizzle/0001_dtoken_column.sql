-- s149 t626 — add dtoken column to connections for proxied providers
-- (Plaid, Google, Discord). Nullable because public-client providers
-- (GitHub) still use access_token. Migration content matches the change
-- in @agi/db-schema canonical source at agi/packages/db-schema/src/auth.ts.

ALTER TABLE "connections" ADD COLUMN "dtoken" text;
