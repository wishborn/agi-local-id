#!/usr/bin/env bash
# Sync @agi/db-schema source files into Local-ID's src/db/schema/ directory.
#
# Local-ID is NOT part of the agi pnpm workspace (separate npm project, separate
# deployment target). Rather than rearchitecting the workspace, we bundle the
# shared schema files into Local-ID at dev/build time. This preserves the
# single-source-of-truth rule (@agi/db-schema remains canonical — Local-ID's
# copy is generated, not authored).
#
# Run before `pnpm dev`, `pnpm build`, or `pnpm db:generate`. The package.json
# scripts wire this up automatically.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_ID_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# Don't hard-`cd` into the AGI root — the sibling checkout is absent in
# Docker builds and CI, and `set -e` would abort the script there. Resolve
# the path lexically and let the presence check below handle missing.
AGI_ROOT="${LOCAL_ID_ROOT}/../agi"
SOURCE_DIR="${AGI_ROOT}/packages/db-schema/src"
TARGET_DIR="${LOCAL_ID_ROOT}/src/db/schema"

if [ ! -d "${SOURCE_DIR}" ]; then
  # Docker builds and CI runs without the sibling AGI workspace checked out.
  # The committed copy in src/db/schema/ is authoritative in those contexts.
  # `predev`/`prebuild` calling this from a clean clone is expected.
  echo "[sync-schema] source not found at ${SOURCE_DIR} — using committed copy" >&2
  exit 0
fi

mkdir -p "${TARGET_DIR}"

# Copy every .ts file from db-schema source. `client.ts` is skipped because
# Local-ID uses its own postgres-js-based client factory (see src/db/client.ts).
# `index.ts` gets its `export * from "./client.js"` line stripped on copy so
# the bundled re-export doesn't break the build (the bundled client.ts is
# intentionally absent; Local-ID's own client lives at src/db/client.ts).
for file in "${SOURCE_DIR}"/*.ts; do
  basename="$(basename "${file}")"
  if [ "${basename}" = "client.ts" ]; then
    continue
  fi
  if [ "${basename}" = "index.ts" ]; then
    # Strip any line re-exporting from a sibling client.js — that file is
    # intentionally absent in Local-ID's bundled copy.
    grep -v './client\.js' "${file}" > "${TARGET_DIR}/${basename}" || true
  else
    cp "${file}" "${TARGET_DIR}/${basename}"
  fi
done

# Emit a header file so the source of each bundled file is discoverable.
cat > "${TARGET_DIR}/README.md" <<'EOF'
# Bundled @agi/db-schema

**This directory is auto-generated — do not edit in place.**

Source of truth: `../../../../agi/packages/db-schema/src/`

Regenerate via: `pnpm sync:schema` (or it runs automatically before `dev`,
`build`, and `db:generate`).

Single-source-of-truth rule: schema changes MUST happen in @agi/db-schema
first, then sync into Local-ID. Never author schema here.
EOF

echo "[sync-schema] copied $(ls "${TARGET_DIR}"/*.ts | wc -l) schema files → src/db/schema/"
