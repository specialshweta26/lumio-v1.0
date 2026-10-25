#!/usr/bin/env bash
# One Render web service runs migrations, the API, the worker, and the web UI.
set -euo pipefail
umask 077

public_url="${RENDER_EXTERNAL_URL:-${BETTER_AUTH_URL:-}}"
host="${public_url#https://}"
host="${host#http://}"
host="${host%%/*}"

export NODE_ENV=production
export SANDBOX_PROVIDER="${SANDBOX_PROVIDER:-e2b}"
export PHONE_CALLS_ENABLED="${PHONE_CALLS_ENABLED:-true}"
export DATA_DIR="${DATA_DIR:-/tmp/lumio-data}"
export API_HOST="${API_HOST:-127.0.0.1}"
export API_URL="${API_URL:-http://127.0.0.1:3100}"
export API_PROXY_TARGET="${API_PROXY_TARGET:-http://127.0.0.1:3100}"
export WEB_PORT="${PORT:-5173}"
export TRUSTED_PROXIES="${TRUSTED_PROXIES:-127.0.0.1}"
export SIGNUPS_ENABLED="${SIGNUPS_ENABLED:-true}"
export CONTENT_ENCRYPTION="${CONTENT_ENCRYPTION:-on}"

if [[ -n "$public_url" ]]; then
  export BETTER_AUTH_URL="${BETTER_AUTH_URL:-$public_url}"
  export WEB_ORIGIN="${WEB_ORIGIN:-$public_url}"
  export LUMIO_HOST="${LUMIO_HOST:-$host}"
  export LUMIO_ALLOWED_HOSTS="${LUMIO_ALLOWED_HOSTS:-$host}"
fi

mkdir -p "$DATA_DIR"

# A computer saved as "none" or "fake" fails the chat snapshot and skips the
# real sandbox. Point existing rows at the configured provider, and keep an
# already-running desktop on screen when a tool reuses it.
if [[ "$SANDBOX_PROVIDER" != "none" ]]; then
  (
    cd /app/packages/db
    node --input-type=module -e '
      import pg from "pg";
      const kind = process.env.SANDBOX_PROVIDER;
      const allowed = new Set(["docker", "e2b", "daytona", "createos", "boat", "railway", "desktop", "fake"]);
      if (!allowed.has(kind)) process.exit(0);
      const client = new pg.Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 8000 });
      await client.connect();
      const result = await client.query(
        "update computers set kind=$1, \"providerRef\"=null, state=$2 where kind <> $1",
        [kind, "stopped"],
      );
      console.log("computer-kind-updated", result.rowCount);
      await client.query(`
        CREATE OR REPLACE FUNCTION revoke_computer_screens() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF (NEW.state IS DISTINCT FROM OLD.state AND NOT (
                (OLD.state = $s$booting$s$ AND NEW.state = $s$running$s$)
                OR (OLD.state = $s$running$s$ AND NEW.state = $s$booting$s$)
              ))
            OR NEW."providerRef" IS DISTINCT FROM OLD."providerRef" THEN
            NEW."screenGeneration" := OLD."screenGeneration" + 1;
          END IF;
          RETURN NEW;
        END;
        $$`);
      console.log("screen-trigger-updated");
      await client.end();
    '
  ) || echo "computer-kind-update-failed" >&2
fi

cd /app
node --enable-source-maps apps/api/dist/cli/migrate-database.js
echo "migrate-done" >&2

trap 'kill $(jobs -p) 2>/dev/null || true; wait || true' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

(cd /app/apps/api && node dist/index.js) &
(cd /app/apps/worker && node dist/index.js) &
(
  cd /app/apps/web
  exec ./node_modules/.bin/vite preview --host 0.0.0.0 --port "$WEB_PORT" --outDir /app/apps/web/dist
) &
wait
