#!/usr/bin/env bash
set -e

# ── 0. Add Metasploit binaries to PATH so msfconsole is available to Rails ────
export PATH="/opt/metasploit-framework/bin:/opt/metasploit-framework/embedded/bin:${PATH}"

MSF_PORT="${MSF_RPC_PORT:-55553}"
MSF_HOST="${MSF_RPC_HOST:-host.docker.internal}"

# ── 1. Refuse to start if Metasploit RPC is not reachable ─────────────────────
echo "Checking Metasploit RPC at ${MSF_HOST}:${MSF_PORT}..."
if ! timeout 5 bash -c "echo > /dev/tcp/${MSF_HOST}/${MSF_PORT}" 2>/dev/null; then
  echo ""
  echo "ERROR: Metasploit RPC daemon is not reachable at ${MSF_HOST}:${MSF_PORT}"
  echo ""
  echo "  Start it on the host with:"
  echo "    msfrpcd -U \$MSF_RPC_USER -P \$MSF_RPC_PASS -p ${MSF_PORT} -S -a 172.20.0.1 -f"
  echo ""
  exit 1
fi
echo "  Metasploit RPC: OK"

# ── 2. Wait for PostgreSQL ─────────────────────────────────────────────────────
echo "Waiting for PostgreSQL..."
until pg_isready -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "${DB_USER:-aegis}" -d vulnerability_scanner -q; do
  sleep 1
done
echo "  PostgreSQL: OK"

# ── 3. Run migrations ─────────────────────────────────────────────────────────
echo "Running migrations..."
bundle exec rails db:migrate

# ── 4. Sync exploit severity data from MSF filesystem ─────────────────────────
MSF_EXPLOIT_PATH="${MSF_MODULES_PATH:-/opt/metasploit-framework/embedded/framework/modules/exploits}"
if [ -d "$MSF_EXPLOIT_PATH" ]; then
  echo "Syncing exploit database from Metasploit filesystem..."
  bundle exec rails exploits:sync
  echo "  Exploit sync: OK"
else
  echo "  Exploit sync: skipped (MSF path not mounted)"
fi

# ── 5. Pull Ollama model on first run (skipped if already present) ────────────
if [ -n "${OLLAMA_HOST}" ]; then
  if curl -s "${OLLAMA_HOST}/api/tags" | grep -q "qwen2.5-coder:7b"; then
    echo "  Ollama model already present, skipping pull."
  else
    echo "Pulling Ollama model..."
    curl -s "${OLLAMA_HOST}/api/pull" \
      -d '{"name":"qwen2.5-coder:7b"}' \
      --max-time 1800 \
      -o /dev/null
  fi
fi

exec "$@"
