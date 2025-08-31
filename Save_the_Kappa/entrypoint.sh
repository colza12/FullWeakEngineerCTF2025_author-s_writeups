#!/usr/bin/env bash
set -euo pipefail

export PATH="/root/.foundry/bin:${PATH}"
HTTP_PORT="${HTTP_PORT:-8545}"
TCP_PORT="${PORT:-31337}"

echo "[entrypoint] starting anvil on 0.0.0.0:${HTTP_PORT} ..."
anvil \
  --host 0.0.0.0 \
  --port "${HTTP_PORT}" \
  --chain-id 31337 \
  --block-time 1 \
  --accounts 10 \
  --balance 10000 \
  --mnemonic "test test test test test test test test test test test junk" \
  > /tmp/anvil.log 2>&1 &

ANVIL_PID=$!

echo "[entrypoint] waiting for anvil to be ready..."
READY=0
for i in $(seq 1 60); do
  if curl -fsS -X POST -H 'Content-Type: application/json' \
      --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
      "http://127.0.0.1:${HTTP_PORT}" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done

if [ "${READY}" -ne 1 ]; then
  echo "[entrypoint] anvil failed to become ready. Dumping /tmp/anvil.log:"
  echo "-------------------------------- /tmp/anvil.log -------------------------------"
  tail -n 200 /tmp/anvil.log || true
  echo "------------------------------------------------------------------------------"
  kill "${ANVIL_PID}" >/dev/null 2>&1 || true
  exit 1
fi

echo "[entrypoint] anvil is up."
echo "[entrypoint] starting socat on 0.0.0.0:${TCP_PORT} ..."
exec socat TCP-L:${TCP_PORT},fork,reuseaddr,ignoreeof EXEC:'python3 /ctf/deploy/chal.py'
