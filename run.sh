#!/usr/bin/env bash
# Veilo close_position_to_sol staged-legs theft — Surfpool composition witness.
#
# Requires: surfpool (v1.3+), cargo-build-sbf, network (mainnet fork clone).
# Run from the PoC root:  bash run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RPC="http://127.0.0.1:8899"

echo "==> building harness SBF program"
NO_DNA=1 cargo build-sbf --manifest-path "$ROOT/harness-Cargo.toml"

echo "==> starting surfpool mainnet fork (port 8899)"
pkill -f "surfpool start" 2>/dev/null || true
sleep 1
nohup env NO_DNA=1 surfpool start --ci --port 8899 --rpc-url https://api.mainnet-beta.solana.com \
  > "$ROOT/surfpool.log" 2>&1 &
SURF_PID=$!
echo "surfpool pid: $SURF_PID"

# wait for RPC
ok=0
for i in $(seq 1 90); do
  if curl -s -m 2 "$RPC" -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]}' | grep -q '"ok"'; then
    ok=1; break
  fi
  sleep 1
done
if [ "$ok" != "1" ]; then echo "surfpool did not become healthy"; tail -20 "$ROOT/surfpool.log"; exit 1; fi
echo "==> surfpool healthy"

echo "==> running driver"
cd "$ROOT"
NO_DNA=1 cargo run --manifest-path "$ROOT/driver-Cargo.toml" --release 2>&1 | tee "$ROOT/run-output.txt"

echo "==> stopping surfpool"
kill "$SURF_PID" 2>/dev/null || true
echo "done (see run-output.txt)"