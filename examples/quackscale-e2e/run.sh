#!/usr/bin/env bash
# Coordinator + two-node proof.
# Always runs the tsnet interop (same stack QuackScale embeds via libtailscale).
# If duckdb + quackscale are available, also exercises CALL tailscale_up.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${ROOT}/build/wirebone"
STATE="$(mktemp /tmp/wirebone-e2e-XXXXXX.json)"
LISTEN="127.0.0.1:18080"
URL="http://${LISTEN}"

cleanup() {
  if [[ -n "${PID:-}" ]]; then kill "${PID}" 2>/dev/null || true; fi
  rm -f "${STATE}"
}
trap cleanup EXIT

"${BIN}" serve --listen "${LISTEN}" --url "${URL}" --state "${STATE}" --dns "127.0.0.1:0" &
PID=$!
for i in $(seq 1 50); do
  if curl -sf "${URL}/healthz" >/dev/null; then break; fi
  sleep 0.1
done
KEY="$("${BIN}" preauth create --state "${STATE}")"
echo "coordinator ${URL} key ${KEY}"

if command -v go >/dev/null; then
  (cd "${ROOT}/tools/interop" && go run ./handshake_test.go "${URL}")
  (cd "${ROOT}/tools/interop" && go run ./tsnet_two_node.go "${URL}" "${KEY}")
fi

if command -v duckdb >/dev/null && duckdb -unsigned -c "LOAD quackscale; SELECT 1;" >/dev/null 2>&1; then
  duckdb -unsigned <<SQL
LOAD quackscale;
CALL tailscale_up(
    hostname => 'e2e-a',
    control_url => '${URL}',
    authkey => '${KEY}',
    state_dir => '/tmp/wirebone-e2e-a'
);
FROM tailscale_status();
SQL
  echo "quackscale joined ${URL}"
else
  echo "duckdb/quackscale not installed; tsnet interop is the protocol proof"
fi
