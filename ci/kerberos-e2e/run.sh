#!/usr/bin/env bash
# =====================================================================
# run.sh – SPNEGO end-to-end test: real KDC, real Keycloak, real ticket
#
#   ci/kerberos-e2e/run.sh [keycloak-version] [provider-jar]
#
# 1. setup-kdc.sh      MIT KDC on localhost, realm EXAMPLE.TEST, keytab
# 2. Keycloak           official distribution (Maven Central, or KC_DIST=<unpacked dir>)
#                       started with the provider jar, reachable as
#                       http://keycloak.example.test:8080 (the service principal's host)
# 3. kerberos_e2e.py    realm via admin API, login played with curl --negotiate
#
# Defaults: keycloak.version from pom.xml, jar from target/ (built with
# mvn package -DskipTests if missing). Needs root/sudo (KDC, /etc/hosts),
# Java 17+, Python 3, curl with GSSAPI, krb5-kdc krb5-admin-server krb5-user.
#
# Output in $WORK_DIR (default .kerberos-e2e/): keycloak.log, e2e.out
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$ROOT/ci/kerberos-e2e"
KC_VERSION="${1:-$(sed -n 's:.*<keycloak.version>\(.*\)</keycloak.version>.*:\1:p' "$ROOT/pom.xml" | head -n 1)}"
JAR="${2:-}"
WORK_DIR="${WORK_DIR:-$ROOT/.kerberos-e2e}"
KC_PORT="${KC_PORT:-8080}"
KC_MGMT_PORT="${KC_MGMT_PORT:-9000}"
KC_HOST="keycloak.example.test"
START_TIMEOUT="${START_TIMEOUT:-300}"
MVN="${MVN:-mvn -B -q}"

mkdir -p "$WORK_DIR"
LOG="$WORK_DIR/keycloak.log"
OUT="$WORK_DIR/e2e.out"

# ── provider jar ─────────────────────────────────────────────────────────
if [ -z "$JAR" ]; then
  JAR=$(ls "$ROOT"/target/keycloak-extensions-sit-*.jar 2>/dev/null | grep -v -- '-sources\|-javadoc' | head -n 1 || true)
  if [ -z "$JAR" ]; then
    echo "[e2e] building provider jar"
    (cd "$ROOT" && $MVN -Dkeycloak.version="$KC_VERSION" clean package -DskipTests) || { echo "[e2e] build failed"; exit 1; }
    JAR=$(ls "$ROOT"/target/keycloak-extensions-sit-*.jar | grep -v -- '-sources\|-javadoc' | head -n 1)
  fi
fi
echo "[e2e] jar: $JAR"

# ── KDC ──────────────────────────────────────────────────────────────────
"$SCRIPT_DIR/setup-kdc.sh" "$WORK_DIR" || exit 1
KEYTAB="$WORK_DIR/keycloak.keytab"

# ── Keycloak distribution ────────────────────────────────────────────────
if [ -n "${KC_DIST:-}" ]; then
  DIST_DIR="$KC_DIST"
else
  DIST_DIR="$WORK_DIR/dist/keycloak-$KC_VERSION"
  if [ ! -x "$DIST_DIR/bin/kc.sh" ]; then
    mkdir -p "$WORK_DIR/dist"
    $MVN dependency:copy -Dartifact="org.keycloak:keycloak-quarkus-dist:$KC_VERSION:tar.gz" \
      -DoutputDirectory="$WORK_DIR/dist" || { echo "[e2e] Keycloak distribution $KC_VERSION not available"; exit 1; }
    tar -xzf "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz" -C "$WORK_DIR/dist"
    rm -f "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz"
  fi
fi

RUN_DIR="$WORK_DIR/run"
rm -rf "$RUN_DIR"
cp -r "$DIST_DIR" "$RUN_DIR"
cp "$JAR" "$RUN_DIR/providers/"

# ── start Keycloak ───────────────────────────────────────────────────────
echo "[e2e] starting Keycloak $KC_VERSION"
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
JAVA_OPTS_APPEND="-Djava.security.krb5.conf=/etc/krb5.conf -Dsun.security.krb5.debug=false" \
  "$RUN_DIR/bin/kc.sh" start-dev \
    --http-port="$KC_PORT" \
    --http-management-port="$KC_MGMT_PORT" \
    --health-enabled=true \
    --log-level=info,org.keycloak.authentication:debug,org.keycloak.federation.kerberos:debug \
    > "$LOG" 2>&1 &
KC_PID=$!

stop_kc() {
  if kill -0 "$KC_PID" 2>/dev/null; then
    kill "$KC_PID" 2>/dev/null
    for _ in $(seq 1 30); do kill -0 "$KC_PID" 2>/dev/null || break; sleep 1; done
    kill -9 "$KC_PID" 2>/dev/null || true
  fi
}
trap stop_kc EXIT

ready=false
for _ in $(seq 1 "$START_TIMEOUT"); do
  kill -0 "$KC_PID" 2>/dev/null || break
  if curl -sf --noproxy '*' "http://localhost:$KC_MGMT_PORT/health/ready" > /dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if ! $ready; then
  echo "[e2e] Keycloak did not start:"; tail -n 40 "$LOG"; exit 1
fi
echo "[e2e] Keycloak ready"

# ── play the login ───────────────────────────────────────────────────────
python3 "$SCRIPT_DIR/kerberos_e2e.py" "http://$KC_HOST:$KC_PORT" "$KEYTAB" 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
stop_kc
trap - EXIT

errors=$(grep -E '^[0-9-]+ [0-9:,.]+ +ERROR ' "$LOG" || true)
if [ -n "$errors" ]; then
  echo "[e2e] ERROR lines in the Keycloak log:"; printf '%s\n' "$errors" | head -n 20
  rc=1
fi
[ "$rc" -eq 0 ] && echo "[e2e] PASS" || echo "[e2e] FAIL (see $OUT and $LOG)"
exit "$rc"
