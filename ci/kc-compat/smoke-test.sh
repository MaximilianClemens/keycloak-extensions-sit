#!/usr/bin/env bash
# =====================================================================
# smoke-test.sh – startet einen echten Keycloak mit unserem Jar
#
#   smoke-test.sh <keycloak-version> <provider-jar> <label>
#
# Nutzt die offizielle Server-Distribution (org.keycloak:keycloak-quarkus-dist)
# aus Maven Central – dieselbe, aus der das Container-Image gebaut wird – und
# braucht daher kein Docker. Voraussetzung: Java 21+, Maven, Python 3.
#
# Ablauf: Distribution entpacken → Jar nach providers/ → start-dev (inkl.
# Build-Schritt) → warten bis /health/ready → smoke_exercise.py → Log nach
# ERROR-Zeilen und Meldungen unserer Klassen durchsuchen.
#
# Ergebnis: $WORK_DIR/smoke-<label>.log (Keycloak-Log),
#           $WORK_DIR/smoke-<label>.out (Prüfungen),
#           $WORK_DIR/smoke-<label>.status (STATUS<TAB>Text)
# Exit-Code 0 = bestanden.
# =====================================================================
set -uo pipefail

KC_VERSION="$1"
JAR="$2"
LABEL="$3"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${WORK_DIR:-$(pwd)/.kc-compat}"
KC_PORT="${KC_PORT:-18080}"
KC_MGMT_PORT="${KC_MGMT_PORT:-19000}"
START_TIMEOUT="${START_TIMEOUT:-300}"
MVN="${MVN:-mvn -B -q}"

mkdir -p "$WORK_DIR"
LOG="$WORK_DIR/smoke-$LABEL.log"
OUT="$WORK_DIR/smoke-$LABEL.out"
STATUS="$WORK_DIR/smoke-$LABEL.status"
: > "$OUT"

status() { printf '%s\t%s\n' "$1" "$2" > "$STATUS"; echo "[smoke:$LABEL] $1: $2"; }

# ── Distribution holen (einmal pro Version) ──────────────────────────────
DIST_DIR="$WORK_DIR/dist/keycloak-$KC_VERSION"
if [ ! -x "$DIST_DIR/bin/kc.sh" ]; then
  mkdir -p "$WORK_DIR/dist"
  if ! $MVN dependency:copy \
        -Dartifact="org.keycloak:keycloak-quarkus-dist:$KC_VERSION:tar.gz" \
        -DoutputDirectory="$WORK_DIR/dist" >> "$OUT" 2>&1; then
    status FAIL "Keycloak-Distribution $KC_VERSION nicht ladbar"
    exit 1
  fi
  tar -xzf "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz" -C "$WORK_DIR/dist"
  rm -f "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz"
fi

# Frische Kopie pro Lauf, damit kein Build-/H2-Zustand des anderen Jars übrig bleibt
RUN_DIR="$WORK_DIR/run-$LABEL"
rm -rf "$RUN_DIR"
cp -r "$DIST_DIR" "$RUN_DIR"
cp "$JAR" "$RUN_DIR/providers/"

# ── Starten ───────────────────────────────────────────────────────────────
echo "[smoke:$LABEL] starte Keycloak $KC_VERSION mit $(basename "$JAR")"
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  "$RUN_DIR/bin/kc.sh" start-dev \
    --http-port="$KC_PORT" \
    --http-management-port="$KC_MGMT_PORT" \
    --health-enabled=true \
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
  if ! kill -0 "$KC_PID" 2>/dev/null; then break; fi
  if curl -sf --noproxy '*' "http://localhost:$KC_MGMT_PORT/health/ready" > /dev/null 2>&1; then
    ready=true; break
  fi
  sleep 1
done

if ! $ready; then
  {
    echo "Keycloak ist nicht gestartet. Letzte Logzeilen:"
    tail -n 60 "$LOG"
  } >> "$OUT"
  status FAIL "Keycloak startet nicht (siehe smoke-$LABEL.log)"
  exit 1
fi
echo "[smoke:$LABEL] Keycloak bereit"

# ── Prüfungen über die Admin-API ─────────────────────────────────────────
python3 "$SCRIPT_DIR/smoke_exercise.py" "http://localhost:$KC_PORT" "$SCRIPT_DIR/expected-providers.txt" >> "$OUT" 2>&1
exercise_rc=$?
stop_kc
trap - EXIT

# ── Log auswerten ─────────────────────────────────────────────────────────
errors=$(grep -E '^[0-9-]+ [0-9:,.]+ +ERROR ' "$LOG" || true)
# KC-SERVICES0047 ("implementing the internal SPI") ist bei jeder Extension normal und wird ignoriert
own=$(grep -nE 'nrw\.sit\.keycloak' "$LOG" | grep -E 'WARN|ERROR|Exception' | grep -v 'KC-SERVICES0047' || true)
{
  echo
  echo "ERROR-Zeilen im Keycloak-Log: $( [ -n "$errors" ] && printf '%s\n' "$errors" | wc -l || echo 0)"
  [ -n "$errors" ] && printf '%s\n' "$errors" | head -n 30
  echo "Warnungen/Fehler aus nrw.sit.keycloak: $( [ -n "$own" ] && printf '%s\n' "$own" | wc -l || echo 0)"
  [ -n "$own" ] && printf '%s\n' "$own" | head -n 30
} >> "$OUT"

passed=$(grep -c '^OK ' "$OUT" || true)
failed=$(grep -c '^FAIL ' "$OUT" || true)
if [ "$exercise_rc" -ne 0 ]; then
  status FAIL "$failed von $((passed + failed)) Prüfungen fehlgeschlagen"
  exit 1
elif [ -n "$errors" ]; then
  status FAIL "Prüfungen ok, aber ERROR-Zeilen im Keycloak-Log"
  exit 1
elif [ -n "$own" ]; then
  status WARN "$passed Prüfungen ok, aber Warnungen aus unseren Klassen im Log"
else
  status PASS "Start ok, $passed Prüfungen bestanden"
fi
exit 0
