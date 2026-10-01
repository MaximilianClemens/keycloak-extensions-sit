#!/usr/bin/env bash
# =====================================================================
# run-all.sh – Kompatibilitätscheck gegen ein (neues) Keycloak-Release
#
#   ci/kc-compat/run-all.sh [NEUE_VERSION] [BASIS_VERSION]
#
#   NEUE_VERSION   default: neueste finale Version aus Maven Central
#   BASIS_VERSION  default: keycloak.version aus pom.xml
#
# Prüfungen:
#   1. Jar gegen die Basisversion bauen (= "altes" Jar, wie es heute ausgerollt ist)
#   2. Build + Unit-Tests gegen die neue Version
#   3. Bytecode-Vergleich: ist ein Neubau überhaupt nötig?
#   4. Geänderte Drittbibliotheken (z. B. webauthn4j)
#   5. API-/Linkage-Vergleich aller Keycloak-Klassen, die wir benutzen oder erweitern
#   6. Keycloak NEU mit altem Jar starten + Admin-API-/Token-Prüfungen
#   7. Keycloak NEU mit neu gebautem Jar starten + dieselben Prüfungen
#
# Umgebung:
#   WORK_DIR  Arbeitsverzeichnis (default: ./.kc-compat)
#   OLD_JAR   statt Schritt 1 ein vorhandenes Jar verwenden (z. B. das ausgerollte)
#
# Ergebnis: $WORK_DIR/report.md (vollständig), $WORK_DIR/summary.md (kurz, für Issues)
# Exit-Code 1, wenn mindestens eine Prüfung FAIL ist.
# Lokal: Java 21+, Maven und Python 3 genügen – Docker wird nicht benötigt.
# =====================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_DIR"

export WORK_DIR="${WORK_DIR:-$REPO_DIR/.kc-compat}"
MVN="mvn -B -q"
export MVN

NEW_VERSION="${1:-$("$SCRIPT_DIR/latest-version.sh")}"
BASE_VERSION="${2:-$(sed -n 's:.*<keycloak.version>\(.*\)</keycloak.version>.*:\1:p' pom.xml | head -n 1)}"

rm -rf "$WORK_DIR/report" "$WORK_DIR"/smoke-*.{out,status,log} "$WORK_DIR/results.tsv" "$WORK_DIR/api-issue.md"
mkdir -p "$WORK_DIR/report" "$WORK_DIR/jars"
RESULTS="$WORK_DIR/results.tsv"
: > "$RESULTS"

echo "== Keycloak-Kompatibilitätscheck: Basis $BASE_VERSION → neu $NEW_VERSION"

# result <Schlüssel> <Titel> <STATUS> <Text>
result() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "[$3] $2: $4"; }
section() { cat >> "$WORK_DIR/report/$1.md"; }

# ── 0. Provider-Liste konsistent? ────────────────────────────────────────
expected=$(grep -cvE '^\s*(#|$)' "$SCRIPT_DIR/expected-providers.txt")
registered=$(cat src/main/resources/META-INF/services/* | grep -cvE '^\s*(#|$)')
if [ "$expected" -ne "$registered" ]; then
  result 00 "Provider-Liste" FAIL "expected-providers.txt hat $expected Einträge, META-INF/services $registered"
fi

# ── 1. Altes Jar ──────────────────────────────────────────────────────────
if [ -n "${OLD_JAR:-}" ]; then
  cp "$OLD_JAR" "$WORK_DIR/jars/old.jar"
  result 01 "Altes Jar" PASS "vorgegeben: $(basename "$OLD_JAR")"
  $MVN clean compile -Dkeycloak.version="$BASE_VERSION" > "$WORK_DIR/build-old.log" 2>&1
  rm -rf "$WORK_DIR/classes-old"; cp -r target/classes "$WORK_DIR/classes-old"
elif $MVN clean package -DskipTests -Dkeycloak.version="$BASE_VERSION" > "$WORK_DIR/build-old.log" 2>&1; then
  cp target/*.jar "$WORK_DIR/jars/old.jar"
  rm -rf "$WORK_DIR/classes-old"; cp -r target/classes "$WORK_DIR/classes-old"
  result 01 "Altes Jar (gebaut gegen $BASE_VERSION)" PASS "$(basename target/*.jar)"
else
  result 01 "Altes Jar (gebaut gegen $BASE_VERSION)" FAIL "Build fehlgeschlagen"
  { echo "## Build gegen $BASE_VERSION"; echo; echo '```'; tail -n 60 "$WORK_DIR/build-old.log"; echo '```'; } | section 01-build-old
fi

# ── 2. Build + Tests gegen neue Version ──────────────────────────────────
if mvn -B clean verify -Dkeycloak.version="$NEW_VERSION" > "$WORK_DIR/build-new.log" 2>&1; then
  tests=$(grep -E 'Tests run: [0-9]+, Failures' "$WORK_DIR/build-new.log" | tail -n 1 | sed 's/.*\(Tests run.*\)/\1/')
  cp target/*.jar "$WORK_DIR/jars/new.jar"
  rm -rf "$WORK_DIR/classes-new"; cp -r target/classes "$WORK_DIR/classes-new"
  result 02 "Build + Unit-Tests gegen $NEW_VERSION" PASS "${tests:-ok}"
else
  result 02 "Build + Unit-Tests gegen $NEW_VERSION" FAIL "Kompilierung oder Tests fehlgeschlagen"
  {
    echo "## Build + Unit-Tests gegen $NEW_VERSION"
    echo; echo '```'
    grep -E '\[ERROR\]|Tests run:|FAIL' "$WORK_DIR/build-new.log" | head -n 80
    echo '```'
  } | section 02-build-new
fi

# ── 3. Bytecode-Vergleich ────────────────────────────────────────────────
if [ -d "$WORK_DIR/classes-old" ] && [ -d "$WORK_DIR/classes-new" ]; then
  (cd "$WORK_DIR/classes-old" && find . -type f | sort | xargs sha256sum) > "$WORK_DIR/sha-old.txt"
  (cd "$WORK_DIR/classes-new" && find . -type f | sort | xargs sha256sum) > "$WORK_DIR/sha-new.txt"
  if diff -q "$WORK_DIR/sha-old.txt" "$WORK_DIR/sha-new.txt" > /dev/null; then
    result 03 "Bytecode alt vs. neu" PASS "byte-identisch ($(wc -l < "$WORK_DIR/sha-new.txt") Dateien) - Neubau nicht nötig"
  else
    changed=$(diff "$WORK_DIR/sha-old.txt" "$WORK_DIR/sha-new.txt" | grep -E '^[<>]' | awk '{print $3}' | sort -u)
    result 03 "Bytecode alt vs. neu" WARN "$(printf '%s\n' "$changed" | wc -l) Datei(en) unterschiedlich - neu gebautes Jar ausrollen"
    {
      echo "## Bytecode-Unterschiede"
      echo
      echo "Der Compiler erzeugt gegen $NEW_VERSION anderen Bytecode (z. B. geänderte Rückgabetypen,"
      echo "Konstanten oder Überladungen). Das alte Jar kann trotzdem laufen - siehe API-Vergleich -,"
      echo "ausgerollt werden sollte aber das neu gebaute."
      echo
      printf -- '- `%s`\n' $changed
    } | section 03-bytecode
  fi
else
  result 03 "Bytecode alt vs. neu" FAIL "übersprungen, ein Build ist fehlgeschlagen"
fi

# ── 4. Drittbibliotheken ─────────────────────────────────────────────────
deps() {
  $MVN dependency:list -Dkeycloak.version="$1" -DincludeScope=provided -DexcludeGroupIds=org.keycloak \
    -DoutputFile="$WORK_DIR/deps-$1.raw" > /dev/null 2>&1 || return 1
  grep -E '^ +[^ ]+:[^ ]+:' "$WORK_DIR/deps-$1.raw" | sed -E 's/^ +//; s/ .*//; s/:provided$//' | sort -u > "$WORK_DIR/deps-$1.txt"
}
if deps "$BASE_VERSION" && deps "$NEW_VERSION"; then
  # Pakete, die unser Code direkt importiert (ohne java.* und org.keycloak.*)
  grep -rhoE '^import (static )?[a-zA-Z0-9_.]+' src/main | awk '{print $NF}' \
    | grep -vE '^(java|javax|jakarta\.annotation|org\.keycloak)\.' | sed -E 's/\.[^.]+$//' | sort -u \
    > "$WORK_DIR/imported-packages.txt"
  python3 - "$WORK_DIR/deps-$BASE_VERSION.txt" "$WORK_DIR/deps-$NEW_VERSION.txt" "$WORK_DIR/imported-packages.txt" \
    "$WORK_DIR/deps-diff.md" "$WORK_DIR/deps.status" <<'EOF2'
import sys
def load(p):
    out = {}
    for line in open(p):
        parts = line.strip().split(":")
        if len(parts) >= 4:
            out[parts[0] + ":" + parts[1]] = parts[-1]
    return out
a, b = load(sys.argv[1]), load(sys.argv[2])
pkgs = [l.strip() for l in open(sys.argv[3]) if l.strip()]
# "direkt benutzt": die groupId ist Präfix eines Pakets, das wir importieren
direct = lambda k: any(p == k.split(":")[0] or p.startswith(k.split(":")[0] + ".") for p in pkgs)
import re
def minor(v):
    return tuple(re.findall(r"\d+", v or "")[:2])
changed = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
hot = [k for k in changed if direct(k)]
# Warnung nur bei Major-/Minor-Sprung einer direkt benutzten Bibliothek, Patch-Updates nur nennen
risky = [k for k in hot if minor(a.get(k)) != minor(b.get(k))]
fmt = lambda ks: ", ".join("%s %s→%s" % (k.split(":")[1], a.get(k, "-"), b.get(k, "-")) for k in ks)
with open(sys.argv[4], "w") as fh:
    if changed:
        fh.write("Fett = Bibliothek, deren Klassen unser Code direkt importiert.\n\n")
        fh.write("| Bibliothek | alt | neu |\n|---|---|---|\n")
        for k in sorted(changed, key=lambda k: (k not in hot, k)):
            name = ("**`%s`**" if k in hot else "`%s`") % k
            fh.write("| %s | %s | %s |\n" % (name, a.get(k, "-"), b.get(k, "-")))
with open(sys.argv[5], "w") as fh:
    if not changed:
        fh.write("PASS\tkeine Versionsänderungen\n")
    elif risky:
        fh.write("WARN\t%d geändert, davon direkt von uns benutzt (Minor/Major): %s\n" % (len(changed), fmt(risky)))
    elif hot:
        fh.write("PASS\t%d geändert, direkt benutzte nur Patch-Updates: %s\n" % (len(changed), fmt(hot)))
    else:
        fh.write("PASS\t%d geändert, keine davon direkt von uns importiert\n" % len(changed))
EOF2
  IFS=$'\t' read -r st txt < "$WORK_DIR/deps.status"
  result 04 "Drittbibliotheken" "$st" "$txt"
  if [ -s "$WORK_DIR/deps-diff.md" ]; then
    { echo "## Geänderte Drittbibliotheken ($BASE_VERSION → $NEW_VERSION)"; echo; cat "$WORK_DIR/deps-diff.md"; } | section 04-deps
  fi
else
  result 04 "Drittbibliotheken" WARN "Abhängigkeitsliste nicht ermittelbar"
fi

# ── 5. API-/Linkage-Vergleich ────────────────────────────────────────────
fetch_kc() {
  local v="$1" d="$WORK_DIR/deps-$1"
  [ -d "$d/jars" ] && [ -d "$d/sources" ] && return 0
  $MVN dependency:copy-dependencies -Dkeycloak.version="$v" -DincludeGroupIds=org.keycloak \
    -DincludeScope=provided -DoutputDirectory="$d/jars" > /dev/null 2>&1 || return 1
  $MVN dependency:copy-dependencies -Dkeycloak.version="$v" -DincludeGroupIds=org.keycloak \
    -DincludeScope=provided -Dclassifier=sources -DfailOnMissingClassifierArtifact=false \
    -DoutputDirectory="$d/sources" > /dev/null 2>&1 || true
}
if [ -d "$WORK_DIR/classes-old" ] && fetch_kc "$BASE_VERSION" && fetch_kc "$NEW_VERSION"; then
  python3 "$SCRIPT_DIR/api_diff.py" \
    --classes "$WORK_DIR/classes-old" \
    --old-version "$BASE_VERSION" --old-jars "$WORK_DIR/deps-$BASE_VERSION/jars" --old-sources "$WORK_DIR/deps-$BASE_VERSION/sources" \
    --new-version "$NEW_VERSION" --new-jars "$WORK_DIR/deps-$NEW_VERSION/jars" --new-sources "$WORK_DIR/deps-$NEW_VERSION/sources" \
    --report "$WORK_DIR/report/05-api.md" --issue "$WORK_DIR/api-issue.md" --status "$WORK_DIR/api.status" 2>/dev/null
  IFS=$'\t' read -r st txt < "$WORK_DIR/api.status"
  result 05 "API-/Linkage-Vergleich" "$st" "$txt"
else
  result 05 "API-/Linkage-Vergleich" FAIL "Keycloak-Artefakte nicht ladbar oder Basis-Build fehlt"
fi

# ── 6./7. Keycloak starten ───────────────────────────────────────────────
smoke() {
  local key="$1" label="$2" jar="$3" title="$4"
  if [ ! -f "$jar" ]; then
    result "$key" "$title" FAIL "übersprungen, kein Jar"
    return
  fi
  "$SCRIPT_DIR/smoke-test.sh" "$NEW_VERSION" "$jar" "$label" > /dev/null 2>&1
  IFS=$'\t' read -r st txt < "$WORK_DIR/smoke-$label.status"
  result "$key" "$title" "$st" "$txt"
  { echo "## $title"; echo; echo '```'; cat "$WORK_DIR/smoke-$label.out"; echo '```'; } | section "$key-smoke-$label"
}
smoke 06 old "$WORK_DIR/jars/old.jar" "Keycloak $NEW_VERSION mit altem Jar"
smoke 07 new "$WORK_DIR/jars/new.jar" "Keycloak $NEW_VERSION mit neu gebautem Jar"

# ── Report ───────────────────────────────────────────────────────────────
icon() { case "$1" in PASS) echo "✅";; WARN) echo "⚠️";; *) echo "❌";; esac; }
overall=PASS
grep -q $'\tWARN\t' "$RESULTS" && overall=WARN
grep -q $'\tFAIL\t' "$RESULTS" && overall=FAIL

{
  echo "# Keycloak $NEW_VERSION – Kompatibilitätscheck"
  echo
  echo "Basis: **$BASE_VERSION** (\`keycloak.version\` in pom.xml) · Neu: **$NEW_VERSION** · Gesamt: $(icon $overall) **$overall**"
  echo
  echo "Release-Infos: [Upgrading Guide $NEW_VERSION](https://www.keycloak.org/docs/$NEW_VERSION/upgrading/) · [Release Notes auf GitHub](https://github.com/keycloak/keycloak/releases/tag/$NEW_VERSION)"
  echo
  echo "| | Prüfung | Ergebnis |"
  echo "|---|---|---|"
  sort "$RESULTS" | while IFS=$'\t' read -r _ title st txt; do
    echo "| $(icon "$st") | $title | $txt |"
  done
  echo
  case "$overall" in
    PASS) echo "**Fazit:** Keine Handlung nötig. Die bestehenden Jars laufen unverändert mit $NEW_VERSION.";;
    WARN) echo "**Fazit:** Läuft, aber Änderungen prüfen (siehe Details). Insbesondere geänderte Oberklassen können das Verhalten unserer Extensions beeinflussen, ohne dass ein Test fehlschlägt.";;
    FAIL) echo "**Fazit:** Handlungsbedarf – mindestens eine Prüfung ist fehlgeschlagen.";;
  esac
} > "$WORK_DIR/summary.md"

{
  cat "$WORK_DIR/summary.md"
  echo
  for f in $(ls "$WORK_DIR/report"/*.md 2>/dev/null | sort); do
    echo; cat "$f"
  done
} > "$WORK_DIR/report.md"

# Kompakte Fassung für GitHub-Issues (Body-Limit 65536 Zeichen): Diffs nur für Oberklassen
{
  cat "$WORK_DIR/summary.md"
  if [ -f "$WORK_DIR/api-issue.md" ]; then
    echo
    cat "$WORK_DIR/api-issue.md"
  fi
  for f in "$WORK_DIR"/report/0[1-7]-*.md; do
    case "$f" in *05-api.md|*04-deps.md|*03-bytecode.md) continue;; esac
    [ -f "$f" ] && grep -q 'FAIL\|ERROR' "$f" && { echo; head -c 6000 "$f"; echo; }
  done
  echo
  echo "Vollständiger Report mit Quelltext-Diffs aller geänderten Klassen und der Liste geänderter Drittbibliotheken: Workflow-Artefakt \`kc-compat-report\`."
} | head -c 64000 > "$WORK_DIR/issue.md"

echo
echo "== Gesamt: $overall  (Report: $WORK_DIR/report.md)"
[ "$overall" != FAIL ]
