#!/usr/bin/env bash
# =====================================================================
# run-all.sh – compatibility check against a (new) Keycloak release
#
#   ci/kc-compat/run-all.sh [NEW_VERSION] [BASE_VERSION]
#
#   NEW_VERSION   default: newest final release in Maven Central
#   BASE_VERSION  default: keycloak.version from pom.xml
#
# Checks:
#   1. Build the jar against the base version (= the "old" jar as deployed today)
#   2. Build + unit tests against the new version
#   3. Bytecode comparison: is a rebuild needed at all?
#   4. Changed third-party libraries (e.g. webauthn4j)
#   5. API/linkage comparison of every Keycloak class we use or extend, including
#      overridden methods, new superclass API and the upstream commits behind it
#   6. Start the NEW Keycloak with the old jar + admin API / token checks
#   7. Start the NEW Keycloak with the rebuilt jar + the same checks
#
# Environment:
#   WORK_DIR  working directory (default: ./.kc-compat)
#   OLD_JAR   use an existing jar instead of step 1 (e.g. the one actually deployed)
#
# Output: $WORK_DIR/report.md (full), $WORK_DIR/summary.md (overview),
#         $WORK_DIR/issue.md (compact, for GitHub issues)
# Exit code 1 if at least one check FAILs.
# Locally: Java 21+, Maven, Python 3 and git are enough – no Docker needed.
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

echo "== Keycloak compatibility check: base $BASE_VERSION → new $NEW_VERSION"

# result <key> <title> <STATUS> <text>
result() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "[$3] $2: $4"; }
section() { cat >> "$WORK_DIR/report/$1.md"; }

# ── 0. Provider list consistent? ─────────────────────────────────────────
expected=$(grep -cvE '^\s*(#|$)' "$SCRIPT_DIR/expected-providers.txt")
registered=$(cat src/main/resources/META-INF/services/* | grep -cvE '^\s*(#|$)')
if [ "$expected" -ne "$registered" ]; then
  result 00 "Provider list" FAIL "expected-providers.txt has $expected entries, META-INF/services $registered"
fi

# ── 1. Old jar ───────────────────────────────────────────────────────────
if [ -n "${OLD_JAR:-}" ]; then
  cp "$OLD_JAR" "$WORK_DIR/jars/old.jar"
  result 01 "Old jar" PASS "given: $(basename "$OLD_JAR")"
  $MVN clean compile -Dkeycloak.version="$BASE_VERSION" > "$WORK_DIR/build-old.log" 2>&1
  rm -rf "$WORK_DIR/classes-old"; cp -r target/classes "$WORK_DIR/classes-old"
elif $MVN clean package -DskipTests -Dkeycloak.version="$BASE_VERSION" > "$WORK_DIR/build-old.log" 2>&1; then
  cp target/*.jar "$WORK_DIR/jars/old.jar"
  rm -rf "$WORK_DIR/classes-old"; cp -r target/classes "$WORK_DIR/classes-old"
  result 01 "Old jar (built against $BASE_VERSION)" PASS "$(basename target/*.jar)"
else
  result 01 "Old jar (built against $BASE_VERSION)" FAIL "build failed"
  { echo "## Build against $BASE_VERSION"; echo; echo '```'; tail -n 60 "$WORK_DIR/build-old.log"; echo '```'; } | section 01-build-old
fi

# ── 2. Build + tests against the new version ─────────────────────────────
if mvn -B clean verify -Dkeycloak.version="$NEW_VERSION" > "$WORK_DIR/build-new.log" 2>&1; then
  tests=$(grep -E 'Tests run: [0-9]+, Failures' "$WORK_DIR/build-new.log" | tail -n 1 | sed 's/.*\(Tests run.*\)/\1/')
  cp target/*.jar "$WORK_DIR/jars/new.jar"
  rm -rf "$WORK_DIR/classes-new"; cp -r target/classes "$WORK_DIR/classes-new"
  result 02 "Build + unit tests against $NEW_VERSION" PASS "${tests:-ok}"
else
  result 02 "Build + unit tests against $NEW_VERSION" FAIL "compilation or tests failed"
  {
    echo "## Build + unit tests against $NEW_VERSION"
    echo; echo '```'
    grep -E '\[ERROR\]|Tests run:|FAIL' "$WORK_DIR/build-new.log" | head -n 80
    echo '```'
  } | section 02-build-new
fi

# ── 3. Bytecode comparison ───────────────────────────────────────────────
if [ -d "$WORK_DIR/classes-old" ] && [ -d "$WORK_DIR/classes-new" ]; then
  (cd "$WORK_DIR/classes-old" && find . -type f | sort | xargs sha256sum) > "$WORK_DIR/sha-old.txt"
  (cd "$WORK_DIR/classes-new" && find . -type f | sort | xargs sha256sum) > "$WORK_DIR/sha-new.txt"
  if diff -q "$WORK_DIR/sha-old.txt" "$WORK_DIR/sha-new.txt" > /dev/null; then
    result 03 "Bytecode old vs. new" PASS "byte-identical ($(wc -l < "$WORK_DIR/sha-new.txt") files) - no rebuild needed"
  else
    changed=$(diff "$WORK_DIR/sha-old.txt" "$WORK_DIR/sha-new.txt" | grep -E '^[<>]' | awk '{print $3}' | sort -u)
    result 03 "Bytecode old vs. new" WARN "$(printf '%s\n' "$changed" | wc -l) file(s) differ - roll out the rebuilt jar"
    {
      echo "## Bytecode differences"
      echo
      echo "Compiling against $NEW_VERSION produces different bytecode (e.g. changed return types,"
      echo "constants or overloads). The old jar may still run - see the API comparison - but the"
      echo "rebuilt one should be rolled out."
      echo
      printf -- '- `%s`\n' $changed
    } | section 03-bytecode
  fi
else
  result 03 "Bytecode old vs. new" FAIL "skipped, a build failed"
fi

# ── 4. Third-party libraries ─────────────────────────────────────────────
deps() {
  $MVN dependency:list -Dkeycloak.version="$1" -DincludeScope=provided -DexcludeGroupIds=org.keycloak \
    -DoutputFile="$WORK_DIR/deps-$1.raw" > /dev/null 2>&1 || return 1
  grep -E '^ +[^ ]+:[^ ]+:' "$WORK_DIR/deps-$1.raw" | sed -E 's/^ +//; s/ .*//; s/:provided$//' | sort -u > "$WORK_DIR/deps-$1.txt"
}
if deps "$BASE_VERSION" && deps "$NEW_VERSION"; then
  # packages our code imports directly (without java.* and org.keycloak.*)
  grep -rhoE '^import (static )?[a-zA-Z0-9_.]+' src/main | awk '{print $NF}' \
    | grep -vE '^(java|javax|jakarta\.annotation|org\.keycloak)\.' | sed -E 's/\.[^.]+$//' | sort -u \
    > "$WORK_DIR/imported-packages.txt"
  python3 - "$WORK_DIR/deps-$BASE_VERSION.txt" "$WORK_DIR/deps-$NEW_VERSION.txt" "$WORK_DIR/imported-packages.txt" \
    "$WORK_DIR/deps-diff.md" "$WORK_DIR/deps.status" <<'EOF2'
import re
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
# "used directly": the groupId is a prefix of a package we import
direct = lambda k: any(p == k.split(":")[0] or p.startswith(k.split(":")[0] + ".") for p in pkgs)
def minor(v):
    return tuple(re.findall(r"\d+", v or "")[:2])
changed = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
hot = [k for k in changed if direct(k)]
# warn only on a major/minor bump of a library we use directly, just mention patch updates
risky = [k for k in hot if minor(a.get(k)) != minor(b.get(k))]
fmt = lambda ks: ", ".join("%s %s→%s" % (k.split(":")[1], a.get(k, "-"), b.get(k, "-")) for k in ks)
with open(sys.argv[4], "w") as fh:
    if changed:
        fh.write("Bold = library whose classes our code imports directly.\n\n")
        fh.write("| Library | old | new |\n|---|---|---|\n")
        for k in sorted(changed, key=lambda k: (k not in hot, k)):
            name = ("**`%s`**" if k in hot else "`%s`") % k
            fh.write("| %s | %s | %s |\n" % (name, a.get(k, "-"), b.get(k, "-")))
with open(sys.argv[5], "w") as fh:
    if not changed:
        fh.write("PASS\tno version changes\n")
    elif risky:
        fh.write("WARN\t%d changed, used directly by us (minor/major): %s\n" % (len(changed), fmt(risky)))
    elif hot:
        fh.write("PASS\t%d changed, only patch updates of libraries we use directly: %s\n" % (len(changed), fmt(hot)))
    else:
        fh.write("PASS\t%d changed, none imported directly by our code\n" % len(changed))
EOF2
  IFS=$'\t' read -r st txt < "$WORK_DIR/deps.status"
  result 04 "Third-party libraries" "$st" "$txt"
  if [ -s "$WORK_DIR/deps-diff.md" ]; then
    { echo "## Changed third-party libraries ($BASE_VERSION → $NEW_VERSION)"; echo; cat "$WORK_DIR/deps-diff.md"; } | section 04-deps
  fi
else
  result 04 "Third-party libraries" WARN "dependency list could not be determined"
fi

# ── 5. API/linkage comparison ────────────────────────────────────────────
fetch_kc() {
  local v="$1" d="$WORK_DIR/deps-$1"
  [ -d "$d/jars" ] && [ -d "$d/sources" ] && return 0
  $MVN dependency:copy-dependencies -Dkeycloak.version="$v" -DincludeGroupIds=org.keycloak \
    -DincludeScope=provided -DoutputDirectory="$d/jars" > /dev/null 2>&1 || return 1
  $MVN dependency:copy-dependencies -Dkeycloak.version="$v" -DincludeGroupIds=org.keycloak \
    -DincludeScope=provided -Dclassifier=sources -DfailOnMissingClassifierArtifact=false \
    -DoutputDirectory="$d/sources" > /dev/null 2>&1 || true
}
# Commits of the new release that are not in the base release, without file contents
# (blobs are fetched on demand). Takes a few seconds and a few MB; optional.
UPSTREAM_GIT="$WORK_DIR/keycloak.git"
fetch_upstream() {
  rm -rf "$UPSTREAM_GIT"
  git init -q --bare "$UPSTREAM_GIT" &&
  git --git-dir "$UPSTREAM_GIT" remote add origin https://github.com/keycloak/keycloak &&
  timeout 300 git --git-dir "$UPSTREAM_GIT" fetch -q --filter=blob:none --shallow-exclude="$BASE_VERSION" \
    origin tag "$NEW_VERSION" > "$WORK_DIR/upstream.log" 2>&1
}
if ! fetch_upstream; then
  echo "note: upstream history not available, commit links omitted (see upstream.log)"
  rm -rf "$UPSTREAM_GIT"
fi
if [ -d "$WORK_DIR/classes-old" ] && fetch_kc "$BASE_VERSION" && fetch_kc "$NEW_VERSION"; then
  python3 "$SCRIPT_DIR/api_diff.py" \
    --classes "$WORK_DIR/classes-old" \
    --old-version "$BASE_VERSION" --old-jars "$WORK_DIR/deps-$BASE_VERSION/jars" --old-sources "$WORK_DIR/deps-$BASE_VERSION/sources" \
    --new-version "$NEW_VERSION" --new-jars "$WORK_DIR/deps-$NEW_VERSION/jars" --new-sources "$WORK_DIR/deps-$NEW_VERSION/sources" \
    --upstream-git "$UPSTREAM_GIT" \
    --report "$WORK_DIR/report/05-api.md" --issue "$WORK_DIR/api-issue.md" --status "$WORK_DIR/api.status" 2>/dev/null
  IFS=$'\t' read -r st txt < "$WORK_DIR/api.status"
  result 05 "API/linkage comparison" "$st" "$txt"
else
  result 05 "API/linkage comparison" FAIL "Keycloak artifacts not available or base build missing"
fi

# ── 6./7. Start Keycloak ─────────────────────────────────────────────────
smoke() {
  local key="$1" label="$2" jar="$3" title="$4"
  if [ ! -f "$jar" ]; then
    result "$key" "$title" FAIL "skipped, no jar"
    return
  fi
  "$SCRIPT_DIR/smoke-test.sh" "$NEW_VERSION" "$jar" "$label" > /dev/null 2>&1
  IFS=$'\t' read -r st txt < "$WORK_DIR/smoke-$label.status"
  result "$key" "$title" "$st" "$txt"
  { echo "## $title"; echo; echo '```'; cat "$WORK_DIR/smoke-$label.out"; echo '```'; } | section "$key-smoke-$label"
}
smoke 06 old "$WORK_DIR/jars/old.jar" "Keycloak $NEW_VERSION with the old jar"
smoke 07 new "$WORK_DIR/jars/new.jar" "Keycloak $NEW_VERSION with the rebuilt jar"

# ── Report ───────────────────────────────────────────────────────────────
icon() { case "$1" in PASS) echo "✅";; WARN) echo "⚠️";; *) echo "❌";; esac; }
overall=PASS
grep -q $'\tWARN\t' "$RESULTS" && overall=WARN
grep -q $'\tFAIL\t' "$RESULTS" && overall=FAIL

{
  echo "# Keycloak $NEW_VERSION – compatibility check"
  echo
  echo "Base: **$BASE_VERSION** (\`keycloak.version\` in pom.xml) · New: **$NEW_VERSION** · Overall: $(icon $overall) **$overall**"
  echo
  echo "Release information: [Upgrading guide $NEW_VERSION](https://www.keycloak.org/docs/$NEW_VERSION/upgrading/) · [Release notes on GitHub](https://github.com/keycloak/keycloak/releases/tag/$NEW_VERSION)"
  echo
  echo "| | Check | Result |"
  echo "|---|---|---|"
  sort "$RESULTS" | while IFS=$'\t' read -r _ title st txt; do
    echo "| $(icon "$st") | $title | $txt |"
  done
  echo
  case "$overall" in
    PASS) echo "**Verdict:** Nothing to do. The existing jars run unchanged on $NEW_VERSION.";;
    WARN) echo "**Verdict:** Runs, but review the changes below. Changed superclasses in particular can alter the behaviour of our extensions without any test failing.";;
    FAIL) echo "**Verdict:** Action required – at least one check failed.";;
  esac
} > "$WORK_DIR/summary.md"

{
  cat "$WORK_DIR/summary.md"
  echo
  for f in $(ls "$WORK_DIR/report"/*.md 2>/dev/null | sort); do
    echo; cat "$f"
  done
} > "$WORK_DIR/report.md"

# Compact variant for GitHub issues (body limit 65536 characters): diffs only for superclasses
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
  echo "Full report with the source diffs of every changed class and the list of changed third-party libraries: workflow artifact \`kc-compat-report\`."
} | head -c 64000 > "$WORK_DIR/issue.md"

echo
echo "== Overall: $overall  (report: $WORK_DIR/report.md)"
[ "$overall" != FAIL ]
