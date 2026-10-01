#!/usr/bin/env bash
# Gibt die neueste finale Keycloak-Version aus, für die die Server-Distribution in
# Maven Central liegt (Release-Kandidaten, Nightlies o. Ä. werden ignoriert).
set -euo pipefail
curl -fsS --retry 5 --retry-delay 5 --retry-all-errors \
  https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/maven-metadata.xml \
  | grep -oE '<version>[0-9]+\.[0-9]+\.[0-9]+</version>' \
  | sed -E 's#</?version>##g' \
  | sort -V | tail -n 1
