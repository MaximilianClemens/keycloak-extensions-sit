#!/usr/bin/env bash
# Prints the newest final Keycloak version whose server distribution is available in
# Maven Central (release candidates, nightlies and the like are ignored).
set -euo pipefail
curl -fsS --retry 5 --retry-delay 5 --retry-all-errors \
  https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/maven-metadata.xml \
  | grep -oE '<version>[0-9]+\.[0-9]+\.[0-9]+</version>' \
  | sed -E 's#</?version>##g' \
  | sort -V | tail -n 1
