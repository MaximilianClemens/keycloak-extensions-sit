#!/usr/bin/env python3
"""
Prüft gegen einen laufenden Keycloak über die Admin-REST-API, dass alle Provider dieses
Projekts geladen sind und sich konfigurieren bzw. ausführen lassen.

  1. Alle Provider-IDs aus expected-providers.txt sind in /admin/serverinfo registriert.
  2. Authenticatoren: Konfigurationsbeschreibung abrufbar, als Execution in einen Flow einfügbar.
  3. Required Action: registrierbar und abrufbar.
  4. IdP-Mapper: für einen OIDC-IdP angeboten und anlegbar.
  5. Protocol Mapper: anlegbar und wird beim Token-Ausstellen tatsächlich ausgeführt
     (Direct Grant, Claim-Inhalt wird geprüft).

Aufruf: smoke_exercise.py <base-url> <expected-providers.txt>
Exit-Code 0 = alles ok. Ausgabe: eine Zeile pro Prüfung (OK/FAIL).
"""
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/")
EXPECTED_FILE = sys.argv[2]
REALM = "sit-compat"
failures = []

# Lokale Verbindung, unabhängig von HTTPS_PROXY/HTTP_PROXY der Umgebung
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(method, path, body=None, token=None, form=None, expect=(200, 201, 204)):
    url = path if path.startswith("http") else BASE + path
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=60) as resp:
            raw = resp.read()
            status = resp.status
            location = resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
        location = None
    if status not in expect:
        raise RuntimeError("%s %s -> HTTP %d: %s" % (method, path, status, raw[:300].decode("utf-8", "replace")))
    if raw:
        try:
            return json.loads(raw), location
        except ValueError:
            return raw.decode("utf-8", "replace"), location
    return None, location


def check(label, fn):
    try:
        detail = fn()
        print("OK    %s%s" % (label, (" - " + detail) if detail else ""))
    except Exception as e:  # noqa: BLE001 - jede Abweichung ist ein Befund
        failures.append(label)
        print("FAIL  %s - %s" % (label, e))


def admin_token():
    tok, _ = call("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    return tok["access_token"]


def load_expected():
    out = []
    with open(EXPECTED_FILE) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                spi, pid = line.split()
                out.append((spi, pid))
    return out


def main():
    token = admin_token()
    expected = load_expected()
    t = lambda: token  # noqa: E731

    # 1. Registrierung
    info, _ = call("GET", "/admin/serverinfo", token=t())
    providers = info.get("providers", {})
    for spi, pid in expected:
        def registered(spi=spi, pid=pid):
            ids = providers.get(spi, {}).get("providers", {})
            if pid not in ids:
                raise RuntimeError("nicht in SPI '%s' registriert" % spi)
        check("registriert: %s/%s" % (spi, pid), registered)

    # Test-Realm frisch anlegen
    call("DELETE", "/admin/realms/" + REALM, token=t(), expect=(204, 404))
    call("POST", "/admin/realms", {"realm": REALM, "enabled": True}, token=t())
    r = "/admin/realms/" + REALM

    # 2. Authenticatoren
    authenticators = [pid for spi, pid in expected if spi == "authenticator"]
    flow = "sit-compat-flow"

    def copy_flow():
        call("POST", r + "/authentication/flows/browser/copy", {"newName": flow}, token=t())
    check("Browser-Flow kopieren", copy_flow)

    for pid in authenticators:
        def describe(pid=pid):
            desc, _ = call("GET", r + "/authentication/config-description/" + pid, token=t())
            return "%d Konfig-Properties" % len(desc.get("properties", []))
        check("Authenticator Konfigbeschreibung: " + pid, describe)

        def add_execution(pid=pid):
            call("POST", r + "/authentication/flows/%s/executions/execution" % flow, {"provider": pid}, token=t())
            execs, _ = call("GET", r + "/authentication/flows/%s/executions" % flow, token=t())
            if not any(e.get("providerId") == pid for e in execs):
                raise RuntimeError("Execution nicht im Flow")
        check("Authenticator als Execution: " + pid, add_execution)

    # 3. Required Actions
    for pid in [pid for spi, pid in expected if spi == "required-action"]:
        def required_action(pid=pid):
            registered, _ = call("GET", r + "/authentication/required-actions", token=t())
            if not any(a.get("providerId") == pid for a in registered):
                unregistered, _ = call("GET", r + "/authentication/unregistered-required-actions", token=t())
                match = [a for a in unregistered if a.get("providerId") == pid]
                if not match:
                    raise RuntimeError("weder registriert noch registrierbar")
                call("POST", r + "/authentication/register-required-action",
                     {"providerId": pid, "name": match[0].get("name", pid)}, token=t())
            ra, _ = call("GET", r + "/authentication/required-actions/" + pid, token=t())
            return "Name: %s" % ra.get("name")
        check("Required Action registrieren: " + pid, required_action)

    # 4. Identity-Provider-Mapper
    idp = "sit-compat-idp"

    def create_idp():
        call("POST", r + "/identity-provider/instances", {
            "alias": idp, "providerId": "oidc", "enabled": True,
            "config": {"clientId": "x", "clientSecret": "x", "clientAuthMethod": "client_secret_post",
                       "authorizationUrl": "https://idp.invalid/auth", "tokenUrl": "https://idp.invalid/token",
                       "syncMode": "FORCE"}}, token=t())
    check("OIDC-IdP anlegen", create_idp)

    for pid in [pid for spi, pid in expected if spi == "identity-provider-mapper"]:
        def idp_mapper(pid=pid):
            types, _ = call("GET", r + "/identity-provider/instances/%s/mapper-types" % idp, token=t())
            if pid not in types:
                raise RuntimeError("wird für OIDC-IdP nicht angeboten")
            call("POST", r + "/identity-provider/instances/%s/mappers" % idp, {
                "name": pid, "identityProviderAlias": idp, "identityProviderMapper": pid,
                "config": {"syncMode": "FORCE", "claim": "groups"}}, token=t())
            mappers, _ = call("GET", r + "/identity-provider/instances/%s/mappers" % idp, token=t())
            if not any(m.get("identityProviderMapper") == pid for m in mappers):
                raise RuntimeError("Mapper nicht angelegt")
        check("IdP-Mapper anlegen: " + pid, idp_mapper)

    # 5. Protocol Mapper - wird beim Token-Ausstellen wirklich ausgeführt
    client_id = "sit-compat-client"
    claim = "sit_compat_groups"

    def setup_user():
        _, loc = call("POST", r + "/groups", {"name": "SSO"}, token=t())
        sso = loc.rsplit("/", 1)[1]
        _, loc = call("POST", r + "/groups/%s/children" % sso, {"name": "team"}, token=t())
        team = loc.rsplit("/", 1)[1]
        _, loc = call("POST", r + "/groups", {"name": "Other"}, token=t())
        other = loc.rsplit("/", 1)[1]
        _, loc = call("POST", r + "/users", {
            "username": "compat", "enabled": True, "email": "compat@example.org", "emailVerified": True,
            "firstName": "Compat", "lastName": "Test",
            "credentials": [{"type": "password", "value": "compat", "temporary": False}]}, token=t())
        uid = loc.rsplit("/", 1)[1]
        for g in (team, other):
            call("PUT", r + "/users/%s/groups/%s" % (uid, g), token=t())
    check("Testgruppen und -benutzer anlegen", setup_user)

    for pid in [pid for spi, pid in expected if spi == "protocol-mapper"]:
        def protocol_mapper(pid=pid):
            call("POST", r + "/clients", {
                "clientId": client_id, "publicClient": True, "directAccessGrantsEnabled": True,
                "protocolMappers": [{
                    "name": pid, "protocol": "openid-connect", "protocolMapper": pid,
                    "config": {"claimName": claim, "fullPath": "true", "pathPrefix": "/SSO",
                               "access.token.claim": "true", "id.token.claim": "true",
                               "userinfo.token.claim": "true"}}]}, token=t())
            tok, _ = call("POST", "/realms/%s/protocol/openid-connect/token" % REALM, form={
                "grant_type": "password", "client_id": client_id, "username": "compat", "password": "compat",
                "scope": "openid"})
            payload = tok["access_token"].split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if claims.get(claim) != ["/SSO/team"]:
                raise RuntimeError("Claim '%s' = %r, erwartet ['/SSO/team']" % (claim, claims.get(claim)))
            return "Claim %s=%s" % (claim, claims[claim])
        check("Protocol Mapper im Token: " + pid, protocol_mapper)

    print()
    print("%d Prüfung(en) fehlgeschlagen" % len(failures) if failures else "Alle Prüfungen bestanden")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print("FAIL  Abbruch - %s" % e)
        sys.exit(1)
