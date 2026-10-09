#!/usr/bin/env python3
"""
End-to-end test for sit-auth-spnego-button against a running Keycloak and a real KDC.

Configures a realm through the admin API (Kerberos user federation with the keytab from
setup-kdc.sh, a browser flow with the on-demand Kerberos execution after the forms, a
public client) and then plays the login the way a browser does, with curl:

  A. kinit alice -> login page -> "try another way" lists the execution -> select it
     -> 303 to the refresh URL -> GET with Negotiate -> 302 with an authorization code
     -> code exchanged, token says preferred_username=alice
  B. no ticket -> same selection -> 401 with Keycloak's fallback form -> fallback POST
     -> password form (no "page expired")
  F. conditional placement ("double wrapper"): ALTERNATIVE sub-flow > CONDITIONAL sub-flow >
     condition + button ALTERNATIVE. Condition true: offered, login with ticket, fallback without ticket.
     Condition false: not offered, a forged selection is not accepted.
  G. step-up layout: bronze REQUIRED (password sub-flow | button, both ALTERNATIVE), then
     silver CONDITIONAL (condition + OTP). The click skips only the password; after Kerberos
     the silver OTP step follows instead of an authorization code.
  C. the built-in auth-spnego selected the same way -> "page expired"
     (documents the Keycloak behaviour this provider works around; if this check ever
     fails, Keycloak fixed it upstream and the provider may be retired)
  D. sit-auth-spnego-level inside a step-up flow (first factor sub-flow, conditional OTP
     sub-flow guarded by sit-conditional-current-loa < 2): a ticket obtained with PKINIT
     (indicator "pkinit") logs in at level 2 and skips OTP, acr claim "silver"; a password
     ticket is level 1 and runs into the OTP step. Needs the PKINIT set-up of setup-kdc.sh.

Usage: kerberos_e2e.py <base-url> <keytab>
The base URL must use the host of the service principal (http://keycloak.example.test:8080).
Exit code 0 = all checks passed. Output: one line per check (OK/FAIL).
"""
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/")
KEYTAB = sys.argv[2]
REALM = "e2e"
KRB_REALM = "EXAMPLE.TEST"
SPN = "HTTP/" + urllib.parse.urlparse(BASE).hostname + "@" + KRB_REALM
CLIENT_ID = "e2e-client"
REDIRECT_URI = BASE + "/e2e/callback"
FLOW_BUTTON = "e2e-browser-button"
FLOW_BUILTIN = "e2e-browser-builtin"
FLOW_NESTED = "e2e-browser-nested"
FLOW_STEPUP = "e2e-browser-stepup"
FLOW_LEVEL = "e2e-level"
PROVIDER_BUTTON = "sit-auth-spnego-button"
PROVIDER_BUILTIN = "auth-spnego"
PROVIDER_LEVEL = "sit-auth-spnego-level"
PROVIDER_CURRENT_LOA = "sit-conditional-current-loa"
PKINIT_DIR = os.environ.get("PKINIT_DIR", os.path.join(os.path.dirname(os.path.abspath(KEYTAB)), "pkinit"))

failures = []
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ── helpers ─────────────────────────────────────────────────────────────────

def check(label, fn):
    try:
        detail = fn()
        print("OK    %s%s" % (label, (" - " + detail) if detail else ""))
        return True
    except Exception as e:  # noqa: BLE001 - every deviation is a finding
        failures.append(label)
        print("FAIL  %s - %s" % (label, e))
        return False


def api(method, path, body=None, token=None, form=None, expect=(200, 201, 204)):
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
            raw, status, location = resp.read(), resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        raw, status, location = e.read(), e.code, None
    if status not in expect:
        raise RuntimeError("%s %s -> HTTP %d: %s" % (method, path, status, raw[:300].decode("utf-8", "replace")))
    if raw:
        try:
            return json.loads(raw), location
        except ValueError:
            return raw.decode("utf-8", "replace"), location
    return None, location


def admin_token():
    tok, _ = api("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    return tok["access_token"]


class Browser:
    """Minimal browser stand-in on top of curl: cookie jar, no automatic redirects, optional
    SPNEGO. Note that curl sends the Negotiate token proactively (no 401 round trip), while a
    browser only does so after a 401. The scenarios therefore send the request twice: plain,
    expecting the challenge, and again with --negotiate, which is what the browser's retry
    looks like on the wire."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="e2e-")
        self.jar = os.path.join(self.dir, "cookies")

    def request(self, method, url, data=None, negotiate=False):
        hdr = os.path.join(self.dir, "headers")
        cmd = ["curl", "-s", "--noproxy", "*", "-c", self.jar, "-b", self.jar, "-D", hdr,
               "-o", "-", "-w", "\n%{http_code}", "-X", method]
        if negotiate:
            cmd += ["--negotiate", "-u", ":"]
        if data is not None:
            cmd += ["--data", urllib.parse.urlencode(data)]
        cmd.append(url)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise RuntimeError("curl failed (%d): %s" % (out.returncode, out.stderr.strip()[:300]))
        body, _, status = out.stdout.rpartition("\n")
        with open(hdr) as fh:
            raw_headers = fh.read()
        # with --negotiate curl writes both the 401 and the final response headers
        rounds = [b for b in raw_headers.split("\r\n\r\n") if b.strip()]
        headers = {}
        for line in rounds[-1].splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        statuses = [int(b.split()[1]) for b in rounds if b.startswith("HTTP/")]
        return int(status), headers, body, statuses


def form_action(body, form_id):
    m = re.search(r'<form[^>]*id="%s"[^>]*action="([^"]+)"' % re.escape(form_id), body)
    if not m:
        raise RuntimeError("form '%s' not in page" % form_id)
    return html.unescape(m.group(1))


def selection_form(body, exec_id):
    """Action URL of the select-authenticator option that posts the given execution id."""
    for m in re.finditer(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', body, re.S):
        if 'name="authenticationExecution"' in m.group(2) and exec_id in m.group(2):
            return html.unescape(m.group(1))
    raise RuntimeError("execution %s not offered on the select-authenticator page" % exec_id)


def auth_url():
    return BASE + "/realms/%s/protocol/openid-connect/auth?" % REALM + urllib.parse.urlencode({
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid"})


def kinit():
    subprocess.run(["kinit", "alice"], input="alicepw\n", capture_output=True, text=True, check=True, timeout=30)


def kinit_pkinit():
    identity = "X509_user_identity=FILE:%s/alice.pem,%s/alicekey.pem" % (PKINIT_DIR, PKINIT_DIR)
    subprocess.run(["kinit", "-X", identity, "alice"], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                   check=True, timeout=30)


def pkinit_available():
    return os.path.exists(os.path.join(PKINIT_DIR, "alice.pem"))


def kdestroy():
    subprocess.run(["kdestroy", "-A"], capture_output=True, text=True, timeout=30)


# ── realm setup ─────────────────────────────────────────────────────────────

def setup_realm(t):
    r = "/admin/realms/" + REALM
    api("DELETE", r, token=t, expect=(204, 404))
    api("POST", "/admin/realms", {"realm": REALM, "enabled": True, "defaultLocale": "en",
                                   "internationalizationEnabled": False,
                                   "attributes": {"acr.loa.map": json.dumps({"bronze": 1, "silver": 2, "gold": 3})}},
        token=t)

    api("POST", r + "/components", {
        "name": "kerberos", "providerId": "kerberos",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "kerberosRealm": [KRB_REALM], "serverPrincipal": [SPN], "keyTab": [KEYTAB],
            "debug": ["true"], "allowPasswordAuthentication": ["false"],
            "updateProfileFirstLogin": ["false"], "editMode": ["READ_ONLY"],
            "enabled": ["true"], "priority": ["0"], "cachePolicy": ["DEFAULT"],
        }}, token=t)

    # A user imported from Kerberos has neither e-mail nor name; without this the login would
    # end on the "update profile" page instead of at the client.
    api("PUT", r + "/authentication/required-actions/VERIFY_PROFILE",
        {"alias": "VERIFY_PROFILE", "providerId": "VERIFY_PROFILE", "name": "Verify Profile",
         "enabled": False, "defaultAction": False, "priority": 10, "config": {}}, token=t)

    api("POST", r + "/clients", {
        "clientId": CLIENT_ID, "publicClient": True, "standardFlowEnabled": True,
        "redirectUris": [REDIRECT_URI], "enabled": True}, token=t)

    execs = {}
    execs[FLOW_BUTTON] = build_flow(t, FLOW_BUTTON, PROVIDER_BUTTON, before_forms=False)
    execs[FLOW_BUILTIN] = build_flow(t, FLOW_BUILTIN, PROVIDER_BUILTIN, before_forms=False)
    execs[FLOW_NESTED] = build_nested_flow(t, FLOW_NESTED)
    execs[FLOW_STEPUP] = build_stepup_flow(t, FLOW_STEPUP)
    execs[FLOW_LEVEL] = build_level_flow(t)
    return execs


def build_level_flow(t):
    """A step-up flow built from scratch:

        e2e-level
        |- Cookie                                   ALTERNATIVE
        `- login (sub-flow)                         ALTERNATIVE
           |- first (sub-flow)                      REQUIRED
           |  |- password (sub-flow)                ALTERNATIVE
           |  |  `- Username Password Form          REQUIRED
           |  `- SIT: Kerberos (level from ticket)  ALTERNATIVE  indicators=pkinit, 2/1
           `- otp (sub-flow)                        CONDITIONAL
              |- Condition - Current LOA below 2    REQUIRED
              `- OTP Form                           REQUIRED
    """
    r = "/admin/realms/" + REALM
    api("POST", r + "/authentication/flows",
        {"alias": FLOW_LEVEL, "providerId": "basic-flow", "topLevel": True, "builtIn": False, "description": ""}, token=t)

    def executions(flow_alias):
        execs, _ = api("GET", r + "/authentication/flows/%s/executions" % urllib.parse.quote(flow_alias), token=t)
        return execs

    def set_requirement(flow_alias, execution, requirement):
        rep = dict(execution)
        rep["requirement"] = requirement
        api("PUT", r + "/authentication/flows/%s/executions" % urllib.parse.quote(flow_alias), rep, token=t)

    def add_execution(flow_alias, provider, requirement, config=None):
        api("POST", r + "/authentication/flows/%s/executions/execution" % urllib.parse.quote(flow_alias),
            {"provider": provider}, token=t)
        ex = [e for e in executions(flow_alias) if e.get("level", 0) == 0 and e.get("providerId") == provider][-1]
        set_requirement(flow_alias, ex, requirement)
        if config:
            api("POST", r + "/authentication/executions/%s/config" % ex["id"],
                {"alias": "%s-%s" % (flow_alias, provider), "config": config}, token=t)
        return ex

    def add_subflow(parent_alias, alias, requirement):
        api("POST", r + "/authentication/flows/%s/executions/flow" % urllib.parse.quote(parent_alias),
            {"alias": alias, "type": "basic-flow", "provider": "registration-page-form", "description": ""}, token=t)
        ex = [e for e in executions(parent_alias) if e.get("level", 0) == 0 and e.get("displayName") == alias][-1]
        set_requirement(parent_alias, ex, requirement)
        return alias

    add_execution(FLOW_LEVEL, "auth-cookie", "ALTERNATIVE")
    login = add_subflow(FLOW_LEVEL, FLOW_LEVEL + " login", "ALTERNATIVE")
    first = add_subflow(login, FLOW_LEVEL + " first", "REQUIRED")
    password = add_subflow(first, FLOW_LEVEL + " password", "ALTERNATIVE")
    add_execution(password, "auth-username-password-form", "REQUIRED")
    level = add_execution(first, PROVIDER_LEVEL, "ALTERNATIVE", {
        "auth.indicators": "pkinit",
        # a dummy AMA SID: makes the authenticator parse and verify the (MIT) PAC too
        "ama.group.sids": "S-1-5-21-1-2-3-4",
        "level.matched": "2", "level.default": "1"})
    otp = add_subflow(login, FLOW_LEVEL + " otp", "CONDITIONAL")
    add_execution(otp, PROVIDER_CURRENT_LOA, "REQUIRED", {"loa-condition-level": "2"})
    add_execution(otp, "auth-otp-form", "REQUIRED")
    if os.environ.get("E2E_DEBUG"):
        print("  %s: %s" % (FLOW_LEVEL, [(e.get("level"), e.get("providerId") or e.get("displayName"), e["requirement"])
                                         for e in executions(FLOW_LEVEL)]))
    return level["id"]


def build_flow(t, name, provider, before_forms):
    """Copy of the browser flow with <provider> as ALTERNATIVE, either before the forms
    sub-flow (what this provider needs) or after it (where the built-in one is usually
    put for a 'try another way' setup). A passkey alternative is added as well so that the
    login page shows the "try another way" link, which Keycloak hides for a single option."""
    r = "/admin/realms/" + REALM
    api("POST", r + "/authentication/flows/browser/copy", {"newName": name}, token=t)
    path = r + "/authentication/flows/%s/executions" % urllib.parse.quote(name)

    def top_level():
        execs, _ = api("GET", path, token=t)
        return [e for e in execs if e.get("level", 0) == 0]

    def update(execution, **changes):
        # Always PUT the full representation: a partial one resets the priority to 0.
        rep = dict(execution)
        rep.update(changes)
        api("PUT", path, rep, token=t)

    def add(provider_id):
        api("POST", path + "/execution", {"provider": provider_id}, token=t)
        return next(e for e in top_level() if e.get("providerId") == provider_id)

    forms = next(e for e in top_level() if e.get("authenticationFlow") and "forms" in e.get("displayName", "").lower())

    builtin = next(e for e in top_level() if e.get("providerId") == PROVIDER_BUILTIN)
    if provider == PROVIDER_BUILTIN:
        target = builtin
    else:
        update(builtin, requirement="DISABLED")
        target = add(provider)
    update(target, requirement="ALTERNATIVE",
           priority=forms["priority"] - 1 if before_forms else forms["priority"] + 1)

    passkey = add("webauthn-authenticator-passwordless")
    update(passkey, requirement="ALTERNATIVE", priority=forms["priority"] + 2)

    top = top_level()
    idx = {e["id"]: i for i, e in enumerate(top)}
    assert (idx[target["id"]] < idx[forms["id"]]) == before_forms, \
        "unexpected order: %s" % [(e.get("providerId") or e.get("displayName"), e["requirement"]) for e in top]
    if os.environ.get("E2E_DEBUG"):
        print("  %s: %s" % (name, [(e.get("providerId") or e.get("displayName"), e["requirement"]) for e in top]))
    return target["id"]


def build_nested_flow(t, name):
    """Copy of the browser flow with the button behind a condition ("double wrapper"):
         forms ALT | <name>-kerberos ALT > <name>-intern CONDITIONAL > client-scope condition
         REQUIRED + button ALTERNATIVE | passkey ALT
    The condition is "client requests scope 'profile'" (a default scope, so true); it stands in
    for a network condition. Returns (button execution id, condition config id)."""
    r = "/admin/realms/" + REALM
    api("POST", r + "/authentication/flows/browser/copy", {"newName": name}, token=t)
    q = urllib.parse.quote
    path = r + "/authentication/flows/%s/executions" % q(name)

    def all_execs():
        execs, _ = api("GET", path, token=t)
        return execs

    def update(execution, **changes):
        rep = dict(execution)
        rep.update(changes)
        api("PUT", path, rep, token=t)

    builtin = next(e for e in all_execs() if e.get("providerId") == PROVIDER_BUILTIN)
    update(builtin, requirement="DISABLED")

    wrap, intern = name + "-kerberos", name + "-intern"
    api("POST", path + "/flow", {"alias": wrap, "type": "basic-flow", "provider": "registration-page-form",
                                 "description": "Kerberos (wrapper)"}, token=t)
    api("POST", r + "/authentication/flows/%s/executions/flow" % q(wrap),
        {"alias": intern, "type": "basic-flow", "provider": "registration-page-form", "description": "Kerberos intern"}, token=t)
    for provider in ["conditional-client-scope", PROVIDER_BUTTON]:
        api("POST", r + "/authentication/flows/%s/executions/execution" % q(intern), {"provider": provider}, token=t)
    api("POST", path + "/execution", {"provider": "webauthn-authenticator-passwordless"}, token=t)

    execs = all_execs()
    by_name = lambda n: next(e for e in execs if e.get("displayName") == n and e.get("authenticationFlow"))
    start = next(i for i, e in enumerate(execs) if e.get("displayName") == intern and e.get("authenticationFlow"))
    by_provider = lambda pid: next(e for e in execs[start + 1:] if e.get("providerId") == pid)
    update(by_name(wrap), requirement="ALTERNATIVE")
    update(by_name(intern), requirement="CONDITIONAL")
    update(by_provider("conditional-client-scope"), requirement="REQUIRED")
    update(by_provider(PROVIDER_BUTTON), requirement="ALTERNATIVE")
    update(next(e for e in execs if e.get("providerId") == "webauthn-authenticator-passwordless"), requirement="ALTERNATIVE")

    cond = by_provider("conditional-client-scope")
    _, location = api("POST", r + "/authentication/executions/%s/config" % cond["id"],
                      {"alias": name + "-cond", "config": {"client_scope": "profile", "negate": "false"}}, token=t)
    config_id = (location or "").rstrip("/").split("/")[-1]
    if not config_id:
        raise RuntimeError("no Location for the condition config")

    execs = all_execs()
    order = [(e.get("level"), e.get("providerId") or e.get("displayName"), e["requirement"]) for e in execs]
    names = [o[1] for o in order]
    assert names.index(wrap) > next(i for i, e in enumerate(execs) if "forms" in e.get("displayName", "").lower()), order
    if os.environ.get("E2E_DEBUG"):
        print("  %s: %s" % (name, order))
    return by_provider(PROVIDER_BUTTON)["id"], config_id


def build_stepup_flow(t, name):
    """The SIT layout, built from scratch:
         <name>                         top level
         |- Cookie                      ALTERNATIVE
         `- bronze/silver (sub-flow)    ALTERNATIVE
            |- bronze (sub-flow)        REQUIRED
            |  |- password (sub-flow)   ALTERNATIVE > Username Password Form REQUIRED
            |  `- button                ALTERNATIVE
            `- silver (sub-flow)        CONDITIONAL
               |- client-scope condition (true, stands in for "requested ACR")
               `- OTP Form              REQUIRED
    Returns the button execution id."""
    r = "/admin/realms/" + REALM
    q = urllib.parse.quote
    api("POST", r + "/authentication/flows",
        {"alias": name, "providerId": "basic-flow", "topLevel": True, "builtIn": False, "description": ""}, token=t)

    def executions(flow_alias):
        execs, _ = api("GET", r + "/authentication/flows/%s/executions" % q(flow_alias), token=t)
        return execs

    def set_requirement(flow_alias, execution, requirement):
        rep = dict(execution)
        rep["requirement"] = requirement
        api("PUT", r + "/authentication/flows/%s/executions" % q(flow_alias), rep, token=t)

    def add_execution(flow_alias, provider, requirement, config=None):
        api("POST", r + "/authentication/flows/%s/executions/execution" % q(flow_alias), {"provider": provider}, token=t)
        ex = [e for e in executions(flow_alias) if e.get("level", 0) == 0 and e.get("providerId") == provider][-1]
        set_requirement(flow_alias, ex, requirement)
        if config:
            api("POST", r + "/authentication/executions/%s/config" % ex["id"],
                {"alias": "%s-%s" % (flow_alias, provider), "config": config}, token=t)
        return ex

    def add_subflow(parent_alias, alias, requirement):
        api("POST", r + "/authentication/flows/%s/executions/flow" % q(parent_alias),
            {"alias": alias, "type": "basic-flow", "provider": "registration-page-form", "description": ""}, token=t)
        ex = [e for e in executions(parent_alias) if e.get("level", 0) == 0 and e.get("displayName") == alias][-1]
        set_requirement(parent_alias, ex, requirement)
        return alias

    add_execution(name, "auth-cookie", "ALTERNATIVE")
    login = add_subflow(name, name + " bronze-silver", "ALTERNATIVE")
    bronze = add_subflow(login, name + " bronze", "REQUIRED")
    password = add_subflow(bronze, name + " password", "ALTERNATIVE")
    add_execution(password, "auth-username-password-form", "REQUIRED")
    button = add_execution(bronze, PROVIDER_BUTTON, "ALTERNATIVE")
    silver = add_subflow(login, name + " silver", "CONDITIONAL")
    add_execution(silver, "conditional-client-scope", "REQUIRED", {"client_scope": "profile", "negate": "false"})
    add_execution(silver, "auth-otp-form", "REQUIRED")
    if os.environ.get("E2E_DEBUG"):
        print("  %s: %s" % (name, [(e.get("level"), e.get("providerId") or e.get("displayName"), e["requirement"])
                                   for e in executions(name)]))
    return button["id"]


def set_condition(t, config_id, name, holds):
    api("PUT", "/admin/realms/%s/authentication/config/%s" % (REALM, config_id),
        {"id": config_id, "alias": name + "-cond",
         "config": {"client_scope": "profile", "negate": "false" if holds else "true"}}, token=t)


def bind_flow(t, name):
    api("PUT", "/admin/realms/" + REALM, {"browserFlow": name}, token=t)


# ── scenarios ───────────────────────────────────────────────────────────────

def open_login_and_select(b, exec_id):
    """GET /auth, click 'try another way', expect the execution to be offered, return the
    action URL of that option (what the theme button posts to)."""
    status, _, body, _ = b.request("GET", auth_url())
    if status != 200 or 'id="kc-form-login"' not in body:
        raise RuntimeError("login page expected, got HTTP %d" % status)
    action = form_action(body, "kc-select-try-another-way-form")
    status, _, body, _ = b.request("POST", action, data={"tryAnotherWay": "on"})
    if status != 200:
        raise RuntimeError("select-authenticator page expected, got HTTP %d" % status)
    if os.environ.get("E2E_DEBUG"):
        print("  select page offers: %s" % re.findall(r'name="authenticationExecution" value="([^"]+)"', body))
    return selection_form(body, exec_id)


def scenario_a(exec_id, p="A"):
    kinit()
    b = Browser()
    state = {}

    def offered():
        state["action"] = open_login_and_select(b, exec_id)
        return "listed in authenticationSelections"
    if not check(p + "1 execution offered on the login page", offered):
        return

    def redirect():
        status, headers, body, _ = b.request("POST", state["action"], data={"authenticationExecution": exec_id})
        if status != 303:
            raise RuntimeError("HTTP %d instead of 303 (body: %s)" % (status, body[:200]))
        loc = headers.get("location", "")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        if "/login-actions/authenticate" not in loc or "session_code" in q or "execution" in q:
            raise RuntimeError("unexpected Location " + loc)
        if q.get("client_id") != [CLIENT_ID] or "tab_id" not in q:
            raise RuntimeError("refresh URL lacks client_id/tab_id: " + loc)
        state["refresh"] = loc
        return "303 -> refresh URL without session_code/execution"
    if not check(p + "2 selection answers with a redirect to the refresh URL", redirect):
        return

    def challenge():
        status, headers, body, _ = b.request("GET", state["refresh"])
        if status != 401 or headers.get("www-authenticate", "").lower() != "negotiate":
            raise RuntimeError("HTTP %d / WWW-Authenticate: %s" % (status, headers.get("www-authenticate")))
        if "<FORM METHOD=\"POST\"" not in body:
            raise RuntimeError("401 without the fallback form")
        return "401 WWW-Authenticate: Negotiate (with fallback form)"
    if not check(p + "3 refresh GET challenges with Negotiate", challenge):
        return

    def negotiate():
        status, headers, body, _ = b.request("GET", state["refresh"], negotiate=True)
        if status != 302:
            raise RuntimeError("HTTP %d after the ticket, expected 302 to the client (body: %s)" % (status, re.sub(r"\s+", " ", body)[:300]))
        loc = headers.get("location", "")
        if not loc.startswith(REDIRECT_URI) or "code=" not in loc:
            raise RuntimeError("unexpected Location " + loc)
        state["code"] = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
        return "retry with ticket -> 302 with authorization code"
    if not check(p + "4 retry of the refresh GET with the ticket logs in", negotiate):
        return

    def token():
        tok, _ = api("POST", "/realms/%s/protocol/openid-connect/token" % REALM, form={
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI, "code": state["code"]})
        payload = tok["access_token"].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(__import__("base64").urlsafe_b64decode(payload))
        if claims.get("preferred_username") != "alice":
            raise RuntimeError("token for %r, expected alice" % claims.get("preferred_username"))
        return "preferred_username=alice"
    check(p + "5 authorization code yields a token for the Kerberos user", token)


def scenario_b(exec_id, p="B"):
    kdestroy()
    b = Browser()
    state = {}

    def select():
        action = open_login_and_select(b, exec_id)
        status, headers, _, _ = b.request("POST", action, data={"authenticationExecution": exec_id})
        if status != 303:
            raise RuntimeError("HTTP %d instead of 303" % status)
        state["refresh"] = headers["location"]
        return "303"
    if not check(p + "1 selection without a ticket also redirects", select):
        return

    def fallback():
        status, headers, body, _ = b.request("GET", state["refresh"], negotiate=True)
        if status != 401 or headers.get("www-authenticate", "").lower() != "negotiate":
            raise RuntimeError("HTTP %d / %s" % (status, headers.get("www-authenticate")))
        m = re.search(r'<FORM METHOD="POST" ACTION="([^"]+)"', body)
        if not m:
            raise RuntimeError("no fallback form in the 401 body")
        state["fallback"] = html.unescape(m.group(1))
        return "401 Negotiate with fallback form"
    if not check(p + "2 refresh GET without ticket returns the fallback form", fallback):
        return

    def password_form():
        status, _, body, _ = b.request("POST", state["fallback"], data={"continue": "CONTINUE"})
        if status != 200 or 'id="kc-form-login"' not in body:
            raise RuntimeError("HTTP %d, password form expected (body: %s)" % (status, re.sub(r"\s+", " ", body)[:300]))
        if "expired" in body.lower():
            raise RuntimeError("page expired instead of the password form")
        state["form"] = body
        return "password form rendered"
    if not check(p + "3 fallback POST lands on the password form", password_form):
        return

    def offered_again():
        action = form_action(state["form"], "kc-select-try-another-way-form")
        status, _, body, _ = b.request("POST", action, data={"tryAnotherWay": "on"})
        if status != 200:
            raise RuntimeError("HTTP %d" % status)
        selection_form(body, exec_id)
        return "execution offered again after the fallback"
    check(p + "4 the Kerberos option is offered again after the fallback", offered_again)


def scenario_f_off(t, exec_id, config_id):
    """Condition false: the button is not offered and a forged selection is not accepted."""
    set_condition(t, config_id, FLOW_NESTED, holds=False)
    kinit()
    b = Browser()
    state = {}

    def hidden():
        status, _, body, _ = b.request("GET", auth_url())
        action = form_action(body, "kc-select-try-another-way-form")
        status, _, body, _ = b.request("POST", action, data={"tryAnotherWay": "on"})
        if status != 200:
            raise RuntimeError("HTTP %d" % status)
        if exec_id in body:
            raise RuntimeError("button offered although the condition is false")
        state["page"] = body
        return "not offered"
    if not check("F6 condition false: button not offered", hidden):
        return

    def forged():
        # every option of the select page posts to the same action URL; use the first one
        m = re.search(r'<form[^>]*action="([^"]+)"[^>]*>(?:(?!</form>).)*name="authenticationExecution"', state["page"], re.S)
        if not m:
            raise RuntimeError("no selection form on the page")
        action = html.unescape(m.group(1))
        status, headers, body, _ = b.request("POST", action, data={"authenticationExecution": exec_id})
        if status in (303, 401) or headers.get("www-authenticate"):
            raise RuntimeError("forged selection accepted: HTTP %d %s" % (status, headers.get("location", "")))
        status, headers, _, _ = b.request("GET", auth_url(), negotiate=True)
        if status == 302 and "code=" in headers.get("location", ""):
            raise RuntimeError("logged in via Kerberos although the condition is false")
        return "HTTP %d, no Negotiate, no login" % status
    check("F7 condition false: forged selection not accepted", forged)
    set_condition(t, config_id, FLOW_NESTED, holds=True)


def scenario_g(exec_id):
    """Step-up layout: the click skips the password alternative only; the silver sub-flow
    (OTP) is a later step of the sequence and must run after Kerberos."""
    kinit()
    b = Browser()

    def otp_follows():
        action = open_login_and_select(b, exec_id)
        status, headers, body, _ = b.request("POST", action, data={"authenticationExecution": exec_id})
        if status != 303:
            raise RuntimeError("HTTP %d instead of 303" % status)
        status, headers, body, _ = b.request("GET", headers["location"], negotiate=True)
        loc = headers.get("location", "")
        if status == 302 and loc.startswith(REDIRECT_URI):
            raise RuntimeError("logged in without the OTP step")
        if status == 302 and "/login-actions/" in loc:
            # no OTP configured yet: Keycloak redirects to the OTP set-up
            status, headers, body, _ = b.request("GET", loc)
        if status != 200 or not re.search(r'otp|totp', body, re.I):
            raise RuntimeError("HTTP %d, OTP step expected (body: %s)" % (status, re.sub(r"\s+", " ", body)[:200]))
        return "ticket accepted, OTP step follows (no authorization code)"
    check("G1 step-up: after Kerberos the silver OTP step follows", otp_follows)


def scenario_c(exec_id):
    kinit()
    b = Browser()

    def expired():
        action = open_login_and_select(b, exec_id)
        data = {"authenticationExecution": exec_id}
        status, headers, _, _ = b.request("POST", action, data=data)
        if status != 401 or headers.get("www-authenticate", "").lower() != "negotiate":
            raise RuntimeError("built-in authenticator did not challenge (HTTP %d)" % status)
        # the browser's retry: same POST, same (now consumed) session_code, plus the ticket
        status, _, body, _ = b.request("POST", action, data=data, negotiate=True)
        if "expired" not in body.lower():
            raise RuntimeError("HTTP %d without 'page expired' - did Keycloak fix the retry upstream? (body: %s)"
                               % (status, re.sub(r"\s+", " ", body)[:300]))
        return "built-in auth-spnego via selection -> page expired (the bug this provider works around)"
    check("C1 built-in Kerberos via selection still ends in 'page expired'", expired)


def login_via_button(b, exec_id):
    """Button click through to the response after the ticket: (status, headers, body)."""
    action = open_login_and_select(b, exec_id)
    status, headers, _, _ = b.request("POST", action, data={"authenticationExecution": exec_id})
    if status != 303:
        raise RuntimeError("HTTP %d instead of 303" % status)
    refresh = headers["location"]
    status, _, _, _ = b.request("GET", refresh)
    if status != 401:
        raise RuntimeError("HTTP %d instead of 401 Negotiate" % status)
    status, headers, body, _ = b.request("GET", refresh, negotiate=True)
    return status, headers, body


def scenario_d(exec_id):
    if not pkinit_available():
        print("SKIP  D PKINIT certificates not found in %s" % PKINIT_DIR)
        return

    def pkinit_login():
        kinit_pkinit()
        b = Browser()
        status, headers, body = login_via_button(b, exec_id)
        if status != 302:
            raise RuntimeError("HTTP %d after the PKINIT ticket (body: %s)" % (status, re.sub(r"\s+", " ", body)[:300]))
        loc = headers.get("location", "")
        if not loc.startswith(REDIRECT_URI) or "code=" not in loc:
            raise RuntimeError("expected the client redirect (OTP skipped), got " + loc)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
        tok, _ = api("POST", "/realms/%s/protocol/openid-connect/token" % REALM, form={
            "grant_type": "authorization_code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "code": code})
        payload = tok["access_token"].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(__import__("base64").urlsafe_b64decode(payload))
        if claims.get("acr") != "silver":
            raise RuntimeError("acr claim %r, expected silver" % claims.get("acr"))
        return "PKINIT ticket -> level 2, OTP skipped, acr=silver"
    check("D1 PKINIT ticket logs in at level 2 without OTP", pkinit_login)

    def password_login():
        kinit()
        b = Browser()
        status, headers, body = login_via_button(b, exec_id)
        loc = headers.get("location", "")
        if status != 302 or "required-action" not in loc or "CONFIGURE_TOTP" not in loc:
            raise RuntimeError("expected the OTP step (CONFIGURE_TOTP required action), got HTTP %d %s (body: %s)"
                               % (status, loc, re.sub(r"\s+", " ", body)[:200]))
        return "password ticket -> level 1, OTP step entered"
    check("D2 password ticket logs in at level 1 and runs into OTP", password_login)
    kdestroy()


def main():
    t = admin_token()
    execs = setup_realm(t)
    print("realm %s configured: %s" % (REALM, execs))

    bind_flow(t, FLOW_BUTTON)
    scenario_a(execs[FLOW_BUTTON])
    scenario_b(execs[FLOW_BUTTON])

    nested_id, nested_cfg = execs[FLOW_NESTED]
    bind_flow(t, FLOW_NESTED)
    scenario_a(nested_id, p="F")
    scenario_b(nested_id, p="FB")
    scenario_f_off(t, nested_id, nested_cfg)

    bind_flow(t, FLOW_STEPUP)
    scenario_g(execs[FLOW_STEPUP])

    bind_flow(t, FLOW_BUILTIN)
    scenario_c(execs[FLOW_BUILTIN])

    bind_flow(t, FLOW_LEVEL)
    scenario_d(execs[FLOW_LEVEL])

    kdestroy()
    print()
    print("%d check(s) failed" % len(failures) if failures else "all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
