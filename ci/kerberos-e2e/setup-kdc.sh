#!/usr/bin/env bash
# =====================================================================
# setup-kdc.sh – a throwaway MIT Kerberos KDC for the SPNEGO end-to-end test
#
#   setup-kdc.sh <work-dir>
#
# Creates realm EXAMPLE.TEST on localhost, user principal "alice" (password
# "alicepw"), service principal HTTP/keycloak.example.test and its keytab
# (<work-dir>/keycloak.keytab), writes /etc/krb5.conf and maps
# keycloak.example.test to 127.0.0.1 in /etc/hosts. Needs root (or sudo) and
# the packages krb5-kdc krb5-admin-server krb5-user.
#
# If krb5-pkinit is installed, PKINIT is set up as well: a throwaway CA, a KDC
# certificate and a client certificate for alice (<work-dir>/pkinit/), and the
# KDC adds the authentication indicator "pkinit" to tickets obtained that way
# (pkinit_indicator). That is the MIT equivalent of a smart-card logon.
#
# Meant for CI runners and disposable VMs. Do not run it on a machine that
# already has a Kerberos configuration you care about.
# =====================================================================
set -euo pipefail

WORK_DIR="${1:?work dir}"
REALM="EXAMPLE.TEST"
KC_HOST="keycloak.example.test"
mkdir -p "$WORK_DIR"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

for bin in kdb5_util kadmin.local krb5kdc kinit; do
  command -v "$bin" > /dev/null || { echo "missing $bin (apt-get install krb5-kdc krb5-admin-server krb5-user)"; exit 1; }
done

# KDC side under /etc/krb5kdc: with systemd the KDC runs with ProtectHome and cannot read
# files below /home, which is where a CI runner's work directory lives. Client side (CA cert,
# alice's certificate and key) in the work dir, because /etc/krb5kdc is root-only.
KDC_PKINIT_DIR="/etc/krb5kdc/pkinit"
PKINIT_DIR="${PKINIT_DIR:-$WORK_DIR/pkinit}"
PKINIT=false
if ls /usr/lib/*/krb5/plugins/preauth/pkinit.so > /dev/null 2>&1; then
  PKINIT=true
fi

$SUDO tee /etc/krb5.conf > /dev/null <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    $REALM = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1
        pkinit_anchors = FILE:$PKINIT_DIR/cacert.pem
    }

[domain_realm]
    .example.test = $REALM
    example.test = $REALM
EOF

$SUDO mkdir -p /etc/krb5kdc /var/lib/krb5kdc
$SUDO tee /etc/krb5kdc/kdc.conf > /dev/null <<EOF
[kdcdefaults]
    kdc_listen = 127.0.0.1:88
    kdc_tcp_listen = 127.0.0.1:88

[realms]
    $REALM = {
        database_name = /var/lib/krb5kdc/principal
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        pkinit_identity = FILE:$KDC_PKINIT_DIR/kdc.pem,$KDC_PKINIT_DIR/kdckey.pem
        pkinit_anchors = FILE:$KDC_PKINIT_DIR/cacert.pem
        pkinit_indicator = pkinit
    }
EOF

# ── PKINIT certificates (MIT docs, "Creating certificates for PKINIT") ──
if $PKINIT; then
  $SUDO mkdir -p "$KDC_PKINIT_DIR"
  mkdir -p "$PKINIT_DIR"
  TMP_PKINIT="$(mktemp -d)"
  cat > "$TMP_PKINIT/openssl.cnf" <<EOF
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
CN = placeholder

[kdc_cert]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
issuerAltName = issuer:copy
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

[kdc_princ_name]
realm = EXP:0,GeneralString:$REALM
principal_name = EXP:1,SEQUENCE:kdc_principal_seq

[kdc_principal_seq]
name_type = EXP:0,INTEGER:2
name_string = EXP:1,SEQUENCE:kdc_principals

[kdc_principals]
princ1 = GeneralString:krbtgt
princ2 = GeneralString:$REALM

[client_cert]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
issuerAltName = issuer:copy
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

[princ_name]
realm = EXP:0,GeneralString:$REALM
principal_name = EXP:1,SEQUENCE:principal_seq

[principal_seq]
name_type = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:principals

[principals]
princ1 = GeneralString:alice
EOF
  (
    cd "$TMP_PKINIT"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout cakey.pem -out cacert.pem -days 30 \
      -config openssl.cnf -subj "/CN=E2E Test CA" > /dev/null 2>&1
    openssl genrsa -out kdckey.pem 2048 > /dev/null 2>&1
    openssl req -new -key kdckey.pem -out kdc.req -config openssl.cnf -subj "/CN=kdc" > /dev/null 2>&1
    openssl x509 -req -in kdc.req -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out kdc.pem -days 30 \
      -extfile openssl.cnf -extensions kdc_cert > /dev/null 2>&1
    openssl genrsa -out alicekey.pem 2048 > /dev/null 2>&1
    openssl req -new -key alicekey.pem -out alice.req -config openssl.cnf -subj "/CN=alice" > /dev/null 2>&1
    openssl x509 -req -in alice.req -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out alice.pem -days 30 \
      -extfile openssl.cnf -extensions client_cert > /dev/null 2>&1
  )
  $SUDO cp "$TMP_PKINIT"/cacert.pem "$TMP_PKINIT"/kdc.pem "$TMP_PKINIT"/kdckey.pem "$KDC_PKINIT_DIR/"
  $SUDO chmod 644 "$KDC_PKINIT_DIR"/cacert.pem "$KDC_PKINIT_DIR"/kdc.pem
  $SUDO chmod 600 "$KDC_PKINIT_DIR"/kdckey.pem
  cp "$TMP_PKINIT"/cacert.pem "$TMP_PKINIT"/alice.pem "$TMP_PKINIT"/alicekey.pem "$PKINIT_DIR/"
  chmod 644 "$PKINIT_DIR"/*.pem
  rm -rf "$TMP_PKINIT"
fi
echo "*/admin@$REALM *" | $SUDO tee /etc/krb5kdc/kadm5.acl > /dev/null

if [ ! -f /var/lib/krb5kdc/principal ]; then
  $SUDO kdb5_util create -s -r "$REALM" -P "master-key-for-tests" > /dev/null
fi

$SUDO kadmin.local -q "addprinc -pw alicepw +requires_preauth alice" > /dev/null
$SUDO kadmin.local -q "addprinc -randkey HTTP/$KC_HOST" > /dev/null
$SUDO rm -f "$WORK_DIR/keycloak.keytab"
$SUDO kadmin.local -q "ktadd -k $WORK_DIR/keycloak.keytab HTTP/$KC_HOST" > /dev/null
$SUDO chmod 644 "$WORK_DIR/keycloak.keytab"
$SUDO chown "$(id -u)" "$WORK_DIR/keycloak.keytab"

if ! grep -q "$KC_HOST" /etc/hosts; then
  echo "127.0.0.1 $KC_HOST" | $SUDO tee -a /etc/hosts > /dev/null
fi

# Start the KDC (systemd on a runner, plain process elsewhere)
if command -v systemctl > /dev/null && systemctl list-unit-files krb5-kdc.service > /dev/null 2>&1 \
   && [ -d /run/systemd/system ]; then
  $SUDO systemctl restart krb5-kdc
else
  $SUDO pkill krb5kdc 2>/dev/null || true
  $SUDO krb5kdc
fi

# Sanity: the KDC answers and the keytab is usable
echo alicepw | kinit alice > /dev/null
kdestroy
klist -k "$WORK_DIR/keycloak.keytab" | grep -q "HTTP/$KC_HOST@$REALM"
if $PKINIT; then
  if ! kinit -X "X509_user_identity=FILE:$PKINIT_DIR/alice.pem,$PKINIT_DIR/alicekey.pem" alice < /dev/null; then
    echo "[kdc] PKINIT kinit failed; KDC trace:"
    KRB5_TRACE=/dev/stderr kinit -X "X509_user_identity=FILE:$PKINIT_DIR/alice.pem,$PKINIT_DIR/alicekey.pem" alice < /dev/null 2>&1 | tail -n 20 || true
    exit 1
  fi
  kdestroy
  echo "[kdc] PKINIT works (certificates in $PKINIT_DIR)"
fi
echo "[kdc] realm $REALM ready, keytab $WORK_DIR/keycloak.keytab"
