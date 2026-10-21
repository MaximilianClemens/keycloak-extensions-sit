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
    }
EOF
echo "*/admin@$REALM *" | $SUDO tee /etc/krb5kdc/kadm5.acl > /dev/null

if [ ! -f /var/lib/krb5kdc/principal ]; then
  $SUDO kdb5_util create -s -r "$REALM" -P "master-key-for-tests" > /dev/null
fi

$SUDO kadmin.local -q "addprinc -pw alicepw alice" > /dev/null
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
echo "[kdc] realm $REALM ready, keytab $WORK_DIR/keycloak.keytab"
