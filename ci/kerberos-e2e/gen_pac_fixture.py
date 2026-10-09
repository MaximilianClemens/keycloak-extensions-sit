#!/usr/bin/env python3
"""
Generates the PAC test fixture in src/test/resources/pac/ with impacket, an implementation
independent of ours: a Windows-style PAC with KERB_VALIDATION_INFO (domain groups, extra SIDs
from another domain, resource groups, USER_SMARTCARD_REQUIRED), client info and UPN/DNS info,
signed with a fixed AES-256 key as a KDC would (key usage 17).

    pip install impacket
    python3 ci/kerberos-e2e/gen_pac_fixture.py

Files: pac.bin (the PAC), pac.properties (key and expected values the unit test asserts).
"""
import os
import sys

from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import (
    GROUP_MEMBERSHIP, SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY,
    USER_DONT_EXPIRE_PASSWORD, USER_NORMAL_ACCOUNT,
)
from impacket.krb5 import pac
from impacket.krb5.constants import ChecksumTypes, KERB_NON_KERB_CKSUM_SALT
from impacket.krb5.pac import (
    KERB_SID_AND_ATTRIBUTES, KERB_VALIDATION_INFO, PAC_CLIENT_INFO, PAC_CLIENT_INFO_TYPE,
    PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA,
    VALIDATION_INFO,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "test", "resources", "pac")
AES_KEY = "7f3b9a1c5e2d4f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
DOMAIN = "EXAMPLE"
DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
USER = "alice"
USER_RID = 1105
GROUP_RIDS = [513, 1120, 1121]
EXTRA_SIDS = ["S-1-5-21-3999999999-2888888888-1777777777-1234", "S-1-18-1"]
RESOURCE_DOMAIN_SID = "S-1-5-21-1555555555-2666666666-3777777777"
RESOURCE_RIDS = [3001]
USER_SMARTCARD_REQUIRED = 0x00001000
LOGON_EXTRA_SIDS = 0x20
LOGON_RESOURCE_GROUPS = 0x200


def validation_info():
    k = KERB_VALIDATION_INFO()
    for f in ("LogonTime", "PasswordLastSet"):
        k[f]["dwLowDateTime"] = 0x9E1A1F00
        k[f]["dwHighDateTime"] = 0x01DC1234
    for f in ("LogoffTime", "KickOffTime", "PasswordMustChange"):
        k[f]["dwLowDateTime"] = 0xFFFFFFFF
        k[f]["dwHighDateTime"] = 0x7FFFFFFF
    k["PasswordCanChange"]["dwLowDateTime"] = 0
    k["PasswordCanChange"]["dwHighDateTime"] = 0
    k["EffectiveName"] = USER
    k["FullName"] = "Alice Example"
    k["LogonScript"] = ""
    k["ProfilePath"] = ""
    k["HomeDirectory"] = ""
    k["HomeDirectoryDrive"] = ""
    k["LogonCount"] = 42
    k["BadPasswordCount"] = 0
    k["UserId"] = USER_RID
    k["PrimaryGroupId"] = 513
    k["GroupCount"] = len(GROUP_RIDS)
    for rid in GROUP_RIDS:
        g = GROUP_MEMBERSHIP()
        gid = NDRULONG()
        gid["Data"] = rid
        g["RelativeId"] = gid
        g["Attributes"] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
        k["GroupIds"].append(g)
    k["UserFlags"] = LOGON_EXTRA_SIDS | LOGON_RESOURCE_GROUPS
    k["UserSessionKey"] = b"\x00" * 16
    k["LogonServer"] = "DC01"
    k["LogonDomainName"] = DOMAIN
    k["LogonDomainId"].fromCanonical(DOMAIN_SID)
    k["LMKey"] = b"\x00" * 8
    k["UserAccountControl"] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD | USER_SMARTCARD_REQUIRED
    k["SubAuthStatus"] = 0
    for f in ("LastSuccessfulILogon", "LastFailedILogon"):
        k[f]["dwLowDateTime"] = 0
        k[f]["dwHighDateTime"] = 0
    k["FailedILogonCount"] = 0
    k["Reserved3"] = 0
    k["SidCount"] = len(EXTRA_SIDS)
    for sid in EXTRA_SIDS:
        s = KERB_SID_AND_ATTRIBUTES()
        s["Sid"].fromCanonical(sid)
        s["Attributes"] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
        k["ExtraSids"].append(s)
    k["ResourceGroupDomainSid"].fromCanonical(RESOURCE_DOMAIN_SID)
    k["ResourceGroupCount"] = len(RESOURCE_RIDS)
    for rid in RESOURCE_RIDS:
        g = GROUP_MEMBERSHIP()
        gid = NDRULONG()
        gid["Data"] = rid
        g["RelativeId"] = gid
        g["Attributes"] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
        k["ResourceGroupIds"].append(g)
    v = VALIDATION_INFO()
    v["Data"] = k
    return v


def main():
    infos = {}
    v = validation_info()
    infos[PAC_LOGON_INFO] = v.getData() + v.getDataReferents()

    for t in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
        sig = PAC_SIGNATURE_DATA()
        sig["SignatureType"] = ChecksumTypes.hmac_sha1_96_aes256.value
        sig["Signature"] = b"\x00" * 12
        infos[t] = sig.getData()

    ci = PAC_CLIENT_INFO()
    ci["Name"] = USER.encode("utf-16le")
    ci["NameLength"] = len(ci["Name"])
    infos[PAC_CLIENT_INFO_TYPE] = ci.getData()

    order = [PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM]
    pac_type = pac.sign_pac(infos, aes_key=AES_KEY, buffer_order=order, checksum_salt=KERB_NON_KERB_CKSUM_SALT)
    blob = pac_type.getData()

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "pac.bin"), "wb") as fh:
        fh.write(blob)
    expected_groups = [DOMAIN_SID + "-" + str(r) for r in GROUP_RIDS] + EXTRA_SIDS \
        + [RESOURCE_DOMAIN_SID + "-" + str(r) for r in RESOURCE_RIDS]
    with open(os.path.join(OUT, "pac.properties"), "w") as fh:
        fh.write("# generated by ci/kerberos-e2e/gen_pac_fixture.py (impacket)\n")
        fh.write("aes256.key=%s\n" % AES_KEY)
        fh.write("effectiveName=%s\n" % USER)
        fh.write("logonDomainName=%s\n" % DOMAIN)
        fh.write("logonDomainSid=%s\n" % DOMAIN_SID)
        fh.write("userId=%d\n" % USER_RID)
        fh.write("primaryGroupId=513\n")
        fh.write("smartcardRequired=true\n")
        fh.write("groupSids=%s\n" % ",".join(expected_groups))
    print("wrote %d bytes to %s" % (len(blob), OUT))


if __name__ == "__main__":
    sys.exit(main())
