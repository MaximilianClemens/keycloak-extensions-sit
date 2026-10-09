package nrw.sit.keycloak.kerberos;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The fixture under src/test/resources/pac is a Windows-style PAC built and signed by
 * impacket (see ci/kerberos-e2e/gen_pac_fixture.py), i.e. by an implementation that is not
 * ours: KERB_VALIDATION_INFO with domain groups, extra SIDs from a second domain, resource
 * groups and USER_SMARTCARD_REQUIRED, plus client info and both signatures.
 */
class PacTest {

    private static byte[] raw;
    private static Properties expected;
    private static byte[] key;

    @BeforeAll
    static void loadFixture() throws IOException {
        try (InputStream in = PacTest.class.getResourceAsStream("/pac/pac.bin")) {
            raw = in.readAllBytes();
        }
        expected = new Properties();
        try (InputStream in = PacTest.class.getResourceAsStream("/pac/pac.properties")) {
            expected.load(in);
        }
        key = HexFormat.of().parseHex(expected.getProperty("aes256.key"));
    }

    @Test
    void parsesTheBufferTable() {
        Pac pac = Pac.parse(raw);

        assertTrue(pac.has(Pac.LOGON_INFO));
        assertTrue(pac.has(Pac.CLIENT_INFO));
        assertTrue(pac.has(Pac.SERVER_CHECKSUM));
        assertTrue(pac.has(Pac.KDC_CHECKSUM));
        assertFalse(pac.has(Pac.UPN_DNS_INFO));
        assertEquals(KerberosChecksum.HMAC_SHA1_96_AES256, pac.serverSignatureType());
    }

    @Test
    void verifiesTheServerSignatureWithTheServiceKey() {
        Pac pac = Pac.parse(raw);

        assertTrue(pac.verifyServerSignature(key));

        byte[] wrong = key.clone();
        wrong[5] ^= 0x40;
        assertFalse(pac.verifyServerSignature(wrong));
        assertFalse(pac.verifyServerSignature(new byte[16]), "key length of the other AES type");
    }

    @Test
    void detectsATamperedPac() {
        byte[] tampered = raw.clone();
        // flip a byte inside the logon info (after the 8 byte header and 4 buffer entries)
        int offset = 8 + 4 * 16 + 40;
        tampered[offset] ^= 0x01;

        assertFalse(Pac.parse(tampered).verifyServerSignature(key));
    }

    @Test
    void decodesTheLogonInformation() {
        Pac.LogonInfo info = Pac.parse(raw).logonInfo();

        assertEquals(expected.getProperty("effectiveName"), info.effectiveName);
        assertEquals(expected.getProperty("logonDomainName"), info.logonDomainName);
        assertEquals(expected.getProperty("logonDomainSid"), info.logonDomainSid);
        assertEquals(Integer.parseInt(expected.getProperty("userId")), info.userId);
        assertEquals(Integer.parseInt(expected.getProperty("primaryGroupId")), info.primaryGroupId);
        assertEquals(Boolean.parseBoolean(expected.getProperty("smartcardRequired")), info.smartcardRequired());
        assertEquals(Arrays.asList(expected.getProperty("groupSids").split(",")), info.groupSids);
    }

    @Test
    void groupSidsCoverDomainGroupsExtraSidsAndResourceGroups() {
        List<String> sids = Pac.parse(raw).logonInfo().groupSids;

        assertTrue(sids.contains("S-1-5-21-1111111111-2222222222-3333333333-513"), "domain group via RID");
        assertTrue(sids.contains("S-1-5-21-3999999999-2888888888-1777777777-1234"), "extra SID from another domain (AMA case)");
        assertTrue(sids.contains("S-1-18-1"), "well-known extra SID");
        assertTrue(sids.contains("S-1-5-21-1555555555-2666666666-3777777777-3001"), "resource group");
    }

    @Test
    void logonInfoIsNullWithoutTheBuffer() {
        // a PAC with only a client info buffer
        byte[] client = Pac.parse(raw).buffer(Pac.CLIENT_INFO);
        byte[] minimal = new byte[8 + 16 + client.length];
        java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(minimal).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        bb.putInt(1).putInt(0).putInt(Pac.CLIENT_INFO).putInt(client.length).putLong(24);
        System.arraycopy(client, 0, minimal, 24, client.length);

        Pac pac = Pac.parse(minimal);
        assertNull(pac.logonInfo());
        assertEquals(-1, pac.serverSignatureType());
        assertFalse(pac.verifyServerSignature(key));
    }

    @Test
    void rejectsGarbage() {
        assertThrows(IllegalArgumentException.class, () -> Pac.parse(new byte[3]));
        byte[] bogus = raw.clone();
        bogus[0] = 100; // 100 buffers that cannot fit
        assertThrows(IllegalArgumentException.class, () -> Pac.parse(bogus));
    }
}
