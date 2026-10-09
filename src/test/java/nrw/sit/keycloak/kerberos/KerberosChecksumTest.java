package nrw.sit.keycloak.kerberos;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KerberosChecksumTest {

    private static final HexFormat HEX = HexFormat.of();

    private static String nfold(String s, int bits) {
        return HEX.formatHex(KerberosChecksum.nfold(s.getBytes(StandardCharsets.US_ASCII), bits / 8));
    }

    @Test
    void nfoldMatchesTheRfc3961TestVectors() {
        assertEquals("be072631276b1955", nfold("012345", 64));
        assertEquals("78a07b6caf85fa", nfold("password", 56));
        assertEquals("bb6ed30870b7f0e0", nfold("Rough Consensus, and Running Code", 64));
        assertEquals("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e", nfold("password", 168));
        assertEquals("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b", nfold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192));
        assertEquals("518a54a215a8452a518a54a215a8452a518a54a215", nfold("Q", 168));
        assertEquals("fb25d531ae8974499f52fd92ea9857c4ba24cf297e", nfold("ba", 168));
        assertEquals("6b65726265726f73", nfold("kerberos", 64));
        assertEquals("6b65726265726f737b9b5b2b93132b93", nfold("kerberos", 128));
        assertEquals("6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4", nfold("kerberos", 256));
    }

    @Test
    void checksumTypeFollowsTheEnctype() {
        assertEquals(KerberosChecksum.HMAC_SHA1_96_AES128, KerberosChecksum.checksumTypeFor(17));
        assertEquals(KerberosChecksum.HMAC_SHA1_96_AES256, KerberosChecksum.checksumTypeFor(18));
        assertEquals(-1, KerberosChecksum.checksumTypeFor(23));
    }

    @Test
    void checksumIs96BitsAndKeyed() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        byte[] data = "hello".getBytes(StandardCharsets.US_ASCII);
        byte[] sum = KerberosChecksum.compute(KerberosChecksum.HMAC_SHA1_96_AES256, key, 17, data);

        assertEquals(12, sum.length);
        assertTrue(KerberosChecksum.verify(KerberosChecksum.HMAC_SHA1_96_AES256, key, 17, data, sum));
        assertFalse(KerberosChecksum.verify(KerberosChecksum.HMAC_SHA1_96_AES256, key, 18, data, sum), "usage is part of the key");
        key[0] ^= 1;
        assertFalse(KerberosChecksum.verify(KerberosChecksum.HMAC_SHA1_96_AES256, key, 17, data, sum));
    }

    @Test
    void rejectsKeyLengthMismatchAndUnknownTypes() {
        assertThrows(IllegalArgumentException.class,
                () -> KerberosChecksum.compute(KerberosChecksum.HMAC_SHA1_96_AES128, new byte[32], 17, new byte[1]));
        assertThrows(IllegalArgumentException.class,
                () -> KerberosChecksum.compute(99, new byte[16], 17, new byte[1]));
    }
}
