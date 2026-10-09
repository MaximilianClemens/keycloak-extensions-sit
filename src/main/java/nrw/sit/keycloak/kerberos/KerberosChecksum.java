package nrw.sit.keycloak.kerberos;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Keyed checksums for the AES Kerberos encryption types (RFC 3961 section 5.4, RFC 3962):
 * {@code hmac-sha1-96-aes128} (15) and {@code hmac-sha1-96-aes256} (16). These are the
 * signature types Windows and MIT use for the PAC server signature.
 *
 * {@code checksum = truncate96(HMAC-SHA1(Kc, data))} with
 * {@code Kc = DK(key, usage || 0x99)}, where DK is the RFC 3961 key derivation with the AES
 * cipher in CBC mode over the 128-bit n-fold of the constant (RFC 3962 section 4).
 */
public final class KerberosChecksum {

    public static final int HMAC_SHA1_96_AES128 = 15;
    public static final int HMAC_SHA1_96_AES256 = 16;

    public static final int ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 17;
    public static final int ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18;

    /** Key usage for the PAC signatures (MS-PAC 2.8.1: KERB_NON_KERB_CKSUM_SALT). */
    public static final int KEY_USAGE_PAC_SIGNATURE = 17;

    private KerberosChecksum() {
    }

    /** The checksum type that goes with an AES encryption type, or -1 for anything else. */
    public static int checksumTypeFor(int enctype) {
        switch (enctype) {
            case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
                return HMAC_SHA1_96_AES128;
            case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
                return HMAC_SHA1_96_AES256;
            default:
                return -1;
        }
    }

    /** Computes the 96-bit HMAC-SHA1 checksum of {@code data} under {@code key} for {@code usage}. */
    public static byte[] compute(int checksumType, byte[] key, int usage, byte[] data) {
        int keyLength;
        switch (checksumType) {
            case HMAC_SHA1_96_AES128:
                keyLength = 16;
                break;
            case HMAC_SHA1_96_AES256:
                keyLength = 32;
                break;
            default:
                throw new IllegalArgumentException("unsupported checksum type " + checksumType);
        }
        if (key.length != keyLength) {
            throw new IllegalArgumentException("key length " + key.length + " does not match checksum type " + checksumType);
        }
        byte[] constant = {(byte) (usage >>> 24), (byte) (usage >>> 16), (byte) (usage >>> 8), (byte) usage, (byte) 0x99};
        byte[] kc = deriveKey(key, constant);
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(kc, "HmacSHA1"));
            byte[] full = mac.doFinal(data);
            return Arrays.copyOf(full, 12);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 not available", e);
        } finally {
            Arrays.fill(kc, (byte) 0);
        }
    }

    /** Constant-time comparison of an expected checksum with a computed one. */
    public static boolean verify(int checksumType, byte[] key, int usage, byte[] data, byte[] expected) {
        byte[] actual = compute(checksumType, key, usage, data);
        return MessageDigest.isEqual(actual, expected);
    }

    /**
     * RFC 3961 DK(key, constant) for AES: DR = E(key, n-fold128(constant)) chained until
     * enough bits for the key, then random-to-key is the identity (RFC 3962).
     */
    static byte[] deriveKey(byte[] key, byte[] constant) {
        byte[] block = constant.length == 16 ? constant.clone() : nfold(constant, 16);
        byte[] out = new byte[key.length];
        int filled = 0;
        try {
            Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            while (filled < out.length) {
                block = aes.doFinal(block); // one block: CBC with zero IV == ECB
                int n = Math.min(block.length, out.length - filled);
                System.arraycopy(block, 0, out, filled, n);
                filled += n;
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES not available", e);
        }
        return out;
    }

    /**
     * RFC 3961 section 5.1 n-fold, ported from MIT krb5 {@code krb5int_nfold}.
     *
     * @param in       input bytes
     * @param outBytes output size in bytes
     */
    static byte[] nfold(byte[] in, int outBytes) {
        int inBytes = in.length;
        int a = outBytes;
        int b = inBytes;
        while (b != 0) {
            int c = b;
            b = a % b;
            a = c;
        }
        int lcm = outBytes * inBytes / a;

        byte[] out = new byte[outBytes];
        int carry = 0;
        for (int i = lcm - 1; i >= 0; i--) {
            int msbit = (((inBytes << 3) - 1)
                    + (((inBytes << 3) + 13) * (i / inBytes))
                    + ((inBytes - (i % inBytes)) << 3))
                    % (inBytes << 3);
            int hi = in[((inBytes - 1) - (msbit >> 3)) % inBytes] & 0xFF;
            int lo = in[(inBytes - (msbit >> 3)) % inBytes] & 0xFF;
            carry += (((hi << 8) | lo) >> ((msbit & 7) + 1)) & 0xFF;
            carry += out[i % outBytes] & 0xFF;
            out[i % outBytes] = (byte) carry;
            carry >>= 8;
        }
        if (carry != 0) {
            for (int i = outBytes - 1; i >= 0; i--) {
                carry += out[i] & 0xFF;
                out[i] = (byte) carry;
                carry >>= 8;
            }
        }
        return out;
    }
}
