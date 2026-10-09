package nrw.sit.keycloak.kerberos;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KerberosAuthzDataTest {

    // ── tiny DER encoder for building test input ─────────────────────────────

    public static byte[] tlv(int tag, byte[]... parts) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            body.writeBytes(p);
        }
        byte[] value = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 0x80) {
            out.write(value.length);
        } else if (value.length < 0x100) {
            out.write(0x81);
            out.write(value.length);
        } else {
            out.write(0x82);
            out.write(value.length >> 8);
            out.write(value.length & 0xFF);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }

    public static byte[] integer(int v) {
        return tlv(0x02, new byte[]{(byte) v});
    }

    public static byte[] octets(byte[] v) {
        return tlv(0x04, v);
    }

    public static byte[] utf8(String s) {
        return tlv(0x0C, s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] ctx(int n, byte[] inner) {
        return tlv(0xA0 | n, inner);
    }

    public static byte[] seq(byte[]... parts) {
        return tlv(0x30, parts);
    }

    /** AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type [0] Int32, ad-data [1] OCTET STRING } */
    public static byte[] authorizationData(byte[]... elements) {
        return seq(elements);
    }

    public static byte[] element(int type, byte[] data) {
        return seq(ctx(0, integer(type)), ctx(1, octets(data)));
    }

    public static byte[] indicators(String... names) {
        byte[][] parts = new byte[names.length][];
        for (int i = 0; i < names.length; i++) {
            parts[i] = utf8(names[i]);
        }
        return seq(parts);
    }

    // ── tests ────────────────────────────────────────────────────────────────

    @Test
    void parsesAuthorizationDataElements() {
        byte[] der = authorizationData(element(97, new byte[]{1, 2}), element(128, new byte[]{3}));

        List<KerberosAuthzData.Entry> entries = KerberosAuthzData.parseAuthorizationData(der);

        assertEquals(2, entries.size());
        assertEquals(97, entries.get(0).type);
        assertArrayEquals(new byte[]{1, 2}, entries.get(0).data);
        assertEquals(128, entries.get(1).type);
    }

    @Test
    void findsIndicatorsTheWayMitWrapsThem() {
        // MIT: IF-RELEVANT( CAMMAC( elements [0] AuthorizationData( AUTH-INDICATOR ) ) )
        byte[] indicatorElement = element(97, indicators("pkinit", "hardened"));
        byte[] cammac = seq(ctx(0, authorizationData(indicatorElement)));
        byte[] ticketAd = authorizationData(element(1, authorizationData(element(96, cammac))));

        KerberosAuthzData ad = KerberosAuthzData.from(KerberosAuthzData.parseAuthorizationData(ticketAd));

        assertEquals(List.of("pkinit", "hardened"), ad.getIndicators());
        assertTrue(ad.getPacs().isEmpty());
    }

    @Test
    void findsAPacInsideIfRelevant() {
        byte[] pacBytes = {9, 9, 9, 9};
        byte[] ticketAd = authorizationData(element(1, authorizationData(element(128, pacBytes))));

        KerberosAuthzData ad = KerberosAuthzData.from(KerberosAuthzData.parseAuthorizationData(ticketAd));

        assertEquals(1, ad.getPacs().size());
        assertArrayEquals(pacBytes, ad.getPacs().get(0));
        assertTrue(ad.getIndicators().isEmpty());
    }

    @Test
    void acceptsUnwrappedEntriesAsTheJdkDeliversThem() {
        List<KerberosAuthzData.Entry> entries = List.of(
                new KerberosAuthzData.Entry(128, new byte[]{1}),
                new KerberosAuthzData.Entry(97, indicators("pkinit")),
                new KerberosAuthzData.Entry(500, new byte[]{0}));

        KerberosAuthzData ad = KerberosAuthzData.from(entries);

        assertEquals(1, ad.getPacs().size());
        assertEquals(List.of("pkinit"), ad.getIndicators());
    }

    @Test
    void handlesLongFormLengths() {
        byte[] big = new byte[300];
        byte[] ticketAd = authorizationData(element(128, big));

        KerberosAuthzData ad = KerberosAuthzData.from(KerberosAuthzData.parseAuthorizationData(ticketAd));

        assertEquals(300, ad.getPacs().get(0).length);
    }

    @Test
    void rejectsMalformedInput() {
        assertThrows(IllegalArgumentException.class,
                () -> KerberosAuthzData.parseAuthorizationData(new byte[]{0x30, 0x05, 0x01}));
        assertThrows(IllegalArgumentException.class,
                () -> KerberosAuthzData.parseAuthorizationData(octets(new byte[]{1})));
        assertThrows(IllegalArgumentException.class,
                () -> KerberosAuthzData.from(List.of(new KerberosAuthzData.Entry(97, octets(new byte[]{1})))));
    }

    @Test
    void stopsAtPathologicalNesting() {
        byte[] ad = authorizationData(element(128, new byte[]{1}));
        for (int i = 0; i < 12; i++) {
            ad = authorizationData(element(1, ad));
        }
        byte[] finalAd = ad;
        assertThrows(IllegalArgumentException.class,
                () -> KerberosAuthzData.from(KerberosAuthzData.parseAuthorizationData(finalAd)));
    }
}
