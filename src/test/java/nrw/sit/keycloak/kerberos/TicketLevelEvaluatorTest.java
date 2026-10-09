package nrw.sit.keycloak.kerberos;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import static nrw.sit.keycloak.kerberos.KerberosAuthzDataTest.authorizationData;
import static nrw.sit.keycloak.kerberos.KerberosAuthzDataTest.element;
import static nrw.sit.keycloak.kerberos.KerberosAuthzDataTest.indicators;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TicketLevelEvaluatorTest {

    private static final String AMA_SID = "S-1-5-21-3999999999-2888888888-1777777777-1234";
    private static byte[] pac;
    private static byte[] key;

    @BeforeAll
    static void loadFixture() throws IOException {
        try (InputStream in = TicketLevelEvaluatorTest.class.getResourceAsStream("/pac/pac.bin")) {
            pac = in.readAllBytes();
        }
        Properties p = new Properties();
        try (InputStream in = TicketLevelEvaluatorTest.class.getResourceAsStream("/pac/pac.properties")) {
            p.load(in);
        }
        key = HexFormat.of().parseHex(p.getProperty("aes256.key"));
    }

    private static List<KerberosAuthzData.Entry> pacTicket() {
        return List.of(new KerberosAuthzData.Entry(KerberosAuthzData.AD_WIN2K_PAC, pac));
    }

    private static TicketLevelEvaluator.Config config(Set<String> sids, Set<String> indicators) {
        return new TicketLevelEvaluator.Config(sids, indicators, 2, 1);
    }

    @Test
    void amaGroupInASignedPacRaisesTheLevel() {
        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(
                config(Set.of(AMA_SID), Set.of()), pacTicket(), t -> t == KerberosChecksum.HMAC_SHA1_96_AES256 ? key : null);

        assertEquals(2, r.level);
        assertEquals(List.of("ama-group:" + AMA_SID), r.evidence);
        assertTrue(r.warnings.isEmpty());
    }

    @Test
    void sidComparisonIgnoresCaseAndWhitespace() {
        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(
                config(Set.of(" " + AMA_SID.toLowerCase() + " "), Set.of()), pacTicket(), t -> key);

        assertEquals(2, r.level);
    }

    @Test
    void otherGroupsDoNotCount() {
        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(
                config(Set.of("S-1-5-21-1111111111-2222222222-3333333333-9999"), Set.of()), pacTicket(), t -> key);

        assertEquals(1, r.level);
        assertFalse(r.matched());
    }

    @Test
    void unverifiablePacNeverRaisesTheLevel() {
        byte[] wrong = key.clone();
        wrong[0] ^= 1;

        TicketLevelEvaluator.Result badKey = TicketLevelEvaluator.evaluate(
                config(Set.of(AMA_SID), Set.of()), pacTicket(), t -> wrong);
        TicketLevelEvaluator.Result noKey = TicketLevelEvaluator.evaluate(
                config(Set.of(AMA_SID), Set.of()), pacTicket(), t -> null);
        TicketLevelEvaluator.Result noKeys = TicketLevelEvaluator.evaluate(
                config(Set.of(AMA_SID), Set.of()), pacTicket(), null);

        assertEquals(1, badKey.level);
        assertEquals(1, noKey.level);
        assertEquals(1, noKeys.level);
        assertFalse(badKey.warnings.isEmpty());
        assertTrue(badKey.warnings.get(0).contains("signature"));
    }

    @Test
    void pacIsIgnoredWhenNoSidIsConfigured() {
        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(
                config(Set.of(), Set.of()), pacTicket(), t -> key);

        assertEquals(1, r.level);
        assertTrue(r.warnings.isEmpty(), "no key lookup, no warning");
    }

    @Test
    void authenticationIndicatorRaisesTheLevel() {
        List<KerberosAuthzData.Entry> ticket = KerberosAuthzData.parseAuthorizationData(
                authorizationData(element(KerberosAuthzData.AD_AUTHENTICATION_INDICATOR, indicators("pkinit"))));

        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(config(Set.of(), Set.of("PKINIT")), ticket, null);

        assertEquals(2, r.level);
        assertEquals(List.of("indicator:pkinit"), r.evidence);
    }

    @Test
    void unknownIndicatorsDoNotCount() {
        List<KerberosAuthzData.Entry> ticket = KerberosAuthzData.parseAuthorizationData(
                authorizationData(element(KerberosAuthzData.AD_AUTHENTICATION_INDICATOR, indicators("otp"))));

        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(config(Set.of(), Set.of("pkinit")), ticket, null);

        assertEquals(1, r.level);
    }

    @Test
    void garbageAuthorizationDataFallsBackToTheDefaultLevel() {
        List<KerberosAuthzData.Entry> ticket = List.of(
                new KerberosAuthzData.Entry(KerberosAuthzData.AD_IF_RELEVANT, new byte[]{1, 2, 3}));

        TicketLevelEvaluator.Result r = TicketLevelEvaluator.evaluate(config(Set.of(AMA_SID), Set.of("pkinit")), ticket, t -> key);

        assertEquals(1, r.level);
        assertFalse(r.warnings.isEmpty());
    }

    @Test
    void configuredLevelsAreUsed() {
        TicketLevelEvaluator.Config cfg = new TicketLevelEvaluator.Config(Set.of(AMA_SID), Set.of(), 3, 0);

        assertEquals(3, TicketLevelEvaluator.evaluate(cfg, pacTicket(), t -> key).level);
        assertEquals(0, TicketLevelEvaluator.evaluate(cfg, List.of(), t -> key).level);
    }
}
