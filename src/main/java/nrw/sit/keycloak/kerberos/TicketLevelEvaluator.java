package nrw.sit.keycloak.kerberos;

import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.IntFunction;

/**
 * Decides the level of authentication a Kerberos ticket is worth, from the evidence the KDC
 * put into it:
 * <ul>
 *   <li><b>Authentication Mechanism Assurance</b> (Windows): a universal group that the KDC adds
 *       to the PAC only when the TGT was obtained with a certificate (smart card). Its SID is
 *       compared against the configured list; the PAC server signature must verify.</li>
 *   <li><b>Authentication indicators</b> (RFC 8129, MIT/Heimdal): strings such as
 *       {@code pkinit} the KDC adds for the pre-authentication mechanism that was used.</li>
 * </ul>
 * Any match yields {@code levelMatched}, otherwise {@code levelDefault}. Evidence that cannot
 * be verified never raises the level; it is logged and ignored.
 */
public final class TicketLevelEvaluator {

    private static final Logger logger = Logger.getLogger(TicketLevelEvaluator.class);

    /** Configuration of one evaluation. */
    public static final class Config {
        public final Set<String> amaGroupSids;
        public final Set<String> indicators;
        public final int levelMatched;
        public final int levelDefault;

        public Config(Set<String> amaGroupSids, Set<String> indicators, int levelMatched, int levelDefault) {
            this.amaGroupSids = normalize(amaGroupSids);
            this.indicators = normalize(indicators);
            this.levelMatched = levelMatched;
            this.levelDefault = levelDefault;
        }

        private static Set<String> normalize(Set<String> in) {
            Set<String> out = new TreeSet<>();
            if (in != null) {
                for (String s : in) {
                    if (s != null && !s.isBlank()) {
                        out.add(s.trim().toUpperCase(Locale.ROOT));
                    }
                }
            }
            return Collections.unmodifiableSet(out);
        }
    }

    /** Outcome: the level and, for logs and session notes, what it was based on. */
    public static final class Result {
        public final int level;
        public final List<String> evidence;
        public final List<String> warnings;

        Result(int level, List<String> evidence, List<String> warnings) {
            this.level = level;
            this.evidence = Collections.unmodifiableList(evidence);
            this.warnings = Collections.unmodifiableList(warnings);
        }

        public boolean matched() {
            return !evidence.isEmpty();
        }
    }

    private TicketLevelEvaluator() {
    }

    /**
     * @param config      what to look for
     * @param entries     the ticket's authorization data
     * @param serviceKeys the service's long-term key for a given AES checksum type (null if
     *                    unavailable); used to verify the PAC server signature
     */
    public static Result evaluate(Config config, List<KerberosAuthzData.Entry> entries, IntFunction<byte[]> serviceKeys) {
        List<String> evidence = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        KerberosAuthzData authz;
        try {
            authz = KerberosAuthzData.from(entries);
        } catch (IllegalArgumentException e) {
            warnings.add("authorization data unreadable: " + e.getMessage());
            return new Result(config.levelDefault, evidence, warnings);
        }

        if (!config.indicators.isEmpty()) {
            for (String indicator : authz.getIndicators()) {
                if (config.indicators.contains(indicator.trim().toUpperCase(Locale.ROOT))) {
                    evidence.add("indicator:" + indicator);
                }
            }
        }

        if (!config.amaGroupSids.isEmpty()) {
            for (byte[] raw : authz.getPacs()) {
                evaluatePac(config, raw, serviceKeys, evidence, warnings);
            }
        }

        int level = evidence.isEmpty() ? config.levelDefault : config.levelMatched;
        logger.debugf("Kerberos ticket level %d (evidence %s, warnings %s)", level, evidence, warnings);
        return new Result(level, evidence, warnings);
    }

    private static void evaluatePac(Config config, byte[] raw, IntFunction<byte[]> serviceKeys,
                                    List<String> evidence, List<String> warnings) {
        Pac pac;
        try {
            pac = Pac.parse(raw);
        } catch (IllegalArgumentException e) {
            warnings.add("PAC unreadable: " + e.getMessage());
            return;
        }
        int sigType = pac.serverSignatureType();
        byte[] key = sigType > 0 && serviceKeys != null ? serviceKeys.apply(sigType) : null;
        if (key == null) {
            warnings.add("no service key for PAC signature type " + sigType + ", PAC ignored");
            return;
        }
        if (!pac.verifyServerSignature(key)) {
            warnings.add("PAC server signature does not verify, PAC ignored");
            return;
        }
        logger.debugf("PAC server signature (type %d) verified", sigType);
        Pac.LogonInfo info;
        try {
            info = pac.logonInfo();
        } catch (IllegalArgumentException e) {
            warnings.add("PAC logon info unreadable: " + e.getMessage());
            return;
        }
        if (info == null) {
            return;
        }
        for (String sid : info.groupSids) {
            if (config.amaGroupSids.contains(sid.toUpperCase(Locale.ROOT))) {
                evidence.add("ama-group:" + sid);
            }
        }
    }
}
