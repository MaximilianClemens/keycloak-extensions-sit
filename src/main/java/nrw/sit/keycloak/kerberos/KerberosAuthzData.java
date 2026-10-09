package nrw.sit.keycloak.kerberos;

import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The authorization data of an accepted Kerberos ticket, reduced to what the SIT
 * authenticators look at:
 * <ul>
 *   <li>the Windows PAC ({@code AD-WIN2K-PAC}, type 128), if the KDC issued one;</li>
 *   <li>RFC 8129 authentication indicators ({@code AD-AUTHENTICATION-INDICATOR}, type 97),
 *       either directly or wrapped in a CAMMAC (RFC 7751, type 96) as MIT krb5 does.</li>
 * </ul>
 * Both can sit inside {@code AD-IF-RELEVANT} (type 1) containers, which are unwrapped.
 *
 * The ticket these entries come from was decrypted and integrity-checked with the service key
 * by the GSS-API layer, so the entries are known to originate from the KDC. CAMMAC verifiers
 * are therefore not checked here; the PAC server signature is checked by {@link Pac} because
 * MS-PAC asks services to do so.
 */
public final class KerberosAuthzData {

    private static final Logger logger = Logger.getLogger(KerberosAuthzData.class);

    public static final int AD_IF_RELEVANT = 1;
    public static final int AD_CAMMAC = 96;
    public static final int AD_AUTHENTICATION_INDICATOR = 97;
    public static final int AD_WIN2K_PAC = 128;

    /** One {@code AuthorizationData} element: ad-type and ad-data. */
    public static final class Entry {
        public final int type;
        public final byte[] data;

        public Entry(int type, byte[] data) {
            this.type = type;
            this.data = data;
        }
    }

    private final List<byte[]> pacs = new ArrayList<>();
    private final List<String> indicators = new ArrayList<>();

    public static KerberosAuthzData from(List<Entry> entries) {
        KerberosAuthzData out = new KerberosAuthzData();
        out.walk(entries, 0);
        return out;
    }

    /** Parses a DER {@code AuthorizationData} (SEQUENCE OF SEQUENCE { [0] ad-type, [1] ad-data }). */
    public static List<Entry> parseAuthorizationData(byte[] der) {
        Der.Tlv seq = Der.read(der);
        if (seq.tag != Der.TAG_SEQUENCE) {
            throw new IllegalArgumentException("AuthorizationData is not a SEQUENCE");
        }
        List<Entry> out = new ArrayList<>();
        for (Der.Tlv element : seq.children()) {
            if (element.tag != Der.TAG_SEQUENCE) {
                throw new IllegalArgumentException("AuthorizationData element is not a SEQUENCE");
            }
            Integer type = null;
            byte[] data = null;
            for (Der.Tlv field : element.children()) {
                switch (field.contextTag()) {
                    case 0:
                        type = field.inner().asInt();
                        break;
                    case 1:
                        data = field.inner().value();
                        break;
                    default:
                        // unknown field, ignore
                }
            }
            if (type == null || data == null) {
                throw new IllegalArgumentException("AuthorizationData element without ad-type or ad-data");
            }
            out.add(new Entry(type, data));
        }
        return out;
    }

    private void walk(List<Entry> entries, int depth) {
        if (depth > 8) {
            throw new IllegalArgumentException("AuthorizationData nested too deeply");
        }
        for (Entry entry : entries) {
            switch (entry.type) {
                case AD_IF_RELEVANT:
                    walk(parseAuthorizationData(entry.data), depth + 1);
                    break;
                case AD_CAMMAC:
                    walk(cammacElements(entry.data), depth + 1);
                    break;
                case AD_AUTHENTICATION_INDICATOR:
                    indicators.addAll(parseIndicators(entry.data));
                    break;
                case AD_WIN2K_PAC:
                    pacs.add(entry.data);
                    break;
                default:
                    logger.tracef("Ignoring authorization data of type %d", entry.type);
            }
        }
    }

    /** CAMMAC ::= SEQUENCE { elements [0] AuthorizationData, verifiers ... } (RFC 7751). */
    static List<Entry> cammacElements(byte[] der) {
        Der.Tlv seq = Der.read(der);
        if (seq.tag != Der.TAG_SEQUENCE) {
            throw new IllegalArgumentException("CAMMAC is not a SEQUENCE");
        }
        for (Der.Tlv field : seq.children()) {
            if (field.contextTag() == 0) {
                return parseAuthorizationData(field.inner().encoded());
            }
        }
        return Collections.emptyList();
    }

    /** AD-AUTHENTICATION-INDICATOR ::= SEQUENCE OF UTF8String (RFC 8129). */
    static List<String> parseIndicators(byte[] der) {
        Der.Tlv seq = Der.read(der);
        if (seq.tag != Der.TAG_SEQUENCE) {
            throw new IllegalArgumentException("indicator list is not a SEQUENCE");
        }
        List<String> out = new ArrayList<>();
        for (Der.Tlv s : seq.children()) {
            if (s.tag != Der.TAG_UTF8_STRING) {
                throw new IllegalArgumentException("indicator is not a UTF8String");
            }
            out.add(s.asUtf8());
        }
        return out;
    }

    /** Raw PAC buffers found in the ticket (normally none or one). */
    public List<byte[]> getPacs() {
        return Collections.unmodifiableList(pacs);
    }

    /** Authentication indicators found in the ticket, in order of appearance. */
    public List<String> getIndicators() {
        return Collections.unmodifiableList(indicators);
    }
}
