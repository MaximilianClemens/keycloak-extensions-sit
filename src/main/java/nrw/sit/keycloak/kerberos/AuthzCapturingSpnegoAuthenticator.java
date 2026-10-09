package nrw.sit.keycloak.kerberos;

import com.sun.security.jgss.AuthorizationDataEntry;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.jboss.logging.Logger;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.federation.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.federation.kerberos.impl.SPNEGOAuthenticator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Keycloak's own {@link SPNEGOAuthenticator} (JAAS login with the keytab, GSS-API accept),
 * plus one thing: while the accepted {@link GSSContext} is still alive, the ticket's
 * authorization data is read through the JDK's {@link ExtendedGSSContext} and kept.
 *
 * Nothing about the validation changes; the hook used is {@link #logAuthDetails}, which the
 * base class calls with the established context right after acceptance.
 */
public class AuthzCapturingSpnegoAuthenticator extends SPNEGOAuthenticator {

    private static final Logger logger = Logger.getLogger(AuthzCapturingSpnegoAuthenticator.class);

    private List<KerberosAuthzData.Entry> authzData = Collections.emptyList();
    private boolean authzDataAvailable;

    public AuthzCapturingSpnegoAuthenticator(CommonKerberosConfig config,
                                            KerberosServerSubjectAuthenticator subjectAuthenticator,
                                            String spnegoToken) {
        super(config, subjectAuthenticator, spnegoToken);
    }

    @Override
    protected void logAuthDetails(GSSContext gssContext) throws GSSException {
        super.logAuthDetails(gssContext);
        if (!gssContext.isEstablished()) {
            return;
        }
        if (!(gssContext instanceof ExtendedGSSContext)) {
            logger.warn("GSSContext is not an ExtendedGSSContext; ticket authorization data not available");
            return;
        }
        Object data = ((ExtendedGSSContext) gssContext).inquireSecContext(InquireType.KRB5_GET_AUTHZ_DATA);
        List<KerberosAuthzData.Entry> entries = new ArrayList<>();
        if (data instanceof AuthorizationDataEntry[]) {
            for (AuthorizationDataEntry e : (AuthorizationDataEntry[]) data) {
                entries.add(new KerberosAuthzData.Entry(e.getType(), e.getData()));
            }
        }
        authzData = Collections.unmodifiableList(entries);
        authzDataAvailable = true;
        logger.debugf("Captured %d authorization data entries from the Kerberos ticket", entries.size());
    }

    /** The ticket's authorization data entries (possibly empty). */
    public List<KerberosAuthzData.Entry> getAuthzData() {
        return authzData;
    }

    /** False if the JDK did not expose the ticket's authorization data at all. */
    public boolean isAuthzDataAvailable() {
        return authzDataAvailable;
    }
}
