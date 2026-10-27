package nrw.sit.keycloak.kerberos;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/** Mounts {@link KerberosTicketResource} under {@code /realms/<realm>/sit-kerberos}. */
public class KerberosTicketResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public KerberosTicketResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new KerberosTicketResource(session);
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
