package nrw.sit.keycloak.kerberos;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Realm REST extension {@code sit-kerberos}: the ticket endpoint used by the login page. */
public class KerberosTicketResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "sit-kerberos";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new KerberosTicketResourceProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
