package nrw.sit.keycloak.authenticator;

import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Factory for {@link SpnegoLevelAuthenticator}: the on-demand Kerberos authenticator with the
 * level of authentication derived from the ticket. Same flow placement and requirement
 * choices as {@link SpnegoButtonAuthenticatorFactory}; configurable.
 */
public class SpnegoLevelAuthenticatorFactory extends SpnegoButtonAuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-auth-spnego-level";

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property()
            .name(SpnegoLevelAuthenticator.CONF_AMA_SIDS)
            .label("AMA group SIDs")
            .helpText("Security identifiers of the Authentication Mechanism Assurance groups that the Windows "
                    + "KDC adds to the PAC for certificate (smart card) logons, comma separated. The PAC "
                    + "server signature is verified with the service key from the keytab before a group "
                    + "counts. Leave empty to ignore the PAC.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(SpnegoLevelAuthenticator.CONF_INDICATORS)
            .label("Authentication indicators")
            .helpText("RFC 8129 authentication indicators (e.g. 'pkinit' as configured with pkinit_indicator "
                    + "on MIT/Heimdal KDCs), comma separated. Any match counts. Leave empty to ignore.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(SpnegoLevelAuthenticator.CONF_LEVEL_MATCHED)
            .label("Level when matched")
            .helpText("Level of authentication (per the realm's acr.loa.map) set when an AMA group or "
                    + "indicator matched. Default 2.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(Integer.toString(SpnegoLevelAuthenticator.DEFAULT_LEVEL_MATCHED))
            .add()
            .property()
            .name(SpnegoLevelAuthenticator.CONF_LEVEL_DEFAULT)
            .label("Level otherwise")
            .helpText("Level of authentication set for a Kerberos login without matching evidence. Default 1.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(Integer.toString(SpnegoLevelAuthenticator.DEFAULT_LEVEL_DEFAULT))
            .add()
            .build();

    static final SpnegoLevelAuthenticator SINGLETON_DISABLED = new SpnegoLevelAuthenticator() {
        @Override
        public void authenticate(org.keycloak.authentication.AuthenticationFlowContext context) {
            throw new IllegalStateException("Not possible to authenticate as Kerberos feature is disabled");
        }
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return isKerberosFeatureEnabled() ? SpnegoLevelAuthenticator.SINGLETON : SINGLETON_DISABLED;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public String getDisplayType() {
        return "SIT: Kerberos (on demand, level from ticket)";
    }

    @Override
    public String getHelpText() {
        return isKerberosFeatureEnabled()
                ? "SPNEGO/Kerberos started by the user from the login page, with the level of authentication "
                + "(ACR) taken from the ticket: a configured Authentication Mechanism Assurance group in the "
                + "signed PAC or an RFC 8129 authentication indicator raises the level. Place as ALTERNATIVE "
                + "after the forms sub-flow."
                : "DISABLED. Please enable Kerberos feature and make sure Kerberos available in your platform.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }
}
