package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory for {@link KerberosTicketAuthenticator}. Reports the {@code kerberos} reference
 * category like the built-in Kerberos factory, which is what lists the execution in the login
 * page's authentication selections. {@code ALTERNATIVE} (and {@code DISABLED}) only: the
 * execution is always one choice among others.
 *
 * <p>Server configuration ({@code --spi-authenticator-sit-auth-kerberos-ticket-<key>=<value>}):
 * <ul>
 *   <li>{@value #CONFIG_MAX_AGE_SECONDS}: how long a validated ticket may wait for the
 *       selection POST, default {@value #DEFAULT_MAX_AGE_SECONDS} s</li>
 * </ul>
 */
public class KerberosTicketAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-auth-kerberos-ticket";

    public static final String CONFIG_MAX_AGE_SECONDS = "max-age-seconds";
    public static final int DEFAULT_MAX_AGE_SECONDS = 60;

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.ALTERNATIVE,
            Requirement.DISABLED,
    };

    private static final Requirement[] REQUIREMENT_CHOICES_DISABLED = {
            Requirement.DISABLED,
    };

    private volatile KerberosTicketAuthenticator authenticator = new KerberosTicketAuthenticator(DEFAULT_MAX_AGE_SECONDS);

    @Override
    public Authenticator create(KeycloakSession session) {
        return authenticator;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.KERBEROS;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return isKerberosFeatureEnabled() ? REQUIREMENT_CHOICES : REQUIREMENT_CHOICES_DISABLED;
    }

    @Override
    public String getDisplayType() {
        return "SIT: Kerberos (ticket checked by the login page)";
    }

    @Override
    public String getHelpText() {
        return isKerberosFeatureEnabled()
                ? "Kerberos as a choice on the login page. The page validates the ticket against "
                + "/realms/<realm>/sit-kerberos/ticket (fetch) and then selects this execution; the "
                + "execution only consumes that result. Place as ALTERNATIVE after the password form. "
                + "Include theme-resources/templates/sit-kerberos-ticket.ftl in login.ftl."
                : "DISABLED. Please enable Kerberos feature and make sure Kerberos available in your platform. "
                + "Kerberos as a choice on the login page (ticket checked by the page).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void init(Config.Scope config) {
        int maxAge = config == null ? DEFAULT_MAX_AGE_SECONDS : config.getInt(CONFIG_MAX_AGE_SECONDS, DEFAULT_MAX_AGE_SECONDS);
        authenticator = new KerberosTicketAuthenticator(Math.max(1, maxAge));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do.
    }

    @Override
    public void close() {
        // Nothing to close.
    }

    private static boolean isKerberosFeatureEnabled() {
        return Profile.isFeatureEnabled(Profile.Feature.KERBEROS);
    }
}
