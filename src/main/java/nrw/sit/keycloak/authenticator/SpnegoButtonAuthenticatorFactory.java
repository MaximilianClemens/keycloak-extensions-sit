package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
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
 * Factory for {@link SpnegoButtonAuthenticator}. Mirrors the built-in
 * {@code SpnegoAuthenticatorFactory} (same reference category, same Kerberos feature guard).
 * {@code ALTERNATIVE} is the normal placement. {@code REQUIRED} exists only for the conditional
 * placement (as the single step of a {@code CONDITIONAL} sub-flow inside an {@code ALTERNATIVE}
 * sub-flow); next to other mandatory steps the authenticator refuses the click.
 */
public class SpnegoButtonAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-auth-spnego-button";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.ALTERNATIVE,
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    private static final Requirement[] REQUIREMENT_CHOICES_DISABLED = {
            Requirement.DISABLED,
    };

    static final SpnegoButtonAuthenticator SINGLETON_DISABLED = new SpnegoButtonAuthenticator() {
        @Override
        public void authenticate(AuthenticationFlowContext context) {
            throw new IllegalStateException("Not possible to authenticate as Kerberos feature is disabled");
        }
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return isKerberosFeatureEnabled() ? SpnegoButtonAuthenticator.SINGLETON : SINGLETON_DISABLED;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        // Same category as the built-in Kerberos authenticator. This is what puts the execution
        // into the login page's authenticationSelections (userless credential-based option).
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
        return "SIT: Kerberos (on demand)";
    }

    @Override
    public String getHelpText() {
        return isKerberosFeatureEnabled()
                ? "SPNEGO/Kerberos that is started by the user from the login page (authentication selection, "
                + "e.g. a 'Sign in with Windows' button) instead of automatically. Place as ALTERNATIVE "
                + "after the forms sub-flow. To show it only under a condition: ALTERNATIVE sub-flow after "
                + "the forms > CONDITIONAL sub-flow > condition(s) + this execution as REQUIRED."
                : "DISABLED. Please enable Kerberos feature and make sure Kerberos available in your platform. "
                + "SPNEGO/Kerberos started on demand from the login page.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void init(Config.Scope config) {
        // No global configuration.
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
