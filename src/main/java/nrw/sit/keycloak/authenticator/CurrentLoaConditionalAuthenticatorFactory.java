package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Factory for {@link CurrentLoaConditionalAuthenticator}.
 */
public class CurrentLoaConditionalAuthenticatorFactory
        implements ConditionalAuthenticatorFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "sit-conditional-current-loa";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property()
            .name(CurrentLoaConditionalAuthenticator.CONF_LEVEL)
            .label("Level")
            .helpText("The condition matches while the level of authentication reached so far in this login "
                    + "is BELOW this value (e.g. 2: run the step after a level-1 first factor, skip it after "
                    + "a level-2 one).")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .build();

    @Override
    public ConditionalAuthenticator getSingleton() {
        return CurrentLoaConditionalAuthenticator.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - Current LOA below (SIT)";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if the level of authentication reached so far in the current login "
                + "is below the configured level. Lets a first factor that already established a higher "
                + "level (e.g. smart-card Kerberos) skip a second-factor step. Does not change the "
                + "session LOA itself.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.STEP_UP_AUTHENTICATION);
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
}
