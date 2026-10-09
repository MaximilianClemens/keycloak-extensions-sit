package nrw.sit.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Conditional authenticator that matches when the level of authentication reached so far in
 * the CURRENT authentication is below the configured level.
 *
 * The built-in "Condition - Level of Authentication" decides on the requested level and on
 * levels reached in earlier sessions (max age); it does not look at what the steps before it in
 * this very login have already established. So a first factor that sets level 2 itself (e.g.
 * a smart-card Kerberos login, see {@link SpnegoLevelAuthenticator}) would still be followed by
 * the OTP step. Add this condition to that step's conditional sub-flow with level 2: the step
 * runs after a level-1 first factor and is skipped after a level-2 one.
 *
 * Read-only: it never changes the session level.
 */
public class CurrentLoaConditionalAuthenticator implements ConditionalAuthenticator {

    private static final Logger LOG = Logger.getLogger(CurrentLoaConditionalAuthenticator.class);

    static final CurrentLoaConditionalAuthenticator SINGLETON = new CurrentLoaConditionalAuthenticator();

    static final String CONF_LEVEL = "loa-condition-level";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AcrStore acrStore = new AcrStore(context.getSession(), context.getAuthenticationSession());
        int current = acrStore.getLevelOfAuthenticationFromCurrentAuthentication();
        Integer configured = getConfiguredLevel(context);
        if (configured == null) {
            LOG.warn("CurrentLoaCondition without a configured level - evaluating to false");
            return false;
        }
        boolean result = current < configured;
        LOG.tracef("CurrentLoaCondition: current=%d < %d -> %s", current, configured.intValue(), Boolean.toString(result));
        return result;
    }

    static Integer getConfiguredLevel(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        Map<String, String> config = cfg == null ? null : cfg.getConfig();
        String value = config == null ? null : config.get(CONF_LEVEL);
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            LOG.warnf("CurrentLoaCondition: invalid level '%s'", value);
            return null;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used for conditions.
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Nothing to set.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
