package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CurrentLoaConditionalAuthenticatorTest {

    private final CurrentLoaConditionalAuthenticator condition = CurrentLoaConditionalAuthenticator.SINGLETON;
    private final CurrentLoaConditionalAuthenticatorFactory factory = new CurrentLoaConditionalAuthenticatorFactory();
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);

    @BeforeEach
    void setUp() {
        when(context.getSession()).thenReturn(mock(KeycloakSession.class));
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of(CurrentLoaConditionalAuthenticator.CONF_LEVEL, "2"));
    }

    private void currentLevel(String level) {
        when(authSession.getAuthNote(Constants.LEVEL_OF_AUTHENTICATION)).thenReturn(level);
    }

    @Test
    void matchesWhenNoLevelWasReachedYet() {
        currentLevel(null);

        assertTrue(condition.matchCondition(context));
    }

    @Test
    void matchesBelowTheConfiguredLevel() {
        currentLevel("1");

        assertTrue(condition.matchCondition(context));
    }

    @Test
    void doesNotMatchAtOrAboveTheConfiguredLevel() {
        currentLevel("2");
        assertFalse(condition.matchCondition(context));

        currentLevel("3");
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void withoutConfigurationItEvaluatesToFalse() {
        currentLevel("0");
        when(config.getConfig()).thenReturn(Map.of());
        assertFalse(condition.matchCondition(context));

        when(config.getConfig()).thenReturn(Map.of(CurrentLoaConditionalAuthenticator.CONF_LEVEL, "two"));
        assertFalse(condition.matchCondition(context));

        when(context.getAuthenticatorConfig()).thenReturn(null);
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void isReadOnly() {
        currentLevel("1");

        condition.matchCondition(context);

        verify(authSession, never()).setAuthNote(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        verify(authSession, never()).setUserSessionNote(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void factoryBasics() {
        assertEquals("sit-conditional-current-loa", factory.getId());
        assertSame(condition, factory.getSingleton());
        assertTrue(factory.isConfigurable());
        assertFalse(factory.isUserSetupAllowed());
        List<Requirement> choices = Arrays.asList(factory.getRequirementChoices());
        assertTrue(choices.containsAll(List.of(Requirement.REQUIRED, Requirement.DISABLED)));
        assertFalse(choices.contains(Requirement.ALTERNATIVE));
        assertEquals(1, factory.getConfigProperties().size());
        assertEquals(CurrentLoaConditionalAuthenticator.CONF_LEVEL, factory.getConfigProperties().get(0).getName());
        assertFalse(condition.requiresUser());
    }
}
