package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KerberosTicketAuthenticatorFactoryTest {

    private final KerberosTicketAuthenticatorFactory factory = new KerberosTicketAuthenticatorFactory();

    @BeforeAll
    static void configureDefaultProfile() {
        if (Profile.getInstance() == null) {
            Profile.configure();
        }
    }

    @Test
    void usesItsOwnProviderId() {
        assertEquals("sit-auth-kerberos-ticket", factory.getId());
        assertNotEquals(SpnegoAuthenticatorFactory.PROVIDER_ID, factory.getId());
        assertNotEquals(SpnegoButtonAuthenticatorFactory.PROVIDER_ID, factory.getId());
    }

    @Test
    void isListedAsAKerberosSelectionWithoutUser() {
        // reference category + requiresUser()==false is what puts the execution into the login
        // page's authenticationSelections
        assertEquals(UserCredentialModel.KERBEROS, factory.getReferenceCategory());
        assertFalse(factory.create(mock(KeycloakSession.class)).requiresUser());
    }

    @Test
    void offersAlternativeAndDisabledOnly() {
        List<Requirement> choices = Arrays.asList(factory.getRequirementChoices());
        assertEquals(List.of(Requirement.ALTERNATIVE, Requirement.DISABLED), choices);
    }

    @Test
    void hasNoPerExecutionConfiguration() {
        assertFalse(factory.isConfigurable());
        assertFalse(factory.isUserSetupAllowed());
        assertNull(factory.getConfigProperties());
    }

    @Test
    void createReturnsASharedInstance() {
        KeycloakSession session = mock(KeycloakSession.class);
        assertSame(factory.create(session), factory.create(session));
        assertTrue(factory.create(session) instanceof KerberosTicketAuthenticator);
    }

    @Test
    void maxAgeComesFromTheServerConfig() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.getInt(eq(KerberosTicketAuthenticatorFactory.CONFIG_MAX_AGE_SECONDS), anyInt())).thenReturn(5);
        factory.init(scope);

        KerberosTicketAuthenticator authenticator = (KerberosTicketAuthenticator) factory.create(mock(KeycloakSession.class));
        assertTrue(authenticator.isFresh(String.valueOf(Time.currentTime() - 5)));
        assertFalse(authenticator.isFresh(String.valueOf(Time.currentTime() - 6)));
    }

    @Test
    void defaultMaxAgeWithoutConfig() {
        factory.init(null);
        KerberosTicketAuthenticator authenticator = (KerberosTicketAuthenticator) factory.create(mock(KeycloakSession.class));
        assertTrue(authenticator.isFresh(String.valueOf(Time.currentTime() - KerberosTicketAuthenticatorFactory.DEFAULT_MAX_AGE_SECONDS)));
        assertFalse(authenticator.isFresh(String.valueOf(Time.currentTime() - KerberosTicketAuthenticatorFactory.DEFAULT_MAX_AGE_SECONDS - 1)));
    }

    @Test
    void textsNameTheEndpointAndTheTemplate() {
        assertTrue(factory.getDisplayType().startsWith("SIT: Kerberos"));
        assertTrue(factory.getHelpText().contains("/sit-kerberos/ticket"));
        assertTrue(factory.getHelpText().contains("sit-kerberos-ticket.ftl"));
    }
}
