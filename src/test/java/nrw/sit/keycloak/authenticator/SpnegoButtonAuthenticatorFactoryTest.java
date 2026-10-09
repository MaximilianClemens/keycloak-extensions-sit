package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticatorFactory;
import org.keycloak.common.Profile;
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
import static org.mockito.Mockito.mock;

class SpnegoButtonAuthenticatorFactoryTest {

    private final SpnegoButtonAuthenticatorFactory factory = new SpnegoButtonAuthenticatorFactory();

    @BeforeAll
    static void configureDefaultProfile() {
        // The factory consults the Kerberos feature flag like the built-in one; outside a
        // server there is no profile yet, so use the defaults (Kerberos is a default feature).
        if (Profile.getInstance() == null) {
            Profile.configure();
        }
    }

    @Test
    void usesItsOwnProviderId() {
        assertEquals("sit-auth-spnego-button", factory.getId());
        assertNotEquals(SpnegoAuthenticatorFactory.PROVIDER_ID, factory.getId());
    }

    @Test
    void sharesTheKerberosReferenceCategoryWithTheBuiltInAuthenticator() {
        // This is what makes the execution show up in the login page's authenticationSelections.
        assertEquals(UserCredentialModel.KERBEROS, factory.getReferenceCategory());
        assertEquals(new SpnegoAuthenticatorFactory().getReferenceCategory(), factory.getReferenceCategory());
    }

    @Test
    void isNeitherConfigurableNorUserSetup() {
        assertFalse(factory.isConfigurable());
        assertFalse(factory.isUserSetupAllowed());
        assertNull(factory.getConfigProperties());
    }

    @Test
    void followsTheKerberosFeatureFlag() {
        List<Requirement> choices = Arrays.asList(factory.getRequirementChoices());

        if (Profile.isFeatureEnabled(Profile.Feature.KERBEROS)) {
            assertSame(SpnegoButtonAuthenticator.SINGLETON, factory.create(mock(KeycloakSession.class)));
            assertTrue(choices.contains(Requirement.ALTERNATIVE));
            assertTrue(choices.contains(Requirement.DISABLED));
            // On demand makes no sense as REQUIRED; the built-in authenticator covers that.
            assertFalse(choices.contains(Requirement.REQUIRED));
            assertFalse(choices.contains(Requirement.CONDITIONAL));
        } else {
            assertSame(SpnegoButtonAuthenticatorFactory.SINGLETON_DISABLED, factory.create(mock(KeycloakSession.class)));
            assertEquals(List.of(Requirement.DISABLED), choices);
        }
    }

    @Test
    void displayTypeIsPrefixedLikeTheOtherSitProviders() {
        assertTrue(factory.getDisplayType().startsWith("SIT: "));
        assertTrue(factory.getDisplayType().contains("Kerberos"));
        assertFalse(factory.getHelpText().isBlank());
    }
}
