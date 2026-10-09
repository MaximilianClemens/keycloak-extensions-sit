package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class SpnegoLevelAuthenticatorFactoryTest {

    private final SpnegoLevelAuthenticatorFactory factory = new SpnegoLevelAuthenticatorFactory();

    @BeforeAll
    static void configureDefaultProfile() {
        if (Profile.getInstance() == null) {
            Profile.configure();
        }
    }

    @Test
    void isASeparateProviderNextToTheButtonAuthenticator() {
        assertEquals("sit-auth-spnego-level", factory.getId());
        assertNotEquals(SpnegoButtonAuthenticatorFactory.PROVIDER_ID, factory.getId());
        assertEquals(UserCredentialModel.KERBEROS, factory.getReferenceCategory());
        assertTrue(factory.getDisplayType().startsWith("SIT: Kerberos"));
    }

    @Test
    void createsTheLevelAuthenticator() {
        if (Profile.isFeatureEnabled(Profile.Feature.KERBEROS)) {
            assertSame(SpnegoLevelAuthenticator.SINGLETON, factory.create(mock(KeycloakSession.class)));
        } else {
            assertSame(SpnegoLevelAuthenticatorFactory.SINGLETON_DISABLED, factory.create(mock(KeycloakSession.class)));
        }
        assertTrue(factory.create(mock(KeycloakSession.class)) instanceof SpnegoButtonAuthenticator);
    }

    @Test
    void exposesTheFourSettings() {
        List<String> names = factory.getConfigProperties().stream()
                .map(ProviderConfigProperty::getName).collect(Collectors.toList());

        assertTrue(factory.isConfigurable());
        assertEquals(List.of(SpnegoLevelAuthenticator.CONF_AMA_SIDS, SpnegoLevelAuthenticator.CONF_INDICATORS,
                SpnegoLevelAuthenticator.CONF_LEVEL_MATCHED, SpnegoLevelAuthenticator.CONF_LEVEL_DEFAULT), names);
    }
}
