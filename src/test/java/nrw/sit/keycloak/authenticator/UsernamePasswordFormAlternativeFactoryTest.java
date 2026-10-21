package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class UsernamePasswordFormAlternativeFactoryTest {

    private final UsernamePasswordFormAlternativeFactory factory = new UsernamePasswordFormAlternativeFactory();
    private final UsernamePasswordFormFactory builtIn = new UsernamePasswordFormFactory();

    @Test
    void offersAlternativeNextToRequired() {
        List<Requirement> choices = Arrays.asList(factory.getRequirementChoices());

        assertTrue(choices.contains(Requirement.REQUIRED));
        assertTrue(choices.contains(Requirement.ALTERNATIVE));
        assertTrue(choices.contains(Requirement.DISABLED));
        assertFalse(choices.contains(Requirement.CONDITIONAL));
        assertEquals(List.of(Requirement.REQUIRED), Arrays.asList(builtIn.getRequirementChoices()),
                "the built-in factory is unchanged");
    }

    @Test
    void createsTheBuiltInAuthenticator() {
        Authenticator authenticator = factory.create(mock(KeycloakSession.class));

        assertEquals(UsernamePasswordForm.class, authenticator.getClass());
        assertFalse(authenticator.requiresUser());
    }

    @Test
    void behavesLikeTheBuiltInFactoryOtherwise() {
        assertEquals(PasswordCredentialModel.TYPE, factory.getReferenceCategory());
        assertEquals(builtIn.getReferenceCategory(), factory.getReferenceCategory());
        assertEquals(builtIn.isConfigurable(), factory.isConfigurable());
        assertEquals(builtIn.isUserSetupAllowed(), factory.isUserSetupAllowed());
        assertEquals(builtIn.getConfigProperties(), factory.getConfigProperties());
    }

    @Test
    void usesItsOwnProviderId() {
        assertEquals("sit-auth-username-password-form", factory.getId());
        assertNotEquals(UsernamePasswordFormFactory.PROVIDER_ID, factory.getId());
        assertTrue(factory.getDisplayType().startsWith("SIT: "));
    }

    @Test
    void shipsTheSelectionTextsForItsProviderId() throws IOException {
        for (String lang : List.of("en", "de")) {
            Properties messages = load("/theme-resources/messages/messages_" + lang + ".properties");
            assertNotNull(messages.getProperty(factory.getId() + "-display-name"), "display name " + lang);
            assertNotNull(messages.getProperty(factory.getId() + "-help-text"), "help text " + lang);
        }
        assertEquals("Benutzername und Passwort",
                load("/theme-resources/messages/messages_de.properties").getProperty(factory.getId() + "-display-name"));
    }

    private static Properties load(String path) throws IOException {
        Properties p = new Properties();
        try (InputStream in = UsernamePasswordFormAlternativeFactoryTest.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing " + path);
            p.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return p;
    }
}
