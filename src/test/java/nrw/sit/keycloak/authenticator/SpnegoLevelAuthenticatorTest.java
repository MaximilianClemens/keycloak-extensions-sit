package nrw.sit.keycloak.authenticator;

import jakarta.ws.rs.core.HttpHeaders;
import nrw.sit.keycloak.kerberos.AuthzCapturingSpnegoAuthenticator;
import nrw.sit.keycloak.kerberos.KerberosAuthzData;
import nrw.sit.keycloak.kerberos.KerberosAuthzDataTest;
import nrw.sit.keycloak.kerberos.TicketLevelEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.EventBuilder;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.UserStorageProvider;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The GSS acceptance is Keycloak's and needs a KDC (covered by ci/kerberos-e2e). Here the
 * SPNEGO step is stubbed and the rest is checked: the pre-authenticated context handed to the
 * user storage providers, the level written to the AcrStore, the session notes, and the
 * failure paths.
 */
class SpnegoLevelAuthenticatorTest {

    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserProvider users = mock(UserProvider.class);
    private final HttpRequest request = mock(HttpRequest.class);
    private final HttpHeaders headers = mock(HttpHeaders.class);
    private final jakarta.ws.rs.core.MultivaluedHashMap<String, String> requestHeaders = new jakarta.ws.rs.core.MultivaluedHashMap<>();
    private final UserModel alice = mock(UserModel.class);
    private final ComponentModel kerberosComponent = mock(ComponentModel.class);
    private final AuthenticatorConfigModel authConfig = mock(AuthenticatorConfigModel.class);

    private final AuthzCapturingSpnegoAuthenticator spnego = mock(AuthzCapturingSpnegoAuthenticator.class);
    private CommonKerberosConfig configSeen;

    private final SpnegoLevelAuthenticator authenticator = new SpnegoLevelAuthenticator() {
        @Override
        protected AuthzCapturingSpnegoAuthenticator createSpnegoAuthenticator(CommonKerberosConfig config, String token) {
            configSeen = config;
            return spnego;
        }
    };

    @BeforeEach
    void setUp() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getHttpRequest()).thenReturn(request);
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getEvent()).thenReturn(mock(EventBuilder.class));
        when(context.getExecution()).thenReturn(mock(AuthenticationExecutionModel.class));
        when(context.getAuthenticatorConfig()).thenReturn(authConfig);
        when(authConfig.getConfig()).thenReturn(Map.of(
                SpnegoLevelAuthenticator.CONF_INDICATORS, "pkinit",
                SpnegoLevelAuthenticator.CONF_LEVEL_MATCHED, "2",
                SpnegoLevelAuthenticator.CONF_LEVEL_DEFAULT, "1"));
        when(session.users()).thenReturn(users);
        when(request.getHttpMethod()).thenReturn("GET");
        when(request.getHttpHeaders()).thenReturn(headers);
        when(request.getDecodedFormParameters()).thenReturn(new jakarta.ws.rs.core.MultivaluedHashMap<>());
        when(headers.getRequestHeaders()).thenReturn(requestHeaders);
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIabc");

        // one enabled Kerberos user storage provider in the realm
        when(realm.getId()).thenReturn("realm-id");
        when(kerberosComponent.getProviderId()).thenReturn("kerberos");
        when(kerberosComponent.getProviderType()).thenReturn(UserStorageProvider.class.getName());
        when(kerberosComponent.getName()).thenReturn("kerberos");
        when(kerberosComponent.getConfig()).thenReturn(config(Map.of(
                "enabled", "true", "priority", "0",
                "kerberosRealm", "EXAMPLE.TEST", "serverPrincipal", "HTTP/kc.example.test@EXAMPLE.TEST",
                "keyTab", "/nonexistent/keycloak.keytab")));
        when(realm.getComponentsStream(eq("realm-id"), eq(UserStorageProvider.class.getName())))
                .thenAnswer(inv -> Stream.of(kerberosComponent));

        when(spnego.getAuthenticatedKerberosPrincipal()).thenReturn(null);
    }

    private static MultivaluedHashMap<String, String> config(Map<String, String> values) {
        MultivaluedHashMap<String, String> out = new MultivaluedHashMap<>();
        values.forEach(out::putSingle);
        return out;
    }

    private void spnegoSucceeds(List<KerberosAuthzData.Entry> authz) {
        when(spnego.isAuthenticated()).thenReturn(true);
        when(spnego.isAuthzDataAvailable()).thenReturn(true);
        when(spnego.getAuthzData()).thenReturn(authz);
        when(users.getUserByCredential(eq(realm), any()))
                .thenReturn(new CredentialValidationOutput(alice, CredentialValidationOutput.Status.AUTHENTICATED, Map.of("k", "v")));
    }

    @Test
    void handsThePreAuthenticatedContextToTheUserStorageProviders() {
        spnegoSucceeds(List.of());

        authenticator.authenticate(context);

        ArgumentCaptor<UserCredentialModel> captor = ArgumentCaptor.forClass(UserCredentialModel.class);
        verify(users).getUserByCredential(eq(realm), captor.capture());
        UserCredentialModel credential = captor.getValue();
        assertEquals(UserCredentialModel.KERBEROS, credential.getType());
        assertEquals("YIIabc", credential.getChallengeResponse());
        assertSame(spnego, credential.getNote(KerberosConstants.AUTHENTICATED_SPNEGO_CONTEXT),
                "the providers must not accept the token a second time");
        assertNotNull(configSeen);
        assertEquals("HTTP/kc.example.test@EXAMPLE.TEST", configSeen.getServerPrincipal());
    }

    @Test
    void setsTheDefaultLevelWithoutEvidence() {
        spnegoSucceeds(List.of());

        authenticator.authenticate(context);

        verify(context).setUser(alice);
        verify(authSession).setUserSessionNote("k", "v");
        verify(authSession).setUserSessionNote(SpnegoLevelAuthenticator.LEVEL_NOTE, "1");
        verify(authSession).setUserSessionNote(SpnegoLevelAuthenticator.EVIDENCE_NOTE, "");
        verify(authSession).setAuthNote(eq("level-of-authentication"), eq("1"));
        verify(context).success(UserCredentialModel.KERBEROS);
        verify(context, never()).resetFlow();
    }

    @Test
    void setsTheMatchedLevelWithAnIndicator() {
        List<KerberosAuthzData.Entry> authz = KerberosAuthzData.parseAuthorizationData(
                KerberosAuthzDataTest.authorizationData(KerberosAuthzDataTest.element(
                        KerberosAuthzData.AD_AUTHENTICATION_INDICATOR, KerberosAuthzDataTest.indicators("pkinit"))));
        spnegoSucceeds(authz);

        authenticator.authenticate(context);

        verify(authSession).setUserSessionNote(SpnegoLevelAuthenticator.LEVEL_NOTE, "2");
        verify(authSession).setUserSessionNote(SpnegoLevelAuthenticator.EVIDENCE_NOTE, "indicator:pkinit");
        verify(authSession).setAuthNote(eq("level-of-authentication"), eq("2"));
        verify(context).success(UserCredentialModel.KERBEROS);
    }

    @Test
    void rejectsATicketTheKdcDoesNotAccept() {
        when(spnego.isAuthenticated()).thenReturn(false);
        when(spnego.getResponseToken()).thenReturn(null);
        when(context.getStatus()).thenReturn(org.keycloak.authentication.FlowStatus.FAILED);

        authenticator.authenticate(context);

        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        verify(users, never()).getUserByCredential(any(), any());
        verify(authSession, never()).setAuthNote(eq("level-of-authentication"), anyString());
        verify(context).resetFlow();
    }

    @Test
    void failsWhenNoProviderKnowsTheUser() {
        when(spnego.isAuthenticated()).thenReturn(true);
        when(spnego.getAuthzData()).thenReturn(List.of());
        when(users.getUserByCredential(eq(realm), any())).thenReturn(null);
        when(context.getStatus()).thenReturn(org.keycloak.authentication.FlowStatus.FAILED);

        authenticator.authenticate(context);

        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        verify(context, never()).success(anyString());
    }

    @Test
    void attemptedWithoutAKerberosEnabledProvider() {
        when(realm.getComponentsStream(eq("realm-id"), eq(UserStorageProvider.class.getName())))
                .thenAnswer(inv -> Stream.empty());
        when(context.getStatus()).thenReturn(org.keycloak.authentication.FlowStatus.ATTEMPTED);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(spnego, never()).authenticate();
    }

    @Test
    void nonNegotiateSchemesAreAttempted() {
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "NTLM TlRMTVNT");
        when(context.getStatus()).thenReturn(org.keycloak.authentication.FlowStatus.ATTEMPTED);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(spnego, never()).authenticate();
    }

    @Test
    void findsAnLdapProviderWithKerberosEnabled() {
        ComponentModel ldap = mock(ComponentModel.class);
        when(ldap.getProviderId()).thenReturn("ldap");
        when(ldap.getProviderType()).thenReturn(UserStorageProvider.class.getName());
        when(ldap.getName()).thenReturn("ad");
        when(ldap.getConfig()).thenReturn(config(Map.of(
                "enabled", "true", "priority", "0", "allowKerberosAuthentication", "true",
                "kerberosRealm", "AD.TEST", "serverPrincipal", "HTTP/kc.ad.test@AD.TEST", "keyTab", "/x")));
        ComponentModel ldapWithout = mock(ComponentModel.class);
        when(ldapWithout.getProviderId()).thenReturn("ldap");
        when(ldapWithout.getProviderType()).thenReturn(UserStorageProvider.class.getName());
        when(ldapWithout.getName()).thenReturn("plain");
        when(ldapWithout.getConfig()).thenReturn(config(Map.of("enabled", "true", "priority", "-1")));
        when(realm.getComponentsStream(eq("realm-id"), eq(UserStorageProvider.class.getName())))
                .thenAnswer(inv -> Stream.of(ldapWithout, ldap));

        CommonKerberosConfig found = SpnegoLevelAuthenticator.findKerberosConfig(realm);

        assertNotNull(found);
        assertEquals("HTTP/kc.ad.test@AD.TEST", found.getServerPrincipal());
    }

    @Test
    void disabledProvidersAreSkipped() {
        when(kerberosComponent.getConfig()).thenReturn(config(Map.of("enabled", "false")));

        assertNull(SpnegoLevelAuthenticator.findKerberosConfig(realm));
    }

    @Test
    void readsTheConfigurationWithDefaults() {
        when(authConfig.getConfig()).thenReturn(Map.of(
                SpnegoLevelAuthenticator.CONF_AMA_SIDS, "S-1-5-21-1-2-3-4, s-1-5-21-5-6-7-8",
                SpnegoLevelAuthenticator.CONF_LEVEL_MATCHED, "x"));

        TicketLevelEvaluator.Config cfg = SpnegoLevelAuthenticator.readConfig(authConfig);

        assertEquals(Set.of("S-1-5-21-1-2-3-4", "S-1-5-21-5-6-7-8"), cfg.amaGroupSids);
        assertTrue(cfg.indicators.isEmpty());
        assertEquals(2, cfg.levelMatched, "invalid value falls back to the default");
        assertEquals(1, cfg.levelDefault);

        TicketLevelEvaluator.Config empty = SpnegoLevelAuthenticator.readConfig(null);
        assertTrue(empty.amaGroupSids.isEmpty());
        assertEquals(2, empty.levelMatched);
    }

    @Test
    void missingKeytabYieldsNoKeyInsteadOfAnError() {
        CommonKerberosConfig config = SpnegoLevelAuthenticator.findKerberosConfig(realm);

        assertNull(SpnegoLevelAuthenticator.serviceKeys(config).apply(16));
    }
}
