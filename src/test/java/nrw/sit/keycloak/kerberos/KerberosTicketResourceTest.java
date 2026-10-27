package nrw.sit.keycloak.kerberos;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import nrw.sit.keycloak.authenticator.KerberosTicketAuthenticator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.models.ClientModel;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The endpoint through a mocked session. The authentication session lookup (cookie handling of
 * {@code AuthenticationSessionManager}) is stubbed through the protected hook.
 */
class KerberosTicketResourceTest {

    private final KeycloakSession session = mock(KeycloakSession.class);
    private final KeycloakContext context = mock(KeycloakContext.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final ClientModel client = mock(ClientModel.class);
    private final UserProvider users = mock(UserProvider.class);
    private final UserModel alice = mock(UserModel.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final HttpHeaders headers = mock(HttpHeaders.class);
    private final MultivaluedHashMap<String, String> requestHeaders = new MultivaluedHashMap<>();

    private AuthenticationSessionModel resolved;
    private int lookups;

    private final KerberosTicketResource resource = new KerberosTicketResource(session) {
        @Override
        protected AuthenticationSessionModel currentAuthenticationSession(RealmModel r, ClientModel c, String tabId) {
            lookups++;
            return "tab-1".equals(tabId) ? resolved : null;
        }

        @Override
        protected void loginError(RealmModel r, ClientModel c, String error) {
            errors.add(error);
        }
    };
    private final java.util.List<String> errors = new java.util.ArrayList<>();

    @BeforeAll
    static void configureDefaultProfile() {
        if (Profile.getInstance() == null) {
            Profile.configure();
        }
    }

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(context.getRequestHeaders()).thenReturn(headers);
        when(context.getConnection()).thenReturn(mock(ClientConnection.class));
        when(headers.getRequestHeaders()).thenReturn(requestHeaders);
        when(realm.getClientByClientId("app")).thenReturn(client);
        when(client.isEnabled()).thenReturn(true);
        when(client.getClientId()).thenReturn("app");
        when(session.users()).thenReturn(users);
        when(alice.getId()).thenReturn("alice-id");
        when(alice.getUsername()).thenReturn("alice");
        resolved = authSession;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(Response response) {
        return (Map<String, Object>) response.getEntity();
    }

    private void withTicket(String token) {
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, KerberosConstants.NEGOTIATE + " " + token);
    }

    @Test
    void withoutHeaderChallengesWithNegotiate() {
        Response response = resource.ticket("app", "tab-1");

        assertEquals(401, response.getStatus());
        assertEquals(KerberosConstants.NEGOTIATE, response.getHeaderString(HttpHeaders.WWW_AUTHENTICATE));
        assertEquals(false, body(response).get("ok"));
        assertTrue(response.getHeaderString(HttpHeaders.CACHE_CONTROL).contains("no-store"));
        verify(users, never()).getUserByCredential(any(), any());
    }

    @Test
    void validTicketRecordsTheUserInTheAuthSession() {
        withTicket("YIIB...");
        when(users.getUserByCredential(eq(realm), any(UserCredentialModel.class)))
                .thenReturn(new CredentialValidationOutput(alice, CredentialValidationOutput.Status.AUTHENTICATED,
                        Map.of("KERBEROS_PRINCIPAL", "alice@EXAMPLE.TEST")));

        Response response = resource.ticket("app", "tab-1");

        assertEquals(200, response.getStatus());
        assertEquals(true, body(response).get("ok"));
        verify(authSession).setAuthNote(KerberosTicketAuthenticator.USER_NOTE, "alice-id");
        ArgumentCaptor<String> time = ArgumentCaptor.forClass(String.class);
        verify(authSession).setAuthNote(eq(KerberosTicketAuthenticator.TIME_NOTE), time.capture());
        assertTrue(Long.parseLong(time.getValue()) > 0);
        verify(authSession).setAuthNote(KerberosTicketAuthenticator.STATE_NOTE, "{\"KERBEROS_PRINCIPAL\":\"alice@EXAMPLE.TEST\"}");

        ArgumentCaptor<UserCredentialModel> credential = ArgumentCaptor.forClass(UserCredentialModel.class);
        verify(users).getUserByCredential(eq(realm), credential.capture());
        assertEquals(UserCredentialModel.KERBEROS, credential.getValue().getType());
        assertEquals("YIIB...", credential.getValue().getChallengeResponse());
    }

    @Test
    void emptyStateLeavesNoStateNote() {
        withTicket("t");
        when(users.getUserByCredential(eq(realm), any(UserCredentialModel.class)))
                .thenReturn(new CredentialValidationOutput(alice, CredentialValidationOutput.Status.AUTHENTICATED, Map.of()));

        assertEquals(200, resource.ticket("app", "tab-1").getStatus());

        verify(authSession, never()).setAuthNote(eq(KerberosTicketAuthenticator.STATE_NOTE), anyString());
        verify(authSession).removeAuthNote(KerberosTicketAuthenticator.STATE_NOTE);
    }

    @Test
    void rejectedTicketIsForbiddenAndLeavesNoNote() {
        withTicket("bad");
        when(users.getUserByCredential(eq(realm), any(UserCredentialModel.class)))
                .thenReturn(new CredentialValidationOutput(null, CredentialValidationOutput.Status.FAILED, Map.of()));

        Response response = resource.ticket("app", "tab-1");

        assertEquals(403, response.getStatus());
        assertEquals("invalid_ticket", body(response).get("reason"));
        assertEquals(java.util.List.of("invalid_user_credentials"), errors);
        verify(authSession, never()).setAuthNote(anyString(), anyString());
    }

    @Test
    void continueAsksForAnotherRoundWithTheResponseToken() {
        withTicket("round1");
        when(users.getUserByCredential(eq(realm), any(UserCredentialModel.class)))
                .thenReturn(new CredentialValidationOutput(null, CredentialValidationOutput.Status.CONTINUE,
                        Map.of(KerberosConstants.RESPONSE_TOKEN, "srv-token")));

        Response response = resource.ticket("app", "tab-1");

        assertEquals(401, response.getStatus());
        assertEquals("Negotiate srv-token", response.getHeaderString(HttpHeaders.WWW_AUTHENTICATE));
        verify(authSession, never()).setAuthNote(anyString(), anyString());
    }

    @Test
    void noKerberosProviderIsForbidden() {
        withTicket("t");
        when(users.getUserByCredential(eq(realm), any(UserCredentialModel.class))).thenReturn(null);

        Response response = resource.ticket("app", "tab-1");

        assertEquals(403, response.getStatus());
        assertEquals("no_provider", body(response).get("reason"));
        assertEquals(java.util.List.of("invalid_user_credentials"), errors);
    }

    @Test
    void aTokenIsOnlyEvaluatedForACallerWithAnAuthSession() {
        withTicket("t");

        Response response = resource.ticket("app", "other-tab");

        assertEquals(403, response.getStatus());
        assertEquals("no_auth_session", body(response).get("reason"));
        assertEquals(1, lookups);
        verify(users, never()).getUserByCredential(any(), any());
    }

    @Test
    void unknownClientOrMissingParametersAreBadRequests() {
        assertEquals(400, resource.ticket("nope", "tab-1").getStatus());
        assertEquals("unknown_client", body(resource.ticket("nope", "tab-1")).get("reason"));
        assertEquals(400, resource.ticket(null, "tab-1").getStatus());
        assertEquals(400, resource.ticket("app", null).getStatus());
        assertEquals(0, lookups);
    }

    @Test
    void disabledClientIsRejected() {
        when(client.isEnabled()).thenReturn(false);
        assertEquals(400, resource.ticket("app", "tab-1").getStatus());
    }

    @Test
    void otherSchemesAreNotEvaluated() {
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Basic YWxpY2U6cHc=");

        Response response = resource.ticket("app", "tab-1");

        assertEquals(403, response.getStatus());
        assertEquals("unsupported_scheme", body(response).get("reason"));
        verify(users, never()).getUserByCredential(any(), any());
    }

    @Test
    void stateSerialization() {
        assertNull(KerberosTicketResource.serializeState(null));
        assertNull(KerberosTicketResource.serializeState(Map.of()));
        assertEquals("{\"a\":\"b\"}", KerberosTicketResource.serializeState(Map.of("a", "b")));
    }
}
