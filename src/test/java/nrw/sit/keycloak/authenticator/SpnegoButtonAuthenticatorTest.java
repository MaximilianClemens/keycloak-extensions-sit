package nrw.sit.keycloak.authenticator;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.net.URI;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Drives the three phases of the on-demand SPNEGO authenticator through a mocked flow context.
 * Building JAX-RS responses needs a RuntimeDelegate, which RESTEasy provides on the test
 * classpath.
 */
class SpnegoButtonAuthenticatorTest {

    private static final URI REFRESH_URL = URI.create("https://sso.example.test/realms/r/login-actions/authenticate?client_id=c&tab_id=t");
    private static final URI ACTION_URL = URI.create("https://sso.example.test/realms/r/login-actions/authenticate?session_code=code&execution=krb&client_id=c&tab_id=t");

    private final SpnegoButtonAuthenticator authenticator = SpnegoButtonAuthenticator.SINGLETON;

    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final RootAuthenticationSessionModel rootSession = mock(RootAuthenticationSessionModel.class);
    private final AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final UserProvider users = mock(UserProvider.class);
    private final EventBuilder event = mock(EventBuilder.class);
    private final HttpRequest request = mock(HttpRequest.class);
    private final HttpHeaders headers = mock(HttpHeaders.class);
    private final MultivaluedHashMap<String, String> requestHeaders = new MultivaluedHashMap<>();
    private final MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();

    @BeforeEach
    void setUp() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getHttpRequest()).thenReturn(request);
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(mock(RealmModel.class));
        when(context.getEvent()).thenReturn(event);
        when(context.getExecution()).thenReturn(execution);
        when(context.getFlowPath()).thenReturn("authenticate");
        when(context.getRefreshUrl(false)).thenReturn(REFRESH_URL);
        when(context.generateAccessCode()).thenReturn("code");
        when(context.getActionUrl("code")).thenReturn(ACTION_URL);

        when(session.users()).thenReturn(users);

        when(authSession.getParentSession()).thenReturn(rootSession);
        when(authSession.getRequiredActions()).thenReturn(Set.of());

        when(request.getHttpMethod()).thenReturn("GET");
        when(request.getHttpHeaders()).thenReturn(headers);
        when(request.getDecodedFormParameters()).thenReturn(form);
        when(headers.getRequestHeaders()).thenReturn(requestHeaders);

        when(execution.isRequired()).thenReturn(false);
    }

    // ── phase 0: nothing requested ───────────────────────────────────────────

    @Test
    void staysSilentWhenNothingWasRequested() {
        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).challenge(any());
        verify(context, never()).forceChallenge(any());
        verify(authSession, never()).setAuthNote(anyString(), anyString());
    }

    // ── phase 1: button click (authentication selection POST) ────────────────

    @Test
    void buttonClickResetsTheFlowMarksTheRequestAndRedirectsToTheRefreshUrl() {
        when(request.getHttpMethod()).thenReturn("POST");
        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");

        authenticator.authenticate(context);

        // flow reset (statuses and notes gone) BEFORE the request marker is written
        InOrder order = inOrder(authSession);
        order.verify(authSession).clearExecutionStatus();
        order.verify(authSession).clearAuthNotes();
        order.verify(authSession).setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, "authenticate");
        order.verify(authSession).setAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE, "true");
        verify(authSession).setAuthenticatedUser(null);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(context).challenge(captor.capture());
        Response response = captor.getValue();
        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), response.getStatus());
        assertEquals(REFRESH_URL, response.getLocation());

        verify(context, never()).attempted();
        verify(context, never()).forceChallenge(any());
    }

    // ── phase 2: GET after the redirect ──────────────────────────────────────

    @Test
    void sendsTheNegotiateChallengeOnTheRefreshGetWhenRequested() {
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");

        authenticator.authenticate(context);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(context).forceChallenge(captor.capture());
        Response response = captor.getValue();
        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
        assertEquals("Negotiate", response.getHeaderString(HttpHeaders.WWW_AUTHENTICATE));
        // ALTERNATIVE execution: body is Keycloak's auto-submitting fallback form
        assertTrue(String.valueOf(response.getEntity()).contains(ACTION_URL.toString()));

        // marker stays until the browser answers or the fallback form posts
        verify(authSession, never()).removeAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE);
        verify(context, never()).attempted();
    }

    // ── phase 3: browser answers with a ticket ───────────────────────────────

    @Test
    void validatesTheTicketLikeTheBuiltInAuthenticatorAndClearsTheMarker() {
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIabc");
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");
        UserModel user = mock(UserModel.class);
        when(users.getUserByCredential(any(), any()))
                .thenReturn(new CredentialValidationOutput(user, CredentialValidationOutput.Status.AUTHENTICATED, Map.of()));

        authenticator.authenticate(context);

        verify(authSession).removeAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE);
        verify(context).setUser(user);
        verify(context).success(UserCredentialModel.KERBEROS);
        verify(context, never()).challenge(any());
        verify(context, never()).attempted();
    }

    @Test
    void rejectsAnInvalidTicket() {
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIbad");
        when(users.getUserByCredential(any(), any()))
                .thenReturn(new CredentialValidationOutput(null, CredentialValidationOutput.Status.FAILED, Map.of()));

        authenticator.authenticate(context);

        verify(authSession).removeAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE);
        verify(event).error(Errors.INVALID_USER_CREDENTIALS);
        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
    }

    @Test
    void aTicketWinsOverAButtonSelectionInTheSameRequest() {
        when(request.getHttpMethod()).thenReturn("POST");
        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "NTLM TlRMTVNT");

        authenticator.authenticate(context);

        // built-in behaviour for a non-Negotiate scheme: attempted, no reset, no redirect
        verify(context).attempted();
        verify(authSession, never()).clearExecutionStatus();
        verify(context, never()).challenge(any());
    }

    // ── fallback form / action ───────────────────────────────────────────────

    @Test
    void actionClearsTheMarkerAndReportsAttempted() {
        authenticator.action(context);

        verify(authSession).removeAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE);
        verify(context).attempted();
    }

    // ── selection detection ──────────────────────────────────────────────────

    @Test
    void detectsTheAuthenticationSelectionPost() {
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request), "GET is never a selection");

        when(request.getHttpMethod()).thenReturn("POST");
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request), "POST without the field");

        form.putSingle(Constants.AUTHENTICATION_EXECUTION, " ");
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request), "blank field");

        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");
        assertTrue(SpnegoButtonAuthenticator.isSelectedViaButton(request));

        when(request.getDecodedFormParameters()).thenReturn(null);
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request), "no form body");
    }

    @Test
    void isTheBuiltInSpnegoAuthenticator() {
        assertTrue(authenticator instanceof SpnegoAuthenticator);
        assertFalse(authenticator.requiresUser());
    }
}
