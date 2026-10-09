package nrw.sit.keycloak.authenticator;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalRoleAuthenticatorFactory;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    private final AuthenticationExecutionModel execution = exec("krb-exec-id", "browser-flow-id", Requirement.ALTERNATIVE, "sit-auth-spnego-button");
    private final AuthenticationExecutionModel cookie = exec("cookie-exec-id", "browser-flow-id", Requirement.ALTERNATIVE, "auth-cookie");
    private final AuthenticationExecutionModel forms = flowExec("forms-exec-id", "browser-flow-id", Requirement.ALTERNATIVE, "forms-flow-id");
    private final KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
    private final RealmModel realm = mock(RealmModel.class);
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
        when(context.getRealm()).thenReturn(realm);
        when(context.getEvent()).thenReturn(event);
        when(context.getExecution()).thenReturn(execution);
        when(context.getFlowPath()).thenReturn("authenticate");
        when(context.getRefreshUrl(false)).thenReturn(REFRESH_URL);
        when(context.generateAccessCode()).thenReturn("code");
        when(context.getActionUrl("code")).thenReturn(ACTION_URL);

        when(session.users()).thenReturn(users);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactory(Authenticator.class, "condition-x")).thenReturn(new ConditionalRoleAuthenticatorFactory());

        when(authSession.getParentSession()).thenReturn(rootSession);
        when(authSession.getRequiredActions()).thenReturn(Set.of());

        when(request.getHttpMethod()).thenReturn("GET");
        when(request.getHttpHeaders()).thenReturn(headers);
        when(request.getDecodedFormParameters()).thenReturn(form);
        when(headers.getRequestHeaders()).thenReturn(requestHeaders);

        when(realm.getAuthenticationExecutionsStream("browser-flow-id"))
                .thenAnswer(inv -> Stream.of(cookie, forms, execution));
        when(realm.getAuthenticationFlowById("browser-flow-id")).thenReturn(flow("browser-flow-id", true));
    }

    private static AuthenticationExecutionModel exec(String id, String parent, Requirement requirement, String authenticator) {
        AuthenticationExecutionModel model = new AuthenticationExecutionModel();
        model.setId(id);
        model.setParentFlow(parent);
        model.setRequirement(requirement);
        model.setAuthenticator(authenticator);
        return model;
    }

    private static AuthenticationExecutionModel flowExec(String id, String parent, Requirement requirement, String flowId) {
        AuthenticationExecutionModel model = exec(id, parent, requirement, null);
        model.setAuthenticatorFlow(true);
        model.setFlowId(flowId);
        return model;
    }

    private static AuthenticationFlowModel flow(String id, boolean topLevel) {
        AuthenticationFlowModel model = new AuthenticationFlowModel();
        model.setId(id);
        model.setAlias(id);
        model.setTopLevel(topLevel);
        return model;
    }

    /**
     * browser-flow: cookie ALT | forms ALT | kerberos-wrap ALT
     *   kerberos-wrap: intern CONDITIONAL
     *     intern: condition REQUIRED | [extra] | button REQUIRED
     */
    private AuthenticationExecutionModel nestedButton(AuthenticationExecutionModel... extraInIntern) {
        AuthenticationExecutionModel wrap = flowExec("wrap-exec-id", "browser-flow-id", Requirement.ALTERNATIVE, "wrap-flow-id");
        AuthenticationExecutionModel intern = flowExec("intern-exec-id", "wrap-flow-id", Requirement.CONDITIONAL, "intern-flow-id");
        AuthenticationExecutionModel condition = exec("cond-exec-id", "intern-flow-id", Requirement.REQUIRED, "condition-x");
        AuthenticationExecutionModel button = exec("krb-nested-id", "intern-flow-id", Requirement.REQUIRED, "sit-auth-spnego-button");

        when(realm.getAuthenticationExecutionsStream("browser-flow-id")).thenAnswer(inv -> Stream.of(cookie, forms, wrap));
        when(realm.getAuthenticationExecutionsStream("wrap-flow-id")).thenAnswer(inv -> Stream.of(intern));
        when(realm.getAuthenticationExecutionsStream("intern-flow-id"))
                .thenAnswer(inv -> Stream.concat(Stream.of(condition), Stream.concat(Stream.of(extraInIntern), Stream.of(button))));
        when(realm.getAuthenticationFlowById("wrap-flow-id")).thenReturn(flow("wrap-flow-id", false));
        when(realm.getAuthenticationFlowById("intern-flow-id")).thenReturn(flow("intern-flow-id", false));
        when(realm.getAuthenticationExecutionByFlowId("wrap-flow-id")).thenReturn(wrap);
        when(realm.getAuthenticationExecutionByFlowId("intern-flow-id")).thenReturn(intern);
        return button;
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
    void buttonClickResetsTheFlowSkipsTheSiblingsMarksTheRequestAndRedirectsToTheRefreshUrl() {
        when(request.getHttpMethod()).thenReturn("POST");
        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");

        authenticator.authenticate(context);

        // flow reset (statuses and notes gone) BEFORE siblings are skipped and the marker is written
        InOrder order = inOrder(authSession);
        order.verify(authSession).clearExecutionStatus();
        order.verify(authSession).clearAuthNotes();
        order.verify(authSession).setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, "authenticate");
        order.verify(authSession).setExecutionStatus("cookie-exec-id", ExecutionStatus.ATTEMPTED);
        order.verify(authSession).setExecutionStatus("forms-exec-id", ExecutionStatus.ATTEMPTED);
        order.verify(authSession).setAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE, "true");
        verify(authSession).setAuthenticatedUser(null);
        verify(authSession, never()).setExecutionStatus(eq("krb-exec-id"), any());

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
    void anInvalidTicketIsRejectedAndTheFlowResetToTheLoginForm() {
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIbad");
        when(users.getUserByCredential(any(), any()))
                .thenReturn(new CredentialValidationOutput(null, CredentialValidationOutput.Status.FAILED, Map.of()));
        when(context.getStatus()).thenReturn(FlowStatus.FAILED);

        authenticator.authenticate(context);

        verify(authSession).removeAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE);
        verify(event).error(Errors.INVALID_USER_CREDENTIALS);
        verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        // siblings were skipped for this attempt, so a reset is the only way back to the form
        verify(context).resetFlow();
    }

    @Test
    void aTicketNobodyCanValidateFallsBackToTheLoginForm() {
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIabc");
        when(users.getUserByCredential(any(), any())).thenReturn(null);
        when(context.getStatus()).thenReturn(FlowStatus.ATTEMPTED);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context).resetFlow();
    }

    @Test
    void aValidTicketDoesNotResetTheFlow() {
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIabc");
        when(users.getUserByCredential(any(), any()))
                .thenReturn(new CredentialValidationOutput(mock(UserModel.class), CredentialValidationOutput.Status.AUTHENTICATED, Map.of()));
        when(context.getStatus()).thenReturn(FlowStatus.SUCCESS);

        authenticator.authenticate(context);

        verify(context, never()).resetFlow();
    }

    @Test
    void aNonNegotiateAnswerAfterTheClickIsTreatedLikeTheBuiltInOne() {
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "NTLM TlRMTVNT");
        when(context.getStatus()).thenReturn(FlowStatus.ATTEMPTED);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context).resetFlow();
        verify(users, never()).getUserByCredential(any(), any());
    }

    // ── fix: a ticket is only evaluated after the user clicked ───────────────

    @Test
    void aTicketWithoutAClickIsIgnored() {
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIabc");

        authenticator.authenticate(context);

        verify(users, never()).getUserByCredential(any(), any());
        verify(context, never()).success(anyString());
        verify(context, never()).setUser(any());
        verify(context).attempted();
    }

    @Test
    void aHeaderOnTheClickItselfDoesNotSkipTheRedirect() {
        when(request.getHttpMethod()).thenReturn("POST");
        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");
        requestHeaders.putSingle(HttpHeaders.AUTHORIZATION, "Negotiate YIIabc");

        authenticator.authenticate(context);

        verify(users, never()).getUserByCredential(any(), any());
        verify(authSession).setAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE, "true");
        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(context).challenge(captor.capture());
        assertEquals(Response.Status.SEE_OTHER.getStatusCode(), captor.getValue().getStatus());
    }

    // ── fix: only a click on this very execution counts ──────────────────────

    @Test
    void aSelectionOfAnotherExecutionIsNotAClick() {
        when(request.getHttpMethod()).thenReturn("POST");
        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "passkey-exec-id");

        authenticator.authenticate(context);

        verify(authSession, never()).clearExecutionStatus();
        verify(authSession, never()).setAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE, "true");
        verify(context, never()).challenge(any());
        verify(context).attempted();
    }

    // ── fix: never skip a mandatory step ─────────────────────────────────────

    @Test
    void refusesTheClickNextToAConditionalSibling() {
        AuthenticationExecutionModel otp = flowExec("otp-exec-id", "browser-flow-id", Requirement.CONDITIONAL, "otp-flow-id");
        when(realm.getAuthenticationExecutionsStream("browser-flow-id")).thenAnswer(inv -> Stream.of(cookie, forms, otp, execution));
        when(request.getHttpMethod()).thenReturn("POST");
        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");

        authenticator.authenticate(context);

        verify(authSession, never()).clearExecutionStatus();
        verify(authSession, never()).setExecutionStatus(anyString(), any());
        verify(authSession, never()).setAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE, "true");
        verify(context, never()).challenge(any());
        verify(context).attempted();
    }

    @Test
    void refusesWhenTheButtonIsRequiredNextToARequiredStep() {
        AuthenticationExecutionModel required = exec("krb-exec-id", "browser-flow-id", Requirement.REQUIRED, "sit-auth-spnego-button");
        AuthenticationExecutionModel password = exec("pw-exec-id", "browser-flow-id", Requirement.REQUIRED, "auth-username-password-form");
        when(realm.getAuthenticationExecutionsStream("browser-flow-id")).thenAnswer(inv -> Stream.of(password, required));

        assertNull(SpnegoButtonAuthenticator.executionsToSkip(session, realm, required));
    }

    @Test
    void ignoresDisabledSiblings() {
        AuthenticationExecutionModel off = exec("off-exec-id", "browser-flow-id", Requirement.DISABLED, "auth-spnego");
        when(realm.getAuthenticationExecutionsStream("browser-flow-id")).thenAnswer(inv -> Stream.of(cookie, off, forms, execution));

        assertEquals(List.of("cookie-exec-id", "forms-exec-id"), SpnegoButtonAuthenticator.executionsToSkip(session, realm, execution));
    }

    @Test
    void nestedConditionalPlacementSkipsOnlyTheTopLevelAlternatives() {
        AuthenticationExecutionModel button = nestedButton();

        // the condition next to the button is not a step; wrap/intern lie on the path itself
        assertEquals(List.of("cookie-exec-id", "forms-exec-id"), SpnegoButtonAuthenticator.executionsToSkip(session, realm, button));
    }

    @Test
    void nestedConditionalPlacementRefusesWhenTheSubFlowHasAnotherStep() {
        AuthenticationExecutionModel otp = exec("otp-exec-id", "intern-flow-id", Requirement.REQUIRED, "auth-otp-form");
        AuthenticationExecutionModel button = nestedButton(otp);

        assertNull(SpnegoButtonAuthenticator.executionsToSkip(session, realm, button));
    }

    @Test
    void requiredInTheNestedPlacementStillGetsTheFallbackFormNotAnErrorPage() {
        AuthenticationExecutionModel button = nestedButton();
        when(context.getExecution()).thenReturn(button);
        when(authSession.getAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE)).thenReturn("true");

        authenticator.authenticate(context);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(context).forceChallenge(captor.capture());
        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), captor.getValue().getStatus());
        assertTrue(String.valueOf(captor.getValue().getEntity()).contains(ACTION_URL.toString()));
    }

    // ── fallback form / action ───────────────────────────────────────────────

    @Test
    void actionClearsTheMarkerAndResetsTheFlow() {
        authenticator.action(context);

        verify(authSession).removeAuthNote(SpnegoButtonAuthenticator.REQUESTED_NOTE);
        // not attempted(): the skipped siblings must come back, so the flow starts over
        verify(context).resetFlow();
        verify(context, never()).attempted();
    }

    @Test
    void skipsTheAlternativeSiblingsButNotItself() {
        assertEquals(List.of("cookie-exec-id", "forms-exec-id"), SpnegoButtonAuthenticator.executionsToSkip(session, realm, execution));
    }

    // ── selection detection ──────────────────────────────────────────────────

    @Test
    void detectsTheAuthenticationSelectionPost() {
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request, execution), "GET is never a selection");

        when(request.getHttpMethod()).thenReturn("POST");
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request, execution), "POST without the field");

        form.putSingle(Constants.AUTHENTICATION_EXECUTION, " ");
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request, execution), "blank field");

        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "other-exec-id");
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request, execution), "another execution");

        form.putSingle(Constants.AUTHENTICATION_EXECUTION, "krb-exec-id");
        assertTrue(SpnegoButtonAuthenticator.isSelectedViaButton(request, execution));

        when(request.getDecodedFormParameters()).thenReturn(null);
        assertFalse(SpnegoButtonAuthenticator.isSelectedViaButton(request, execution), "no form body");
    }

    @Test
    void isTheBuiltInSpnegoAuthenticator() {
        assertTrue(authenticator instanceof SpnegoAuthenticator);
        assertFalse(authenticator.requiresUser());
    }
}
