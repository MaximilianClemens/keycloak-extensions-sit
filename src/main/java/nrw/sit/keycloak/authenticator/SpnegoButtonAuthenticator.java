package nrw.sit.keycloak.authenticator;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.Constants;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

/**
 * Kerberos/SPNEGO that is triggered on demand (a "Sign in with Windows" button on the login
 * page) instead of running automatically on the first request.
 *
 * <h2>Why the built-in {@code auth-spnego} cannot be offered as a selectable alternative</h2>
 *
 * Selecting an execution from the login page is a {@code POST} to
 * {@code login-actions/authenticate?session_code=A&execution=<form>} with the form field
 * {@code authenticationExecution=<kerberos>}. The built-in authenticator answers that POST
 * with {@code 401 WWW-Authenticate: Negotiate}. The browser then repeats <em>the same POST</em>
 * with the ticket attached. That retry can never succeed:
 * <ul>
 *   <li>{@code session_code} is single use; it was consumed by the first POST.</li>
 *   <li>The {@code execution} query parameter still names the form, but the flow engine has
 *       already switched the current execution to Kerberos, so
 *       {@code AuthenticationProcessor#authenticationAction} answers "page expired".</li>
 * </ul>
 * This is the long-standing "Kerberos via Try another way shows page expired" behaviour.
 *
 * <h2>How this authenticator works</h2>
 *
 * The SPNEGO challenge is moved onto a request whose retry is harmless: a {@code GET} of the
 * flow's refresh URL, which carries neither {@code session_code} nor {@code execution}.
 * <ol>
 *   <li><b>Login page</b>: the execution sits <b>after</b> the forms sub-flow, so the first pass
 *       of the flow never reaches it. It is therefore still unprocessed and, because the
 *       factory reports the Kerberos reference category and the authenticator does not require
 *       a user, listed in {@code auth.authenticationSelections}, where the theme renders it as
 *       a button. (An execution that has already reported "attempted" is not listed, which is
 *       why it must not run before the form.)</li>
 *   <li><b>Button click</b> (POST with {@code authenticationExecution}): the flow is reset
 *       ({@link AuthenticationProcessor#resetFlow}), every sibling execution of the parent
 *       flow is marked {@code ATTEMPTED} so the next pass skips the forms and lands here, the
 *       request is remembered in the auth session note {@value #REQUESTED_NOTE}, and the
 *       browser is redirected (303) to the refresh URL.</li>
 *   <li><b>GET refresh URL</b> with the note set: the built-in behaviour runs and sends
 *       {@code 401 Negotiate} with Keycloak's auto-submitting fallback form in the body.</li>
 *   <li><b>Browser retry</b> of that GET with {@code Authorization: Negotiate ...}: the ticket is
 *       validated exactly as by the built-in authenticator (Kerberos user federation). If the
 *       ticket is rejected, the flow is reset so the user gets the password form instead of a
 *       dead end.</li>
 *   <li><b>No ticket</b>: the fallback form posts to this execution, {@link #action} resets the
 *       flow, and the password form renders with the button available again.</li>
 * </ol>
 *
 * <h2>Flow placement</h2>
 *
 * Requirement {@code ALTERNATIVE}, in the top-level browser flow <b>after</b> the forms
 * sub-flow, as a sibling of it. Leave the built-in Kerberos execution {@code DISABLED}.
 */
public class SpnegoButtonAuthenticator extends SpnegoAuthenticator {

    private static final Logger logger = Logger.getLogger(SpnegoButtonAuthenticator.class);

    /** Auth session note that marks "user asked for Kerberos, challenge on the next GET". */
    public static final String REQUESTED_NOTE = "sit.spnego-button.requested";

    public static final SpnegoButtonAuthenticator SINGLETON = new SpnegoButtonAuthenticator();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        HttpRequest request = context.getHttpRequest();
        String authHeader = request.getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null) {
            // The browser answered a challenge. Validate like the built-in authenticator.
            logger.trace("Authorization header present, validating SPNEGO token");
            authSession.removeAuthNote(REQUESTED_NOTE);
            super.authenticate(context);
            if (context.getStatus() == FlowStatus.FAILED || context.getStatus() == FlowStatus.ATTEMPTED) {
                // Siblings were skipped for this attempt; without a reset the flow would have
                // nothing left to offer. Back to the password form instead.
                logger.debug("SPNEGO token rejected, resetting flow to the login form");
                context.resetFlow();
            }
            return;
        }

        if (isSelectedViaButton(request)) {
            // Phase 1: the user clicked the button. Start over, skip the siblings so that the
            // next pass lands here, remember the request, and move the browser onto a
            // code-less GET where a 401 retry is safe.
            logger.debug("Kerberos requested via authentication selection, resetting flow and redirecting to refresh URL");
            AuthenticationProcessor.resetFlow(authSession, context.getFlowPath());
            skipSiblings(context);
            authSession.setAuthNote(REQUESTED_NOTE, "true");
            context.challenge(Response.seeOther(context.getRefreshUrl(false)).build());
            return;
        }

        if (Boolean.parseBoolean(authSession.getAuthNote(REQUESTED_NOTE))) {
            // Phase 2: GET after the redirect. The built-in implementation sends 401 Negotiate
            // (with the auto-submitting fallback form, as the execution is ALTERNATIVE).
            logger.debug("Kerberos requested, sending SPNEGO challenge");
            super.authenticate(context);
            return;
        }

        // Reached without a request (e.g. placed before the form): stay silent.
        logger.trace("Kerberos not requested, skipping");
        context.attempted();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Reached through the fallback form in the 401 body (browser had no ticket) or any
        // other POST to this execution. The siblings are still marked as skipped, so start
        // over: the password form renders and this execution is offered again.
        context.getAuthenticationSession().removeAuthNote(REQUESTED_NOTE);
        context.resetFlow();
    }

    /**
     * Marks every other execution of the parent flow as attempted, so that the next pass of
     * the flow engine skips them and reaches this execution.
     */
    static void skipSiblings(AuthenticationFlowContext context) {
        AuthenticationExecutionModel self = context.getExecution();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        context.getRealm().getAuthenticationExecutionsStream(self.getParentFlow())
                .filter(e -> !e.getId().equals(self.getId()))
                .forEach(e -> authSession.setExecutionStatus(e.getId(), ExecutionStatus.ATTEMPTED));
    }

    /**
     * True for the POST the login page sends when the user picks this execution
     * ({@code authenticationExecution=<id>} in the form body).
     */
    static boolean isSelectedViaButton(HttpRequest request) {
        if (!HttpMethod.POST.equalsIgnoreCase(request.getHttpMethod())) {
            return false;
        }
        MultivaluedMap<String, String> form = request.getDecodedFormParameters();
        if (form == null) {
            return false;
        }
        String selected = form.getFirst(Constants.AUTHENTICATION_EXECUTION);
        return selected != null && !selected.isBlank();
    }
}
