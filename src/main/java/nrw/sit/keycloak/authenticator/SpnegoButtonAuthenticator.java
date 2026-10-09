package nrw.sit.keycloak.authenticator;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

import java.util.ArrayList;
import java.util.List;

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
 *
 * <p>To offer the button only under a condition (e.g. internal network), wrap it twice: an
 * {@code ALTERNATIVE} sub-flow after the forms, containing a {@code CONDITIONAL} sub-flow with
 * the condition(s) and this execution as {@code ALTERNATIVE}. A single {@code ALTERNATIVE} sub-flow
 * is not enough (Keycloak ignores conditions there), and a {@code CONDITIONAL} sub-flow directly
 * in the top-level flow would make Keycloak ignore all top-level alternatives.
 *
 * <h2>Safety rules</h2>
 * <ul>
 *   <li>Only {@code ALTERNATIVE} executions are skipped (the alternatives of each
 *       {@code ALTERNATIVE} on the path to the top-level flow). {@code REQUIRED} and
 *       {@code CONDITIONAL} steps are never skipped and run as usual, e.g. an OTP sub-flow after
 *       the first factor or an OTP form after the button. An {@code ALTERNATIVE} on the path next
 *       to a mandatory step (a placement Keycloak ignores) refuses the click.</li>
 *   <li>A click only counts if the selection names this very execution.</li>
 *   <li>An {@code Authorization} header is only evaluated after the user clicked the button;
 *       otherwise it is ignored.</li>
 * </ul>
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
        boolean requested = Boolean.parseBoolean(authSession.getAuthNote(REQUESTED_NOTE));
        String authHeader = request.getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && requested) {
            // The browser answered our challenge. Validate like the built-in authenticator.
            logger.trace("Authorization header present after a button click, validating SPNEGO token");
            authSession.removeAuthNote(REQUESTED_NOTE);
            authenticateWithToken(context, authHeader);
            if (context.getStatus() == FlowStatus.FAILED || context.getStatus() == FlowStatus.ATTEMPTED) {
                // Siblings were skipped for this attempt; without a reset the flow would have
                // nothing left to offer. Back to the password form instead.
                logger.debug("SPNEGO token rejected, resetting flow to the login form");
                context.resetFlow();
            }
            return;
        }
        if (authHeader != null) {
            // Kerberos only on demand: a header the user did not ask for is not evaluated.
            logger.trace("Authorization header without a button click, ignored");
        }

        if (isSelectedViaButton(request, context.getExecution())) {
            // Phase 1: the user clicked the button. Work out what to skip before touching the
            // session: if the flow has a mandatory sibling on the way up, refuse.
            List<String> skip = executionsToSkip(context.getSession(), context.getRealm(), context.getExecution());
            if (skip == null) {
                logger.warnf("Kerberos button in flow path '%s' refused: an ALTERNATIVE on its path sits next to a "
                        + "REQUIRED or CONDITIONAL step. Place it as described in the help text.", context.getFlowPath());
                context.attempted();
                return;
            }
            // Start over, skip the alternatives so that the next pass lands here, remember the
            // request, and move the browser onto a code-less GET where a 401 retry is safe.
            logger.debug("Kerberos requested via authentication selection, resetting flow and redirecting to refresh URL");
            AuthenticationProcessor.resetFlow(authSession, context.getFlowPath());
            skip.forEach(id -> authSession.setExecutionStatus(id, ExecutionStatus.ATTEMPTED));
            authSession.setAuthNote(REQUESTED_NOTE, "true");
            context.challenge(Response.seeOther(context.getRefreshUrl(false)).build());
            return;
        }

        if (requested) {
            // Phase 2: GET after the redirect: 401 Negotiate with Keycloak's auto-submitting
            // fallback form. Always the fallback variant, even if the execution was set to REQUIRED
            // through the admin API (the built-in code would send a dead-end error page then).
            logger.debug("Kerberos requested, sending SPNEGO challenge");
            context.forceChallenge(optionalChallengeRedirect(context, KerberosConstants.NEGOTIATE));
            return;
        }

        // Reached without a request (e.g. placed before the form): stay silent.
        logger.trace("Kerberos not requested, skipping");
        context.attempted();
    }

    /**
     * Validates the {@code Authorization} header the browser sent in reply to the challenge.
     * The default is the built-in behaviour ({@link SpnegoAuthenticator#authenticate});
     * subclasses can look at the ticket in more detail.
     */
    protected void authenticateWithToken(AuthenticationFlowContext context, String authHeader) {
        super.authenticate(context);
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
     * The executions that must be marked {@code ATTEMPTED} so that the next pass of the flow
     * engine reaches {@code self}: the {@code ALTERNATIVE} siblings of every {@code ALTERNATIVE}
     * execution on the way up to the top-level flow ({@code self} included). {@code REQUIRED} and
     * {@code CONDITIONAL} executions are never skipped; they run as usual. Condition
     * authenticators and disabled executions are ignored.
     *
     * @return the execution ids, or {@code null} if an {@code ALTERNATIVE} on the path sits next to
     *         a {@code REQUIRED} or {@code CONDITIONAL} step (a placement Keycloak ignores)
     */
    static List<String> executionsToSkip(KeycloakSession session, RealmModel realm, AuthenticationExecutionModel self) {
        List<String> skip = new ArrayList<>();
        AuthenticationExecutionModel current = self;
        while (true) {
            String parentFlowId = current.getParentFlow();
            // In a sequence (current REQUIRED/CONDITIONAL) nothing is skipped: the other steps
            // run as usual, e.g. an OTP sub-flow after the first factor.
            if (current.isAlternative()) {
                for (AuthenticationExecutionModel sibling : realm.getAuthenticationExecutionsStream(parentFlowId).toList()) {
                    if (sibling.getId().equals(current.getId()) || sibling.isDisabled() || isCondition(session, sibling)) {
                        continue;
                    }
                    if (!sibling.isAlternative()) {
                        // an alternative next to a mandatory step: Keycloak ignores the alternatives
                        // of such a flow, so this placement is wrong; never skip a mandatory step
                        return null;
                    }
                    skip.add(sibling.getId());
                }
            }
            AuthenticationFlowModel parentFlow = realm.getAuthenticationFlowById(parentFlowId);
            if (parentFlow == null) {
                return null;
            }
            if (parentFlow.isTopLevel()) {
                return skip;
            }
            current = realm.getAuthenticationExecutionByFlowId(parentFlowId);
            if (current == null) {
                return null;
            }
        }
    }

    private static boolean isCondition(KeycloakSession session, AuthenticationExecutionModel execution) {
        if (execution.isAuthenticatorFlow() || execution.getAuthenticator() == null) {
            return false;
        }
        AuthenticatorFactory factory = (AuthenticatorFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(org.keycloak.authentication.Authenticator.class, execution.getAuthenticator());
        return factory instanceof ConditionalAuthenticatorFactory;
    }

    /**
     * True for the POST the login page sends when the user picks <em>this</em> execution
     * ({@code authenticationExecution=<own id>} in the form body).
     */
    static boolean isSelectedViaButton(HttpRequest request, AuthenticationExecutionModel self) {
        if (!HttpMethod.POST.equalsIgnoreCase(request.getHttpMethod())) {
            return false;
        }
        MultivaluedMap<String, String> form = request.getDecodedFormParameters();
        if (form == null) {
            return false;
        }
        String selected = form.getFirst(Constants.AUTHENTICATION_EXECUTION);
        return selected != null && self != null && selected.equals(self.getId());
    }
}
