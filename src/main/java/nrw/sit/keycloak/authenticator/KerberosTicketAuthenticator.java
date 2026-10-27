package nrw.sit.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;

/**
 * Kerberos as a choice on the login page, without touching the flow engine.
 *
 * <p>The SPNEGO round trip ({@code 401 Negotiate}, browser retry with the ticket) does not
 * happen in the flow at all. The login page runs it against the realm endpoint
 * {@code /realms/<realm>/sit-kerberos/ticket} with {@code fetch()}; the endpoint validates the
 * ticket with Keycloak's Kerberos user storage provider (the same call the built-in
 * {@code auth-spnego} makes) and records the result in the browser's authentication session:
 * <ul>
 *   <li>{@value #USER_NOTE}: id of the user the ticket belongs to</li>
 *   <li>{@value #TIME_NOTE}: when the ticket was validated (seconds since the epoch)</li>
 *   <li>{@value #STATE_NOTE}: optional state the storage provider returned, as JSON; it becomes
 *       user session notes like with the built-in authenticator</li>
 * </ul>
 * The page then posts the ordinary "try another way" selection for this execution. Because the
 * ticket is already validated, {@link #authenticate} completes synchronously: no challenge, no
 * retried POST, no "page expired". Keycloak continues the flow as after any other successful
 * alternative (conditional OTP, required actions, redirect).
 *
 * <p>Without a note the execution reports <em>attempted</em>, so a stray selection falls back
 * to the password form. The notes are single use and expire after
 * {@link KerberosTicketAuthenticatorFactory#CONFIG_MAX_AGE_SECONDS max age} seconds. An
 * {@code Authorization} header on the flow request is never evaluated here.
 *
 * <p>Placement: {@code ALTERNATIVE} next to the password form (after it, so that the login page
 * lists it in {@code auth.authenticationSelections}). The jar ships
 * {@code theme-resources/templates/sit-kerberos-ticket.ftl} with the page-side part.
 */
public class KerberosTicketAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(KerberosTicketAuthenticator.class);

    /** Auth note: id of the user whose ticket the endpoint validated. */
    public static final String USER_NOTE = "sit.kerberos.ticket.user";
    /** Auth note: {@link Time#currentTime()} of the validation. */
    public static final String TIME_NOTE = "sit.kerberos.ticket.time";
    /** Auth note: JSON map of the storage provider's state (user session notes), may be absent. */
    public static final String STATE_NOTE = "sit.kerberos.ticket.state";

    private final int maxAgeSeconds;

    public KerberosTicketAuthenticator(int maxAgeSeconds) {
        this.maxAgeSeconds = maxAgeSeconds;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String userId = authSession.getAuthNote(USER_NOTE);
        if (userId == null) {
            logger.trace("No validated Kerberos ticket in this authentication session, skipping");
            context.attempted();
            return;
        }
        String time = authSession.getAuthNote(TIME_NOTE);
        String state = authSession.getAuthNote(STATE_NOTE);
        // single use, whatever the outcome
        authSession.removeAuthNote(USER_NOTE);
        authSession.removeAuthNote(TIME_NOTE);
        authSession.removeAuthNote(STATE_NOTE);

        if (!isFresh(time)) {
            logger.debugf("Validated Kerberos ticket is older than %d s, ignored", maxAgeSeconds);
            context.attempted();
            return;
        }
        UserModel user = context.getSession().users().getUserById(context.getRealm(), userId);
        if (user == null) {
            logger.warnf("Kerberos ticket was validated for user %s, who no longer exists", userId);
            context.attempted();
            return;
        }
        for (Map.Entry<String, String> entry : parseState(state).entrySet()) {
            authSession.setUserSessionNote(entry.getKey(), entry.getValue());
        }
        logger.debugf("Kerberos ticket validated by the login page, authenticating user %s", user.getUsername());
        context.setUser(user);
        context.success(UserCredentialModel.KERBEROS);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // This execution never challenges, so an action POST is not expected; treat it as a
        // selection without a validated ticket.
        context.attempted();
    }

    boolean isFresh(String time) {
        if (time == null) {
            return false;
        }
        try {
            long validated = Long.parseLong(time);
            long age = Time.currentTime() - validated;
            return age >= 0 && age <= maxAgeSeconds;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, String> parseState(String json) {
        if (json == null || json.isEmpty()) {
            return Map.of();
        }
        try {
            return JsonSerialization.readValue(json, Map.class);
        } catch (IOException e) {
            logger.warn("Ignoring unreadable Kerberos state note", e);
            return Map.of();
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Nothing to set up.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
