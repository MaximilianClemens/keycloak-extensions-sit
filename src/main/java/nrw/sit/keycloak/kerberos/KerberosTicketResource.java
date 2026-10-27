package nrw.sit.keycloak.kerberos;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import nrw.sit.keycloak.authenticator.KerberosTicketAuthenticator;
import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;

/**
 * {@code GET /realms/<realm>/sit-kerberos/ticket?client_id=..&tab_id=..}
 *
 * <p>The SPNEGO round trip for {@link KerberosTicketAuthenticator}, run by the login page with
 * {@code fetch()} (same origin, so the browser handles {@code Negotiate} by itself):
 * <ol>
 *   <li>no {@code Authorization} header: {@code 401 WWW-Authenticate: Negotiate}; the browser
 *       retries with the ticket, or gives up (the page then shows no Kerberos option)</li>
 *   <li>{@code Authorization: Negotiate <token>}: validated with
 *       {@code users().getUserByCredential(realm, kerberos(token))}, the call the built-in
 *       {@code auth-spnego} makes; it ends in the Kerberos (or LDAP with Kerberos) user storage
 *       provider and its keytab</li>
 *   <li>valid: the user id, the time and the provider's state are recorded as auth notes of the
 *       caller's authentication session; {@code 200 {"ok":true}}</li>
 *   <li>otherwise {@code 403 {"ok":false,"reason":..}} ({@code invalid_ticket},
 *       {@code no_provider}), or another {@code 401 Negotiate} with the response token when the
 *       provider asks for one more round</li>
 * </ol>
 *
 * <p>The endpoint does not authenticate anybody: the notes are worthless without the ordinary
 * selection POST that follows, and that one carries Keycloak's {@code session_code}. A token is
 * only evaluated for a caller that has an authentication session for the given client and tab
 * (cookie {@code AUTH_SESSION_ID}); without one, {@code 403 no_auth_session} before any GSS work.
 */
@Path("")
public class KerberosTicketResource {

    private static final Logger logger = Logger.getLogger(KerberosTicketResource.class);

    static final String AUTH_METHOD = "sit-kerberos-ticket";

    private final KeycloakSession session;

    public KerberosTicketResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("ticket")
    @Produces(MediaType.APPLICATION_JSON)
    public Response ticket(@QueryParam("client_id") String clientId, @QueryParam("tab_id") String tabId) {
        RealmModel realm = session.getContext().getRealm();
        if (!Profile.isFeatureEnabled(Profile.Feature.KERBEROS)) {
            return json(Response.Status.NOT_FOUND, "kerberos_disabled", null);
        }
        if (clientId == null || tabId == null) {
            return json(Response.Status.BAD_REQUEST, "missing_parameter", null);
        }
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !client.isEnabled()) {
            return json(Response.Status.BAD_REQUEST, "unknown_client", null);
        }
        AuthenticationSessionModel authSession = currentAuthenticationSession(realm, client, tabId);
        if (authSession == null) {
            logger.debug("Kerberos ticket endpoint called without a matching authentication session");
            return json(Response.Status.FORBIDDEN, "no_auth_session", null);
        }

        String authHeader = session.getContext().getRequestHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            return challenge(null);
        }
        String[] tokens = authHeader.trim().split("\\s+");
        if (tokens.length != 2 || !KerberosConstants.NEGOTIATE.equalsIgnoreCase(tokens[0])) {
            logger.debugf("Kerberos ticket endpoint: unsupported Authorization scheme '%s'", tokens.length > 0 ? tokens[0] : "");
            return json(Response.Status.FORBIDDEN, "unsupported_scheme", null);
        }

        CredentialValidationOutput output = session.users().getUserByCredential(realm, UserCredentialModel.kerberos(tokens[1]));
        if (output == null) {
            logger.warn("Received kerberos token, but there is no user storage provider that handles kerberos credentials.");
            loginError(realm, client, Errors.INVALID_USER_CREDENTIALS);
            return json(Response.Status.FORBIDDEN, "no_provider", null);
        }
        switch (output.getAuthStatus()) {
            case AUTHENTICATED:
                authSession.setAuthNote(KerberosTicketAuthenticator.USER_NOTE, output.getAuthenticatedUser().getId());
                authSession.setAuthNote(KerberosTicketAuthenticator.TIME_NOTE, String.valueOf(Time.currentTime()));
                String state = serializeState(output.getState());
                if (state != null) {
                    authSession.setAuthNote(KerberosTicketAuthenticator.STATE_NOTE, state);
                } else {
                    authSession.removeAuthNote(KerberosTicketAuthenticator.STATE_NOTE);
                }
                logger.debugf("Kerberos ticket validated for user %s, recorded in the authentication session",
                        output.getAuthenticatedUser().getUsername());
                return json(Response.Status.OK, null, Map.of("ok", true));
            case CONTINUE:
                String responseToken = output.getState() == null ? null : output.getState().get(KerberosConstants.RESPONSE_TOKEN);
                return challenge(responseToken);
            default:
                loginError(realm, client, Errors.INVALID_USER_CREDENTIALS);
                return json(Response.Status.FORBIDDEN, "invalid_ticket", null);
        }
    }

    /** Records a rejected ticket as a LOGIN_ERROR event, like the built-in authenticator does. */
    protected void loginError(RealmModel realm, ClientModel client, String error) {
        new EventBuilder(realm, session, session.getContext().getConnection())
                .event(EventType.LOGIN)
                .client(client)
                .detail(Details.AUTH_METHOD, AUTH_METHOD)
                .error(error);
    }

    /** The caller's authentication session for the client and tab, or {@code null}. */
    protected AuthenticationSessionModel currentAuthenticationSession(RealmModel realm, ClientModel client, String tabId) {
        return new AuthenticationSessionManager(session).getCurrentAuthenticationSession(realm, client, tabId);
    }

    private static Response challenge(String responseToken) {
        String header = responseToken == null ? KerberosConstants.NEGOTIATE : KerberosConstants.NEGOTIATE + " " + responseToken;
        return noStore(Response.status(Response.Status.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, header)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(Map.of("ok", false, "reason", "negotiate"))).build();
    }

    private static Response json(Response.Status status, String reason, Map<String, Object> body) {
        Map<String, Object> entity = body != null ? body : Map.of("ok", false, "reason", reason);
        return noStore(Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(entity)).build();
    }

    private static Response.ResponseBuilder noStore(Response.ResponseBuilder builder) {
        return builder.header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
                .header("Pragma", "no-cache");
    }

    static String serializeState(Map<String, String> state) {
        if (state == null || state.isEmpty()) {
            return null;
        }
        try {
            return JsonSerialization.writeValueAsString(state);
        } catch (IOException e) {
            logger.warn("Could not serialize the Kerberos provider state, dropping it", e);
            return null;
        }
    }
}
