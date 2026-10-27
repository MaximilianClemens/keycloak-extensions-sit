package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.InOrder;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The authenticator only consumes what the ticket endpoint recorded in the authentication
 * session; the auth notes are simulated with a map.
 */
class KerberosTicketAuthenticatorTest {

    private static final int MAX_AGE = 60;

    private final KerberosTicketAuthenticator authenticator = new KerberosTicketAuthenticator(MAX_AGE);

    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final UserProvider users = mock(UserProvider.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserModel alice = mock(UserModel.class);
    private final Map<String, String> notes = new HashMap<>();

    @BeforeEach
    void setUp() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(users);
        when(alice.getId()).thenReturn("alice-id");
        when(alice.getUsername()).thenReturn("alice");
        when(users.getUserById(realm, "alice-id")).thenReturn(alice);

        when(authSession.getAuthNote(anyString())).thenAnswer(inv -> notes.get(inv.<String>getArgument(0)));
        org.mockito.Mockito.doAnswer(inv -> notes.remove(inv.<String>getArgument(0)))
                .when(authSession).removeAuthNote(anyString());
    }

    @AfterEach
    void resetClock() {
        Time.setOffset(0);
    }

    private void recordTicket(String userId, long validatedAt) {
        notes.put(KerberosTicketAuthenticator.USER_NOTE, userId);
        notes.put(KerberosTicketAuthenticator.TIME_NOTE, String.valueOf(validatedAt));
    }

    @Test
    void freshTicketAuthenticatesTheUserAndConsumesTheNotes() {
        recordTicket("alice-id", Time.currentTime() - 5);

        authenticator.authenticate(context);

        InOrder order = inOrder(context);
        order.verify(context).setUser(alice);
        order.verify(context).success(UserCredentialModel.KERBEROS);
        verify(context, never()).attempted();
        assertTrue(notes.isEmpty(), "notes are single use: " + notes);
    }

    @Test
    void providerStateBecomesUserSessionNotes() {
        recordTicket("alice-id", Time.currentTime());
        notes.put(KerberosTicketAuthenticator.STATE_NOTE, "{\"krb.principal\":\"alice@EXAMPLE.TEST\",\"x\":\"y\"}");

        authenticator.authenticate(context);

        verify(authSession).setUserSessionNote("krb.principal", "alice@EXAMPLE.TEST");
        verify(authSession).setUserSessionNote("x", "y");
        verify(context).success(UserCredentialModel.KERBEROS);
    }

    @Test
    void withoutANoteTheExecutionIsAttempted() {
        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).setUser(any());
        verify(context, never()).success(anyString());
    }

    @Test
    void anExpiredTicketIsIgnoredAndStillConsumed() {
        recordTicket("alice-id", Time.currentTime() - MAX_AGE - 1);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).setUser(any());
        assertTrue(notes.isEmpty(), "an expired note must not survive: " + notes);
    }

    @Test
    void aTicketFromTheFutureIsIgnored() {
        recordTicket("alice-id", Time.currentTime() + 120);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).setUser(any());
    }

    @Test
    void aMissingOrUnreadableTimeIsIgnored() {
        notes.put(KerberosTicketAuthenticator.USER_NOTE, "alice-id");
        authenticator.authenticate(context);
        verify(context).attempted();

        notes.put(KerberosTicketAuthenticator.USER_NOTE, "alice-id");
        notes.put(KerberosTicketAuthenticator.TIME_NOTE, "yesterday");
        authenticator.authenticate(context);
        verify(context, org.mockito.Mockito.times(2)).attempted();
        verify(context, never()).setUser(any());
    }

    @Test
    void aVanishedUserIsAttempted() {
        recordTicket("ghost-id", Time.currentTime());

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).setUser(any());
        assertTrue(notes.isEmpty());
    }

    @Test
    void theClockOffsetCountsForFreshness() {
        recordTicket("alice-id", Time.currentTime());
        Time.setOffset(MAX_AGE + 5);

        authenticator.authenticate(context);

        verify(context).attempted();
    }

    @Test
    void actionIsNeverALogin() {
        recordTicket("alice-id", Time.currentTime());

        authenticator.action(context);

        verify(context).attempted();
        verify(context, never()).setUser(any());
    }

    @Test
    void unreadableStateIsDropped() {
        assertEquals(Map.of(), KerberosTicketAuthenticator.parseState("{not json"));
        assertEquals(Map.of(), KerberosTicketAuthenticator.parseState(null));
        assertEquals(Map.of("a", "b"), KerberosTicketAuthenticator.parseState("{\"a\":\"b\"}"));
    }

    @Test
    void doesNotRequireAUserAndIsAlwaysConfigured() {
        assertFalse(authenticator.requiresUser());
        assertTrue(authenticator.configuredFor(session, realm, alice));
    }
}
