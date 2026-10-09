package nrw.sit.keycloak.authenticator;

import jakarta.ws.rs.core.Response;
import nrw.sit.keycloak.kerberos.AuthzCapturingSpnegoAuthenticator;
import nrw.sit.keycloak.kerberos.KerberosChecksum;
import nrw.sit.keycloak.kerberos.TicketLevelEvaluator;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.events.Errors;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.federation.kerberos.KerberosConfig;
import org.keycloak.federation.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.IntFunction;

/**
 * {@link SpnegoButtonAuthenticator} that additionally reads the accepted ticket's
 * authorization data and sets the level of authentication (ACR) from it:
 * a configured Authentication Mechanism Assurance group SID in the (signature-verified)
 * Windows PAC, or an RFC 8129 authentication indicator, yields the "matched" level
 * (default 2, silver), anything else the default level (default 1, bronze).
 *
 * Ticket validation itself is still Keycloak's: this class runs Keycloak's own
 * {@code SPNEGOAuthenticator} (JAAS login with the keytab of the realm's Kerberos-enabled
 * user storage provider, GSS-API accept) and then hands the already-authenticated context
 * to the user storage providers through {@link KerberosConstants#AUTHENTICATED_SPNEGO_CONTEXT},
 * exactly the path Keycloak uses for provider chains, so the token is accepted only once
 * (replay cache) and user lookup is unchanged.
 */
public class SpnegoLevelAuthenticator extends SpnegoButtonAuthenticator {

    private static final Logger logger = Logger.getLogger(SpnegoLevelAuthenticator.class);

    public static final SpnegoLevelAuthenticator SINGLETON = new SpnegoLevelAuthenticator();

    static final String CONF_AMA_SIDS = "ama.group.sids";
    static final String CONF_INDICATORS = "auth.indicators";
    static final String CONF_LEVEL_MATCHED = "level.matched";
    static final String CONF_LEVEL_DEFAULT = "level.default";
    static final int DEFAULT_LEVEL_MATCHED = 2;
    static final int DEFAULT_LEVEL_DEFAULT = 1;

    /** User session note with the evidence the level was based on (for mappers and audits). */
    public static final String EVIDENCE_NOTE = "sit.kerberos.evidence";
    /** User session note with the level that was set. */
    public static final String LEVEL_NOTE = "sit.kerberos.level";

    @Override
    protected void authenticateWithToken(AuthenticationFlowContext context, String authHeader) {
        String[] tokens = authHeader.split(" ");
        if (tokens.length == 0 || !KerberosConstants.NEGOTIATE.equalsIgnoreCase(tokens[0])) {
            logger.debugf("Unknown authorization scheme %s", tokens.length > 0 ? tokens[0] : "");
            context.attempted();
            return;
        }
        if (tokens.length != 2) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }
        String spnegoToken = tokens[1];
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        CommonKerberosConfig kerberosConfig = findKerberosConfig(realm);
        if (kerberosConfig == null) {
            logger.warn("Received kerberos token, but the realm has no user storage provider with Kerberos authentication enabled");
            context.attempted();
            return;
        }

        AuthzCapturingSpnegoAuthenticator spnego = createSpnegoAuthenticator(kerberosConfig, spnegoToken);
        spnego.authenticate();

        if (!spnego.isAuthenticated()) {
            if (spnego.getResponseToken() != null) {
                // multi-round SPNEGO handshake, same as the built-in authenticator
                logger.trace("SPNEGO handshake continues");
                Response challenge = optionalChallengeRedirect(context,
                        KerberosConstants.NEGOTIATE + " " + spnego.getResponseToken());
                context.challenge(challenge);
                return;
            }
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        // User lookup by the storage providers, with the acceptance already done (no second
        // GSS accept: the Kerberos replay cache would reject it).
        UserCredentialModel credential = UserCredentialModel.kerberos(spnegoToken);
        credential.setNote(KerberosConstants.AUTHENTICATED_SPNEGO_CONTEXT, spnego);
        CredentialValidationOutput output = session.users().getUserByCredential(realm, credential);

        if (output == null || output.getAuthStatus() != CredentialValidationOutput.Status.AUTHENTICATED) {
            logger.warnf("Kerberos principal %s authenticated, but no user storage provider could look up the user",
                    spnego.getAuthenticatedKerberosPrincipal());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        TicketLevelEvaluator.Result result = TicketLevelEvaluator.evaluate(
                readConfig(context.getAuthenticatorConfig()), spnego.getAuthzData(), serviceKeys(kerberosConfig));
        for (String warning : result.warnings) {
            logger.warnf("Kerberos ticket of %s: %s", spnego.getAuthenticatedKerberosPrincipal(), warning);
        }
        if (!spnego.isAuthzDataAvailable()) {
            logger.warn("Ticket authorization data not available from the JDK; level falls back to the default");
        }

        context.setUser(output.getAuthenticatedUser());
        if (output.getState() != null) {
            for (Map.Entry<String, String> entry : output.getState().entrySet()) {
                context.getAuthenticationSession().setUserSessionNote(entry.getKey(), entry.getValue());
            }
        }
        context.getAuthenticationSession().setUserSessionNote(LEVEL_NOTE, Integer.toString(result.level));
        context.getAuthenticationSession().setUserSessionNote(EVIDENCE_NOTE, String.join(",", result.evidence));
        new AcrStore(session, context.getAuthenticationSession()).setLevelAuthenticated(result.level);
        logger.infof("Kerberos login of %s: level %d%s", spnego.getAuthenticatedKerberosPrincipal(), result.level,
                result.matched() ? " (" + String.join(", ", result.evidence) + ")" : "");

        context.success(UserCredentialModel.KERBEROS);
    }

    /** Overridable for tests. */
    protected AuthzCapturingSpnegoAuthenticator createSpnegoAuthenticator(CommonKerberosConfig config, String token) {
        return new AuthzCapturingSpnegoAuthenticator(config, new KerberosServerSubjectAuthenticator(config), token);
    }

    /**
     * The Kerberos settings of the realm: the first enabled user storage provider (by priority)
     * that is either a Kerberos provider or an LDAP provider with Kerberos authentication on.
     */
    static CommonKerberosConfig findKerberosConfig(RealmModel realm) {
        return realm.getComponentsStream(realm.getId(), UserStorageProvider.class.getName())
                .map(UserStorageProviderModel::new)
                .filter(UserStorageProviderModel::isEnabled)
                .sorted(UserStorageProviderModel.comparator)
                .map(SpnegoLevelAuthenticator::toKerberosConfig)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    private static CommonKerberosConfig toKerberosConfig(UserStorageProviderModel model) {
        if ("kerberos".equals(model.getProviderId())) {
            return new KerberosConfig(model);
        }
        if ("ldap".equals(model.getProviderId())) {
            LDAPProviderKerberosConfig config = new LDAPProviderKerberosConfig(model);
            return config.isAllowKerberosAuthentication() ? config : null;
        }
        return null;
    }

    /** The service keys from the keytab, by checksum type, for the PAC signature check. */
    static IntFunction<byte[]> serviceKeys(CommonKerberosConfig config) {
        return checksumType -> {
            try {
                KeyTab keyTab = KeyTab.getInstance(new File(config.getKeyTab()));
                for (KerberosKey key : keyTab.getKeys(new KerberosPrincipal(config.getServerPrincipal()))) {
                    if (KerberosChecksum.checksumTypeFor(key.getKeyType()) == checksumType) {
                        return key.getEncoded();
                    }
                }
            } catch (RuntimeException e) {
                logger.warnf(e, "Cannot read service keys from keytab %s", config.getKeyTab());
            }
            return null;
        };
    }

    static TicketLevelEvaluator.Config readConfig(AuthenticatorConfigModel model) {
        Map<String, String> cfg = model != null && model.getConfig() != null ? model.getConfig() : Map.of();
        return new TicketLevelEvaluator.Config(
                split(cfg.get(CONF_AMA_SIDS)),
                split(cfg.get(CONF_INDICATORS)),
                intValue(cfg.get(CONF_LEVEL_MATCHED), DEFAULT_LEVEL_MATCHED),
                intValue(cfg.get(CONF_LEVEL_DEFAULT), DEFAULT_LEVEL_DEFAULT));
    }

    private static Set<String> split(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return new HashSet<>(Arrays.asList(value.split("[,;\\s]+")));
    }

    private static int intValue(String value, int fallback) {
        try {
            return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            logger.warnf("Invalid level '%s', using %d", value, fallback);
            return fallback;
        }
    }
}
