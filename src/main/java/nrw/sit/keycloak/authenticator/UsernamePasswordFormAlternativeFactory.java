package nrw.sit.keycloak.authenticator;

import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;

/**
 * The built-in <em>Username Password Form</em> ({@code auth-username-password-form}) with
 * {@code ALTERNATIVE} as an additional requirement choice.
 *
 * The built-in factory only offers {@code REQUIRED}, so the form can only be one of several
 * first-factor options when it is wrapped in a sub-flow of its own:
 * <pre>
 * First factor (sub-flow)          REQUIRED
 * ├─ Password (sub-flow)           ALTERNATIVE   ← wrapper, only there for the requirement
 * │  └─ Username Password Form     REQUIRED
 * └─ Kerberos / Passkey / …        ALTERNATIVE
 * </pre>
 * With this provider the wrapper goes away:
 * <pre>
 * First factor (sub-flow)              REQUIRED
 * ├─ SIT: Username Password Form       ALTERNATIVE
 * └─ Kerberos / Passkey / …            ALTERNATIVE
 * </pre>
 *
 * Nothing else changes: same authenticator class ({@code UsernamePasswordForm}), same template,
 * same reference category ({@code password}), same optional passkey (conditional UI) category,
 * same brute-force handling. As {@code REQUIRED} it is identical to the built-in form.
 *
 * The texts for the "try another way" page ({@code <provider-id>-display-name} /
 * {@code -help-text}) ship in {@code theme-resources/messages} of this jar, because Keycloak
 * derives those message keys from the provider id.
 */
public class UsernamePasswordFormAlternativeFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "sit-auth-username-password-form";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.ALTERNATIVE,
            Requirement.DISABLED,
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "SIT: Username Password Form (alternative allowed)";
    }

    @Override
    public String getHelpText() {
        return "The built-in Username Password Form, which can also be used as ALTERNATIVE next to other "
                + "first-factor options (Kerberos, passkey, identity providers) without wrapping it in a "
                + "sub-flow of its own. As REQUIRED it behaves exactly like the built-in form.";
    }
}
