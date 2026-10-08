package io.axiam.sdk.oidc;

import java.util.Objects;

/**
 * Whom a CIBA request authenticates: <strong>exactly one</strong> hint
 * (CONTRACT.md &sect;33.2). A sealed type, so sending both hints, or neither,
 * cannot be written. {@code login_hint_token} is not offered: AXIAM refuses it
 * (&sect;33.3 rule 3).
 *
 * <p>A hint can be personal data; this SDK never logs it, and
 * {@code toString()} names only the kind.
 */
public sealed interface CibaUserHint permits CibaUserHint.LoginHint, CibaUserHint.IdTokenHint {

    /**
     * A username, then an e-mail address, within the tenant ({@code login_hint}).
     *
     * @param value the hint
     * @return the hint
     */
    static CibaUserHint loginHint(String value) {
        return new LoginHint(value);
    }

    /**
     * An ID token this deployment issued to this client ({@code id_token_hint}).
     *
     * @param value the ID token
     * @return the hint
     */
    static CibaUserHint idTokenHint(String value) {
        return new IdTokenHint(value);
    }

    /** {@return the form member this hint is sent as} */
    String member();

    /** {@return the hint's value} */
    String value();

    /**
     * {@code login_hint}.
     *
     * @param value a username or e-mail address within the tenant
     */
    record LoginHint(String value) implements CibaUserHint {

        /**
         * Requires a value.
         *
         * @param value the hint
         */
        public LoginHint {
            Objects.requireNonNull(value, "value");
        }

        @Override
        public String member() {
            return "login_hint";
        }

        @Override
        public String toString() {
            return "LoginHint[...]";
        }
    }

    /**
     * {@code id_token_hint}.
     *
     * @param value an ID token this deployment issued to this client
     */
    record IdTokenHint(String value) implements CibaUserHint {

        /**
         * Requires a value.
         *
         * @param value the hint
         */
        public IdTokenHint {
            Objects.requireNonNull(value, "value");
        }

        @Override
        public String member() {
            return "id_token_hint";
        }

        @Override
        public String toString() {
            return "IdTokenHint[...]";
        }
    }
}
