package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Arguments to {@code AxiamClient.cibaInitiate} (CONTRACT.md &sect;33.2
 * {@code CibaInitiateRequest}).
 *
 * <p>Exactly the members set are sent. {@code user_code}, {@code login_hint_token}
 * and {@code request_uri} are not members and have no setter: AXIAM refuses each
 * (&sect;33.3 rule 3). {@link CibaUserHint} holds exactly one hint, so both or
 * neither cannot be written. With a {@link #signer()} set, every member travels
 * inside the signed {@code request} and nothing else is sent beside it.
 *
 * <p>{@code binding_message} and {@code login_hint} can be personal data; this
 * SDK never logs them, and {@link #toString()} shows neither. The
 * notification token is {@link Sensitive} (&sect;33.5).
 */
public final class CibaInitiateRequest {

    private final String scope;
    private final CibaUserHint hint;
    private final @Nullable String bindingMessage;
    private final @Nullable Integer requestedExpiry;
    private final @Nullable String acrValues;
    private final @Nullable String resource;
    private final boolean pingMode;
    private final @Nullable Sensitive clientNotificationToken;
    private final @Nullable CibaRequestSigner signer;
    private final @Nullable UUID tenantId;
    private final @Nullable OidcConfiguration configuration;

    private CibaInitiateRequest(Builder b) {
        this.scope = b.scope;
        this.hint = b.hint;
        this.bindingMessage = b.bindingMessage;
        this.requestedExpiry = b.requestedExpiry;
        this.acrValues = b.acrValues;
        this.resource = b.resource;
        this.pingMode = b.pingMode;
        this.clientNotificationToken = b.clientNotificationToken;
        this.signer = b.signer;
        this.tenantId = b.tenantId;
        this.configuration = b.configuration;
    }

    /**
     * Starts a poll-mode, unsigned request.
     *
     * @param scope space-separated; must include {@code openid}
     * @param hint  whom to authenticate
     * @return a builder
     */
    public static Builder builder(String scope, CibaUserHint hint) {
        return new Builder(scope, hint);
    }

    /** {@return the space-separated scope} */
    public String scope() {
        return scope;
    }

    /** {@return the user hint} */
    public CibaUserHint hint() {
        return hint;
    }

    /** {@return the binding message, or {@code null}} */
    public @Nullable String bindingMessage() {
        return bindingMessage;
    }

    /** {@return the requested lifetime in seconds, or {@code null}} */
    public @Nullable Integer requestedExpiry() {
        return requestedExpiry;
    }

    /** {@return the space-separated ACR values, or {@code null}} */
    public @Nullable String acrValues() {
        return acrValues;
    }

    /** {@return the RFC 8707 resource, or {@code null}} */
    public @Nullable String resource() {
        return resource;
    }

    /** {@return whether the client registered ping mode} */
    public boolean pingMode() {
        return pingMode;
    }

    /** {@return the ping bearer, or {@code null} in poll mode} */
    public @Nullable Sensitive clientNotificationToken() {
        return clientNotificationToken;
    }

    /** {@return the signer for the signed form, or {@code null} for the plain form} */
    public @Nullable CibaRequestSigner signer() {
        return signer;
    }

    /** {@return the tenant for the {@code tenant_id} query parameter, or {@code null} for the client's} */
    public @Nullable UUID tenantId() {
        return tenantId;
    }

    /** {@return a pre-fetched discovery document, or {@code null} to discover} */
    public @Nullable OidcConfiguration configuration() {
        return configuration;
    }

    /**
     * The authentication-request members, exactly those set, in their JSON
     * types: {@code requested_expiry} is a number here (inside a signed
     * request) and is sent as a string on the plain form.
     *
     * @return the members, in a stable order
     */
    public Map<String, Object> members() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("scope", scope);
        out.put(hint.member(), hint.value());
        if (bindingMessage != null) {
            out.put("binding_message", bindingMessage);
        }
        if (requestedExpiry != null) {
            out.put("requested_expiry", requestedExpiry);
        }
        if (acrValues != null) {
            out.put("acr_values", acrValues);
        }
        if (resource != null) {
            out.put("resource", resource);
        }
        if (pingMode && clientNotificationToken != null) {
            out.put("client_notification_token", clientNotificationToken.expose());
        }
        return out;
    }

    @Override
    public String toString() {
        return "CibaInitiateRequest[scope=" + scope + ", hint=" + hint + ", mode=" + (pingMode ? "ping" : "poll")
                + ", signed=" + (signer != null) + "]";
    }

    /** Builds a {@link CibaInitiateRequest}. */
    public static final class Builder {
        private final String scope;
        private final CibaUserHint hint;
        private @Nullable String bindingMessage;
        private @Nullable Integer requestedExpiry;
        private @Nullable String acrValues;
        private @Nullable String resource;
        private boolean pingMode;
        private @Nullable Sensitive clientNotificationToken;
        private @Nullable CibaRequestSigner signer;
        private @Nullable UUID tenantId;
        private @Nullable OidcConfiguration configuration;

        private Builder(String scope, CibaUserHint hint) {
            this.scope = Objects.requireNonNull(scope, "scope");
            this.hint = Objects.requireNonNull(hint, "hint");
        }

        /**
         * Shown to the user on the approval page &mdash; what lets them tell the
         * request they started from one an attacker did. Required for a
         * {@code fapi2} client.
         *
         * @param value at most 64 printable characters (the server's bound)
         * @return this builder
         */
        public Builder bindingMessage(String value) {
            this.bindingMessage = value;
            return this;
        }

        /**
         * The requested lifetime, 30&ndash;600 s (absent: 300). Not pre-checked:
         * the server's bounds are the authority.
         *
         * @param seconds the lifetime in seconds
         * @return this builder
         */
        public Builder requestedExpiry(int seconds) {
            this.requestedExpiry = seconds;
            return this;
        }

        /**
         * Space-separated authentication context classes; a class the approving
         * session has not achieved makes the user step up first.
         *
         * @param value the ACR values
         * @return this builder
         */
        public Builder acrValues(String value) {
            this.acrValues = value;
            return this;
        }

        /**
         * The RFC 8707 resource indicator.
         *
         * @param value the resource
         * @return this builder
         */
        public Builder resource(String value) {
            this.resource = value;
            return this;
        }

        /**
         * Ping mode, as registered: AXIAM pings the client's notification
         * endpoint presenting {@code clientNotificationToken} as a bearer. Keep the
         * token to check the ping with {@code cibaHandlePing}; it is never
         * returned by AXIAM. A missing or empty token is refused at
         * {@code cibaInitiate}, before any request.
         *
         * @param clientNotificationToken the ping bearer
         * @return this builder
         */
        public Builder pingMode(@Nullable Sensitive clientNotificationToken) {
            this.pingMode = true;
            this.clientNotificationToken = clientNotificationToken;
            return this;
        }

        /**
         * Sends the request as one signed JWT ({@code request}) &mdash; required of
         * a client that registered a signing algorithm, refused from one that did
         * not.
         *
         * @param value the signer
         * @return this builder
         */
        public Builder signer(CibaRequestSigner value) {
            this.signer = Objects.requireNonNull(value, "signer");
            return this;
        }

        /**
         * The tenant for the {@code tenant_id} query parameter (&sect;12.1 note 2).
         *
         * @param value the tenant
         * @return this builder
         */
        public Builder tenantId(UUID value) {
            this.tenantId = value;
            return this;
        }

        /**
         * A pre-fetched discovery document.
         *
         * @param value the document
         * @return this builder
         */
        public Builder configuration(OidcConfiguration value) {
            this.configuration = value;
            return this;
        }

        /**
         * Builds the request.
         *
         * @return the request
         */
        public CibaInitiateRequest build() {
            return new CibaInitiateRequest(this);
        }
    }
}
