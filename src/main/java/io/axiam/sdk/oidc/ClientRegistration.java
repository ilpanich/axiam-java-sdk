package io.axiam.sdk.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.NetworkError;

import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An RFC 7591 &sect;3.2.1 / RFC 7592 &sect;3 client information response
 * (CONTRACT.md &sect;28.12.1) &mdash; what
 * {@code AxiamClient.readClientRegistration} and
 * {@code updateClientRegistration} return, and what
 * {@code updateClientRegistration} takes as the replacement.
 *
 * <p><strong>{@code registrationAccessToken} and {@code clientSecret} are
 * {@link Sensitive}</strong> (&sect;28.12.4): {@link #toString()} and every
 * Jackson rendering show {@code [SENSITIVE]} for both.
 *
 * <p><strong>Decoded tolerantly, and nothing is dropped.</strong> RFC 7591
 * &sect;3.2.1 lets a server add members, and because an update is a
 * <em>full replacement</em>, a member a read returned and an update left out is
 * a member the server deletes. Every member this type does not name &mdash; the
 * CIBA {@code backchannel_*} members, for instance &mdash; is kept verbatim in
 * {@link #extra()}, so passing a read's result straight back to an update sends
 * it back intact.
 *
 * <p>Change a member with {@link #toBuilder()}:
 * <pre>{@code
 * ClientRegistration current = client.readClientRegistration(uri, token);
 * ClientRegistration updated = client.updateClientRegistration(uri, token,
 *         current.toBuilder().clientName("Agent v2").build());
 * }</pre>
 *
 * @param clientId                the client's {@code client_id}
 * @param clientIdIssuedAt        when the id was issued (seconds since the epoch); never sent on an update
 * @param clientName              the registered display name
 * @param redirectUris            the registered redirect URIs
 * @param grantTypes              the registered grant types
 * @param responseTypes           the registered response types
 * @param tokenEndpointAuthMethod how the client authenticates; the server refuses an update that changes it
 * @param scope                   the registered scope, space-separated
 * @param registrationClientUri   where this registration is read, replaced and deleted; never sent on an update
 * @param clientSecretExpiresAt   when the client secret expires ({@code 0} = never); never sent on an update
 * @param jwks                    the client's JWK Set, for a {@code private_key_jwt} client
 * @param jwksUri                 where the client's JWK Set is published
 * @param clientSecret            the client secret &mdash; on the registration response only, never on a read or an update; never sent back
 * @param registrationAccessToken the registration access token &mdash; on the registration response and, <strong>rotated</strong>, on every update response; absent on a read; never sent in a body
 * @param extra                   every other member of the response, verbatim
 */
public record ClientRegistration(
        String clientId,
        @Nullable Long clientIdIssuedAt,
        @Nullable String clientName,
        List<String> redirectUris,
        List<String> grantTypes,
        List<String> responseTypes,
        @Nullable String tokenEndpointAuthMethod,
        @Nullable String scope,
        @Nullable String registrationClientUri,
        @Nullable Long clientSecretExpiresAt,
        @Nullable JsonNode jwks,
        @Nullable String jwksUri,
        @Nullable Sensitive clientSecret,
        @Nullable Sensitive registrationAccessToken,
        Map<String, JsonNode> extra) {

    /** The members an update never sends (&sect;28.12.2 rule 4). */
    static final List<String> SERVER_STATED_MEMBERS = List.of(
            "registration_access_token",
            "registration_client_uri",
            "client_secret_expires_at",
            "client_id_issued_at",
            "client_secret");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Copies every collection, so the value is immutable.
     *
     * @param clientId                the client's {@code client_id}
     * @param clientIdIssuedAt        when the id was issued
     * @param clientName              the registered display name
     * @param redirectUris            the registered redirect URIs
     * @param grantTypes              the registered grant types
     * @param responseTypes           the registered response types
     * @param tokenEndpointAuthMethod how the client authenticates
     * @param scope                   the registered scope
     * @param registrationClientUri   where this registration lives
     * @param clientSecretExpiresAt   when the client secret expires
     * @param jwks                    the client's JWK Set
     * @param jwksUri                 where the client's JWK Set is published
     * @param clientSecret            the client secret
     * @param registrationAccessToken the registration access token
     * @param extra                   every other member, verbatim
     */
    public ClientRegistration {
        Objects.requireNonNull(clientId, "clientId");
        redirectUris = List.copyOf(redirectUris);
        grantTypes = List.copyOf(grantTypes);
        responseTypes = List.copyOf(responseTypes);
        extra = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(extra));
    }

    /**
     * Starts a registration for {@code clientId} with every other member unset.
     *
     * @param clientId the client's {@code client_id}
     * @return a builder
     */
    public static Builder builder(String clientId) {
        return new Builder(clientId);
    }

    /**
     * A builder carrying every member of this registration, {@link #extra()}
     * included &mdash; the read-modify-write form an update wants.
     *
     * @return a builder seeded from this value
     */
    public Builder toBuilder() {
        Builder b = new Builder(clientId);
        b.clientIdIssuedAt = clientIdIssuedAt;
        b.clientName = clientName;
        b.redirectUris = redirectUris;
        b.grantTypes = grantTypes;
        b.responseTypes = responseTypes;
        b.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        b.scope = scope;
        b.registrationClientUri = registrationClientUri;
        b.clientSecretExpiresAt = clientSecretExpiresAt;
        b.jwks = jwks;
        b.jwksUri = jwksUri;
        b.clientSecret = clientSecret;
        b.registrationAccessToken = registrationAccessToken;
        b.extra = new LinkedHashMap<>(extra);
        return b;
    }

    /**
     * Decodes a client information response, tolerating unknown members.
     *
     * <p>A member of an unexpected type is kept in {@link #extra()} rather
     * than dropped: a replacement must not lose what the server holds.
     *
     * @param wire the response body
     * @return the decoded registration
     * @throws NetworkError if the body is not a JSON object or carries no {@code client_id}
     */
    public static ClientRegistration fromJson(JsonNode wire) {
        if (wire == null || !wire.isObject()) {
            throw new NetworkError("client registration response is not a JSON object");
        }
        Map<String, JsonNode> rest = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> e : wire.properties()) {
            rest.put(e.getKey(), e.getValue());
        }
        String clientId = takeString(rest, "client_id");
        if (clientId == null) {
            throw new NetworkError("client registration response carries no client_id");
        }
        Long issuedAt = takeLong(rest, "client_id_issued_at");
        String name = takeString(rest, "client_name");
        List<String> redirects = takeList(rest, "redirect_uris");
        List<String> grants = takeList(rest, "grant_types");
        List<String> responses = takeList(rest, "response_types");
        String authMethod = takeString(rest, "token_endpoint_auth_method");
        String scope = takeString(rest, "scope");
        String uri = takeString(rest, "registration_client_uri");
        Long secretExpires = takeLong(rest, "client_secret_expires_at");
        JsonNode jwks = rest.remove("jwks");
        if (jwks != null && jwks.isNull()) {
            jwks = null;
        }
        String jwksUri = takeString(rest, "jwks_uri");
        String secret = takeString(rest, "client_secret");
        String token = takeString(rest, "registration_access_token");
        return new ClientRegistration(clientId, issuedAt, name, redirects, grants, responses,
                authMethod, scope, uri, secretExpires, jwks, jwksUri,
                secret == null ? null : Sensitive.of(secret),
                token == null ? null : Sensitive.of(token),
                rest);
    }

    /**
     * The RFC 7592 &sect;2.2 replacement body (&sect;28.12.2 rule 4): every
     * member, {@link #extra()} included, except the five the server states
     * &mdash; {@code registration_access_token}, {@code registration_client_uri},
     * {@code client_secret_expires_at}, {@code client_id_issued_at} and
     * {@code client_secret} &mdash; with {@code client_id} set to this
     * registration's own.
     *
     * @return the JSON body an update sends
     */
    public ObjectNode updateBody() {
        ObjectNode body = MAPPER.createObjectNode();
        extra.forEach(body::set);
        for (String member : SERVER_STATED_MEMBERS) {
            body.remove(member);
        }
        body.put("client_id", clientId);
        if (clientName != null) {
            body.put("client_name", clientName);
        }
        body.set("redirect_uris", list(redirectUris));
        body.set("grant_types", list(grantTypes));
        body.set("response_types", list(responseTypes));
        if (tokenEndpointAuthMethod != null) {
            body.put("token_endpoint_auth_method", tokenEndpointAuthMethod);
        }
        if (scope != null) {
            body.put("scope", scope);
        }
        if (jwks != null) {
            body.set("jwks", jwks);
        }
        if (jwksUri != null) {
            body.put("jwks_uri", jwksUri);
        }
        return body;
    }

    private static ArrayNode list(List<String> items) {
        ArrayNode array = MAPPER.createArrayNode();
        items.forEach(array::add);
        return array;
    }

    private static @Nullable String takeString(Map<String, JsonNode> map, String key) {
        JsonNode node = map.get(key);
        if (node == null || node.isNull()) {
            map.remove(key);
            return null;
        }
        if (node.isTextual()) {
            map.remove(key);
            return node.asText();
        }
        return null;
    }

    private static @Nullable Long takeLong(Map<String, JsonNode> map, String key) {
        JsonNode node = map.get(key);
        if (node == null || node.isNull()) {
            map.remove(key);
            return null;
        }
        if (node.isIntegralNumber() && node.canConvertToLong()) {
            map.remove(key);
            return node.asLong();
        }
        return null;
    }

    private static List<String> takeList(Map<String, JsonNode> map, String key) {
        JsonNode node = map.get(key);
        List<String> out = new ArrayList<>();
        if (node == null || node.isNull()) {
            map.remove(key);
            return out;
        }
        if (!node.isArray()) {
            return out;
        }
        map.remove(key);
        for (JsonNode item : node) {
            if (item.isTextual()) {
                out.add(item.asText());
            }
        }
        return out;
    }

    /** Builds a {@link ClientRegistration}; see {@link ClientRegistration#toBuilder()}. */
    public static final class Builder {
        private final String clientId;
        private @Nullable Long clientIdIssuedAt;
        private @Nullable String clientName;
        private List<String> redirectUris = List.of();
        private List<String> grantTypes = List.of();
        private List<String> responseTypes = List.of();
        private @Nullable String tokenEndpointAuthMethod;
        private @Nullable String scope;
        private @Nullable String registrationClientUri;
        private @Nullable Long clientSecretExpiresAt;
        private @Nullable JsonNode jwks;
        private @Nullable String jwksUri;
        private @Nullable Sensitive clientSecret;
        private @Nullable Sensitive registrationAccessToken;
        private Map<String, JsonNode> extra = new LinkedHashMap<>();

        private Builder(String clientId) {
            this.clientId = Objects.requireNonNull(clientId, "clientId");
        }

        /**
         * Sets {@code client_name}.
         *
         * @param value the display name, or {@code null} to drop it
         * @return this builder
         */
        public Builder clientName(@Nullable String value) {
            this.clientName = value;
            return this;
        }

        /**
         * Sets {@code redirect_uris}.
         *
         * @param value the redirect URIs
         * @return this builder
         */
        public Builder redirectUris(List<String> value) {
            this.redirectUris = List.copyOf(value);
            return this;
        }

        /**
         * Sets {@code grant_types}.
         *
         * @param value the grant types
         * @return this builder
         */
        public Builder grantTypes(List<String> value) {
            this.grantTypes = List.copyOf(value);
            return this;
        }

        /**
         * Sets {@code response_types}.
         *
         * @param value the response types
         * @return this builder
         */
        public Builder responseTypes(List<String> value) {
            this.responseTypes = List.copyOf(value);
            return this;
        }

        /**
         * Sets {@code token_endpoint_auth_method}.
         *
         * @param value the method, or {@code null}
         * @return this builder
         */
        public Builder tokenEndpointAuthMethod(@Nullable String value) {
            this.tokenEndpointAuthMethod = value;
            return this;
        }

        /**
         * Sets {@code scope}.
         *
         * @param value the space-separated scope, or {@code null}
         * @return this builder
         */
        public Builder scope(@Nullable String value) {
            this.scope = value;
            return this;
        }

        /**
         * Sets {@code jwks}.
         *
         * @param value the JWK Set, or {@code null}
         * @return this builder
         */
        public Builder jwks(@Nullable JsonNode value) {
            this.jwks = value;
            return this;
        }

        /**
         * Sets {@code jwks_uri}.
         *
         * @param value the JWK Set URI, or {@code null}
         * @return this builder
         */
        public Builder jwksUri(@Nullable String value) {
            this.jwksUri = value;
            return this;
        }

        /**
         * Sets, or with {@code null} removes, a member this type does not name.
         *
         * @param member the wire name
         * @param value  the value, or {@code null} to remove the member
         * @return this builder
         */
        public Builder extra(String member, @Nullable JsonNode value) {
            if (value == null) {
                extra.remove(member);
            } else {
                extra.put(member, value);
            }
            return this;
        }

        /**
         * Builds the registration.
         *
         * @return the registration
         */
        public ClientRegistration build() {
            return new ClientRegistration(clientId, clientIdIssuedAt, clientName, redirectUris,
                    grantTypes, responseTypes, tokenEndpointAuthMethod, scope, registrationClientUri,
                    clientSecretExpiresAt, jwks, jwksUri, clientSecret, registrationAccessToken, extra);
        }
    }
}
