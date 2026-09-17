package io.axiam.sdk.mcp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * The RFC 9728 &sect;2 document, carrying <strong>at most</strong> the five
 * members CONTRACT.md &sect;28.2 permits, in that order, and no others
 * (&sect;28.2).
 *
 * <p>Member names are the wire names: this record serializes to the document
 * byte for byte. RFC 9728 defines further members; &sect;28.2 forbids
 * emitting them in this contract version &mdash; a member one SDK emits and
 * ten do not is a divergence the cross-SDK review would have to reconcile.
 *
 * <p>Two members are <strong>omitted rather than emitted empty or
 * {@code null}</strong>: {@link #scopesSupported()} when the caller passed no
 * scopes, and {@link #resourceDocumentation()} when the caller passed none
 * &mdash; {@link JsonInclude.Include#NON_EMPTY} does both, since it excludes
 * a {@code null} value and an empty collection alike.
 *
 * @param resource the resource identifier this server publishes for itself
 *                 &mdash; the string an RFC 8707 {@code resource} parameter
 *                 carries and the {@code aud} the guard checks
 * @param authorizationServers the issuer identifiers of the authorization
 *                             servers that guard this resource; at least one,
 *                             each verbatim
 * @param scopesSupported the scope tokens this resource server understands,
 *                        in the caller's order; omitted when the caller
 *                        passed none
 * @param bearerMethodsSupported always {@code ["header"]} in this contract
 *                              version &mdash; &sect;10's guard reads a
 *                              bearer credential from the
 *                              {@code Authorization} header alone
 * @param resourceDocumentation a human-readable documentation page; omitted
 *                             when the caller passed none, never {@code null}
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ProtectedResourceMetadataDocument(
        String resource,
        @JsonProperty("authorization_servers") List<String> authorizationServers,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("bearer_methods_supported") List<String> bearerMethodsSupported,
        @JsonProperty("resource_documentation") @Nullable String resourceDocumentation) {

    /**
     * Copies every list defensively so the document is immutable once built.
     *
     * @param resource the resource identifier
     * @param authorizationServers the authorization server issuer identifiers
     * @param scopesSupported the supported scope tokens
     * @param bearerMethodsSupported always {@code ["header"]}
     * @param resourceDocumentation the documentation page, or {@code null}
     */
    public ProtectedResourceMetadataDocument {
        authorizationServers = List.copyOf(authorizationServers);
        scopesSupported = List.copyOf(scopesSupported);
        bearerMethodsSupported = List.copyOf(bearerMethodsSupported);
    }
}
