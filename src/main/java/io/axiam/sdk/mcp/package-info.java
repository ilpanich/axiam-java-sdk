/**
 * MCP resource-server helpers (CONTRACT.md &sect;28, RFC 9728 + RFC 6750):
 * publishing the protected-resource metadata document that names the
 * authorization server guarding this resource, and building the
 * {@code WWW-Authenticate} challenge that starts an MCP client's discovery.
 *
 * <p>&sect;28.0: this SDK implements the <strong>resource server's</strong>
 * half and nothing else. AXIAM is the authorization server and implements
 * none of &sect;28; the MCP client's half (parsing a challenge, fetching a
 * document, deciding whether to trust the authorization server it names) is
 * deliberately not in this contract version.
 *
 * <p><strong>No operation here performs network I/O</strong>, so
 * &sect;16 (retry) and &sect;9 (single-flight refresh) do not apply and
 * nothing in this package touches the SDK client's own session. All three
 * canonical operations ({@link io.axiam.sdk.mcp.Mcp#protectedResourceMetadata}
 * and its overload, {@link io.axiam.sdk.mcp.Mcp#bearerChallenge} and its
 * overload) are pure local computation, like {@code oidcBegin} (&sect;12.1)
 * and {@code UmaChallenge.parse} (&sect;20.5).
 *
 * <p><strong>Nothing here is a source of truth about a token.</strong> The
 * document is a claim a resource server publishes about itself; the
 * challenge is a hint it gives a caller that already failed. Whether a
 * request is authorized stays &sect;10.1's and &sect;11's decision, unchanged
 * and unreachable from here.
 *
 * <p>This package is deliberately free of any Spring dependency: it is the
 * framework-independent half of &sect;28, so any Spring MVC (or other JVM
 * framework) integration can be built on it without forking the validation
 * logic. {@link io.axiam.sdk.spring.AxiamAuthenticationFilter},
 * {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor} and
 * {@link io.axiam.sdk.spring.AxiamProtectedResourceMetadataController} are
 * the Spring Boot wiring built on top of it.
 */
@NullMarked
package io.axiam.sdk.mcp;

import org.jspecify.annotations.NullMarked;
