package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.mcp.Mcp;
import io.axiam.sdk.mcp.McpGuardChallenges;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.Objects;

/**
 * The CONTRACT.md &sect;28.4 "no credential presented" challenge, for the one
 * 401 {@link AxiamAuthenticationFilter} does not itself own.
 *
 * <p>{@link AxiamAuthenticationFilter} passes an unauthenticated request
 * through unchanged when it carries no credential at all &mdash; the request
 * may yet reach a route that permits anonymous access, and this filter has no
 * way to know in advance whether the eventual response will be a 401 or a
 * 200. Spring Security's own access-control layer decides that, and reports a
 * refusal through whichever {@link AuthenticationEntryPoint} the
 * application's {@code SecurityFilterChain} configures via
 * {@code exceptionHandling(handling -> handling.authenticationEntryPoint(...))}.
 * This class is that entry point: constructed with the <strong>same</strong>
 * {@link JwksVerifier} and {@code resourceMetadataUrl} as the filter, so the
 * two can never disagree about the challenge they emit, it writes the
 * identical &sect;10 JSON body ({@code {"error":"authentication_failed", …}})
 * plus the &sect;28.4 vector-1 {@code WWW-Authenticate} header (no
 * {@code error} parameter — RFC 6750 &sect;3 says not to name one when the
 * request carried no authentication information at all).
 *
 * <p>Only meaningful when &sect;28 is configured: unlike
 * {@link AxiamAuthenticationFilter}'s two-argument constructor, there is no
 * "off" form of this class &mdash; an application that has not opted into
 * &sect;28 simply never constructs or wires one.
 *
 * @see AxiamAuthenticationFilter#AxiamAuthenticationFilter(JwksVerifier, String, String)
 */
public final class AxiamMcpAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final McpGuardChallenges challenges;

    /**
     * Creates an entry point that emits the &sect;28.4 "no credential" challenge
     * derived from {@code jwksVerifier}'s configured expected audience.
     *
     * @param jwksVerifier        the SAME verifier passed to
     *                            {@link AxiamAuthenticationFilter} &mdash; its
     *                            {@link JwksVerifier.LocalVerificationPolicy#expectedAudience()}
     *                            is reused as the &sect;28.5 rule 2 expected
     *                            audience; &sect;28 adds no second option
     * @param resourceMetadataUrl the SAME URL passed to
     *                            {@link AxiamAuthenticationFilter}
     * @throws io.axiam.sdk.errors.ValidationError if {@code jwksVerifier}'s
     *         expected audience is not set (&sect;28.5 rule 2), or
     *         {@code resourceMetadataUrl} is outside &sect;28.4's syntax
     */
    public AxiamMcpAuthenticationEntryPoint(JwksVerifier jwksVerifier, String resourceMetadataUrl) {
        Objects.requireNonNull(jwksVerifier, "jwksVerifier");
        Objects.requireNonNull(resourceMetadataUrl, "resourceMetadataUrl");
        this.challenges = Objects.requireNonNull(Mcp.mcpGuardChallenges(
                resourceMetadataUrl, jwksVerifier.policy().expectedAudience(), "AxiamMcpAuthenticationEntryPoint"));
    }

    @Override
    public void commence(
            HttpServletRequest request, HttpServletResponse response, @Nullable AuthenticationException authException)
            throws IOException {
        // Spring Security invokes an AuthenticationEntryPoint only when no
        // authentication was ever established for this request — exactly
        // AxiamAuthenticationFilter's "no credential presented" pass-through
        // case, since a presented-but-rejected credential is answered by the
        // filter itself before this layer is ever reached. So this is always
        // §28.4 vector 1: no `error` parameter.
        response.setHeader("WWW-Authenticate", challenges.noCredential());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        ObjectNode body = MAPPER.createObjectNode();
        body.put("error", "authentication_failed");
        body.put("message", "authentication required");
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }
}
