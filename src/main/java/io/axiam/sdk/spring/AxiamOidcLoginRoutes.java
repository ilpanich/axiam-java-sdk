package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcStateEntry;
import io.axiam.sdk.oidc.OidcStateStore;
import io.axiam.sdk.oidc.OidcTokenSet;

import org.jspecify.annotations.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;
import java.util.function.Consumer;

/**
 * "Login with AXIAM" Spring MVC route pair (CONTRACT.md &sect;12): a login
 * redirect and its callback, built as a {@link RouterFunction} over
 * {@link AxiamClient}'s &sect;12 {@code oidcDiscover}/{@code oidcBegin}/
 * {@code oidcExchange} operations plus an {@link OidcStateStore}.
 *
 * <p>Framework glue only — every piece of actual OIDC logic (discovery
 * caching, PKCE, ID-token validation, the &sect;9 refresh guard) lives on
 * {@link AxiamClient} and is reused here, never re-implemented. This class
 * is {@code compileOnly}-safe with respect to the OIDC core: {@link AxiamClient}
 * has no Spring dependency, so the core compiles and runs with Spring absent;
 * only this class (and {@link AxiamAutoConfiguration}'s opt-in wiring of it)
 * requires {@code spring-webmvc} on the classpath.
 *
 * <p>Use {@link #routes} directly for manual wiring, or opt into
 * {@link AxiamAutoConfiguration}'s zero-config registration via the
 * {@code axiam.oidc.enabled=true} property (CONTRACT.md &sect;12,
 * plan T5 item 2 "auto-configured only when the consumer opts in via
 * properties").
 *
 * <p>Failure mapping (framework-level, not CONTRACT.md-specified):
 * {@code 400 invalid_request} for a malformed callback; {@code 401
 * authentication_failed} for an IdP error, an unknown/expired/replayed
 * {@code state}, an ID-token failure, or an {@code OAuthProtocolError};
 * {@code 503 oidc_unavailable} for a network error. The caller's configured
 * {@code returnTo}/success-redirect destination is echoed back verbatim —
 * open-redirect protection of that value is explicitly the caller's
 * responsibility (it is never validated against an allowlist here).
 */
public final class AxiamOidcLoginRoutes {

    private static final Logger LOG = LoggerFactory.getLogger(AxiamOidcLoginRoutes.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AxiamOidcLoginRoutes() {
    }

    /**
     * Configuration for {@link #routes}.
     *
     * @param loginPath        the path that starts the login flow (redirects to the IdP); e.g. {@code "/oidc/login"}
     * @param callbackPath     the path AXIAM redirects back to after authentication; e.g. {@code "/oidc/callback"}
     * @param redirectUri      the relying party's registered redirect URI — the public URL of {@code callbackPath}; replayed verbatim on token exchange
     * @param scope            requested scope, space-separated, or {@code null} for the default ({@code openid})
     * @param successRedirect  where to send the browser after a successful login, or {@code null} to fall back to the {@code returnTo} captured at login time, then to a JSON summary
     * @param onSuccess        called with the validated token set once the exchange succeeds — the hook where an application establishes its OWN session; the SDK deliberately does not do this for you
     */
    public record Options(String loginPath, String callbackPath, String redirectUri, @Nullable String scope,
            @Nullable String successRedirect, @Nullable Consumer<OidcTokenSet> onSuccess) {

        /**
         * Convenience constructor with no {@link #scope()}, {@link #successRedirect()}, or {@link #onSuccess()}.
         *
         * @param loginPath    the path that starts the login flow
         * @param callbackPath the path AXIAM redirects back to
         * @param redirectUri  the relying party's registered redirect URI
         */
        public Options(String loginPath, String callbackPath, String redirectUri) {
            this(loginPath, callbackPath, redirectUri, null, null, null);
        }
    }

    /**
     * Builds the login-redirect + callback {@link RouterFunction} pair.
     *
     * @param client  the OIDC-configured {@link AxiamClient} (built with
     *                {@code Builder.oidcClientId(...)}, and
     *                {@code Builder.oidcClientSecret(...)} for a confidential
     *                client)
     * @param store   where in-flight login state is parked between the login
     *                redirect and the callback (e.g. {@link io.axiam.sdk.oidc.MemoryOidcStateStore})
     * @param options path/redirect-URI/scope/success-destination configuration
     * @return a {@link RouterFunction} exposing {@code GET options.loginPath()}
     *         and {@code GET options.callbackPath()}
     */
    public static RouterFunction<ServerResponse> routes(AxiamClient client, OidcStateStore store, Options options) {
        return RouterFunctions.route()
                .GET(options.loginPath(), request -> beginLogin(client, store, options))
                .GET(options.callbackPath(), request -> completeLogin(client, store, options, request))
                .build();
    }

    private static ServerResponse beginLogin(AxiamClient client, OidcStateStore store, Options options) {
        try {
            OidcConfiguration configuration = client.oidcDiscover();
            AuthorizationRequest request = client.oidcBegin(configuration, options.redirectUri(), options.scope(), null);
            store.save(new OidcStateEntry(request.state(), request.nonce(), request.codeVerifier(), options.redirectUri()));
            return ServerResponse.status(HttpStatus.FOUND).location(URI.create(request.url())).build();
        } catch (RuntimeException e) {
            LOG.debug("axiam_sdk.oidc: could not start the OIDC login flow", e);
            return errorResponse(HttpStatus.SERVICE_UNAVAILABLE, "oidc_unavailable", "could not start the OIDC login flow");
        }
    }

    private static ServerResponse completeLogin(AxiamClient client, OidcStateStore store, Options options,
            ServerRequest request) {
        String idpError = request.param("error").orElse(null);
        if (idpError != null) {
            String description = request.param("error_description").orElse(idpError);
            LOG.debug("axiam_sdk.oidc: idp returned an authorization error: {}", idpError);
            return errorResponse(HttpStatus.UNAUTHORIZED, "authentication_failed", idpError + ": " + description);
        }

        String state = request.param("state").orElse(null);
        String code = request.param("code").orElse(null);
        if (state == null || code == null) {
            return errorResponse(HttpStatus.BAD_REQUEST, "invalid_request", "callback is missing the state or code query parameter");
        }

        OidcStateEntry entry = store.consume(state);
        if (entry == null) {
            LOG.debug("axiam_sdk.oidc: no stored login state for the callback state");
            return errorResponse(HttpStatus.UNAUTHORIZED, "authentication_failed", "unknown, expired, or already-used login state");
        }

        OidcTokenSet tokens;
        try {
            OidcConfiguration configuration = client.oidcDiscover();
            tokens = client.oidcExchange(configuration, code, entry.codeVerifier(), entry.redirectUri(), entry.nonce(), null);
        } catch (NetworkError e) {
            LOG.debug("axiam_sdk.oidc: token exchange transport failure", e);
            return errorResponse(HttpStatus.SERVICE_UNAVAILABLE, "oidc_unavailable", "the AXIAM token endpoint is unreachable");
        } catch (AuthError e) {
            // Includes OAuthProtocolError and every §12.4 reason code: a
            // login that cannot be proven is a failed login.
            LOG.debug("axiam_sdk.oidc: token exchange failed: {}", e.getMessage());
            return errorResponse(HttpStatus.UNAUTHORIZED, "authentication_failed", e.getMessage());
        }

        if (options.onSuccess() != null) {
            options.onSuccess().accept(tokens);
        }

        String destination = options.successRedirect() != null ? options.successRedirect() : entry.returnTo();
        if (destination != null) {
            return ServerResponse.status(HttpStatus.FOUND).location(URI.create(destination)).build();
        }

        ObjectNode body = MAPPER.createObjectNode();
        body.put("authenticated", true);
        if (tokens.idClaims() != null) {
            body.put("sub", tokens.idClaims().sub());
        }
        body.put("expiresIn", tokens.expiresIn());
        return jsonResponse(HttpStatus.OK, body);
    }

    private static ServerResponse errorResponse(HttpStatus status, String error, String message) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("error", error);
        body.put("message", message);
        return jsonResponse(status, body);
    }

    private static ServerResponse jsonResponse(HttpStatus status, ObjectNode body) {
        return ServerResponse.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
