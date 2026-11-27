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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;
import java.util.function.Consumer;
import java.util.function.Predicate;

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
 * {@code 503 oidc_unavailable} for a network error.
 *
 * <p><strong>Browser binding (CONTRACT.md &sect;12.8 rule 1; contract 1.68, C7).</strong>
 * The login route sets a random 32-byte value as the {@code __Host-axiam_oidc_bind} cookie
 * ({@code HttpOnly; Secure; SameSite=Lax; Path=/}, no {@code Domain}) and records its SHA-256 on
 * the state entry. The callback consumes the entry first and then compares the presented cookie in
 * constant time; a missing cookie, an entry with no digest or a different value is the uniform
 * {@code 401}, with no code exchange and no success hook. Every callback response clears the
 * cookie. On an {@code http:} {@code redirect_uri} for {@code localhost}, {@code 127.0.0.1} or
 * {@code [::1]} (and only there) the name is {@code axiam_oidc_bind} without {@code Secure}.
 * Two logins started concurrently in one browser share the cookie, so the earlier callback is
 * refused and the user starts again. A caller-supplied {@link OidcStateStore} must persist
 * {@link OidcStateEntry#bindingDigest()} unchanged, or every sign-in is refused.
 *
 * <p><strong>{@code returnTo} (&sect;12.8 rule 3; C6).</strong> The login route reads an optional
 * {@code returnTo} query parameter; the callback follows a stored {@code returnTo} only when it is
 * a same-origin relative path (a single leading {@code /}, no {@code //} or {@code /\} prefix, no
 * backslash, no control character). It is checked when stored and again before redirecting; one
 * that fails is dropped and the glue falls back to {@code successRedirect} or the JSON summary. The
 * {@code Location} header carries the percent-encoded form of the destination (existing {@code %XX}
 * kept, any other {@code %} becomes {@code %25}, pure ASCII), so a value with a space or a
 * non-ASCII character is followed rather than failing the callback. An
 * {@link Options#allowReturnTo()} predicate may widen the rule, for values the default rule
 * refuses.
 */
public final class AxiamOidcLoginRoutes {

    private static final Logger LOG = LoggerFactory.getLogger(AxiamOidcLoginRoutes.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AxiamOidcLoginRoutes() {
    }

    /**
     * The success hook that also receives the consumed state entry and the request that completed
     * the sign-in (CONTRACT.md &sect;12.8 rule 2), so an application creates its session on that
     * request without reaching for {@code RequestContextHolder}.
     */
    @FunctionalInterface
    public interface SuccessHandler {

        /**
         * Called once the browser binding, the code exchange and every &sect;12.4 check have all
         * succeeded.
         *
         * @param tokens  the validated token set
         * @param entry   the consumed login-state entry (its {@code returnTo} is the value the login stored)
         * @param request the callback request, i.e. the one that completed the sign-in
         */
        void onSuccess(OidcTokenSet tokens, OidcStateEntry entry, ServerRequest request);
    }

    /**
     * Configuration for {@link #routes}.
     *
     * @param loginPath        the path that starts the login flow (redirects to the IdP); e.g. {@code "/oidc/login"}
     * @param callbackPath     the path AXIAM redirects back to after authentication; e.g. {@code "/oidc/callback"}
     * @param redirectUri      the relying party's registered redirect URI — the public URL of {@code callbackPath}; replayed verbatim on token exchange
     * @param scope            requested scope, space-separated, or {@code null} for the default ({@code openid}); add {@code roles} for {@code @AxiamRequireRole} to work
     * @param successRedirect  where to send the browser after a successful login, or {@code null} to fall back to a safe {@code returnTo} captured at login time, then to a JSON summary
     * @param onSuccess        called with the validated token set once the exchange succeeds — the hook where an application establishes its OWN session; the SDK deliberately does not do this for you
     * @param onSuccessWithRequest like {@code onSuccess}, and also given the consumed entry and the callback request (&sect;12.8 rule 2); runs after {@code onSuccess} when both are set
     * @param allowReturnTo    optional predicate that may widen the default same-origin-relative {@code returnTo} rule; consulted, at storing and before redirecting, only for a value the default rule refuses. A predicate that throws accepts nothing
     */
    public record Options(String loginPath, String callbackPath, String redirectUri, @Nullable String scope,
            @Nullable String successRedirect, @Nullable Consumer<OidcTokenSet> onSuccess,
            @Nullable SuccessHandler onSuccessWithRequest, @Nullable Predicate<String> allowReturnTo) {

        /**
         * Constructor with the success hook and no request-aware hook or {@code returnTo} predicate
         * (the shape this record had before contract 1.68).
         *
         * @param loginPath       the path that starts the login flow
         * @param callbackPath    the path AXIAM redirects back to
         * @param redirectUri     the relying party's registered redirect URI
         * @param scope           requested scope, or {@code null}
         * @param successRedirect where to send the browser after a successful login, or {@code null}
         * @param onSuccess       called with the validated token set, or {@code null}
         */
        public Options(String loginPath, String callbackPath, String redirectUri, @Nullable String scope,
                @Nullable String successRedirect, @Nullable Consumer<OidcTokenSet> onSuccess) {
            this(loginPath, callbackPath, redirectUri, scope, successRedirect, onSuccess, null, null);
        }

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

        /**
         * Returns a copy of these options with a request-aware success hook (&sect;12.8 rule 2).
         *
         * @param handler the hook that also receives the consumed entry and the callback request
         * @return the new options
         */
        public Options withSuccessHandler(SuccessHandler handler) {
            return new Options(loginPath, callbackPath, redirectUri, scope, successRedirect, onSuccess, handler,
                    allowReturnTo);
        }

        /**
         * Returns a copy of these options with a {@code returnTo} predicate that may widen the default rule.
         *
         * @param predicate accepts the extra values (for example an allowlist of the application's other origins)
         * @return the new options
         */
        public Options withAllowReturnTo(Predicate<String> predicate) {
            return new Options(loginPath, callbackPath, redirectUri, scope, successRedirect, onSuccess,
                    onSuccessWithRequest, predicate);
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
                .GET(options.loginPath(), request -> beginLogin(client, store, options, request))
                .GET(options.callbackPath(), request -> completeLogin(client, store, options, request))
                .build();
    }

    private static ServerResponse beginLogin(AxiamClient client, OidcStateStore store, Options options,
            ServerRequest serverRequest) {
        try {
            OidcConfiguration configuration = client.oidcDiscover();
            AuthorizationRequest request = client.oidcBegin(configuration, options.redirectUri(), options.scope(), null);
            // §12.8 rule 1 (a): a fresh binding value per login, never a cookie the request presents.
            String binding = OidcLoginBinding.newValue();
            // §12.8 rule 3: a returnTo that fails the rule is dropped, not stored.
            String returnTo = serverRequest.param("returnTo").orElse(null);
            if (returnTo != null && !returnToAllowed(options, returnTo)) {
                returnTo = null;
            }
            store.save(new OidcStateEntry(request.state(), request.nonce(), request.codeVerifier(),
                    options.redirectUri(), returnTo, OidcLoginBinding.digest(binding)));
            return ServerResponse.status(HttpStatus.FOUND)
                    .location(URI.create(request.url()))
                    .header(HttpHeaders.SET_COOKIE, OidcLoginBinding.setCookie(options.redirectUri(), binding))
                    .build();
        } catch (RuntimeException e) {
            LOG.debug("axiam_sdk.oidc: could not start the OIDC login flow", e);
            return errorResponse(HttpStatus.SERVICE_UNAVAILABLE, "oidc_unavailable", "could not start the OIDC login flow");
        }
    }

    private static ServerResponse completeLogin(AxiamClient client, OidcStateStore store, Options options,
            ServerRequest request) {
        // §12.8 rule 1 (d): every callback response clears the binding cookie, an unexpected
        // failure (the store, an application hook) included (GLUE-R1-5). The cookie clear wins over
        // propagating the exception to the application's handlers; the failure is logged, and the
        // browser gets a generic 500 that echoes nothing from it.
        String clear = OidcLoginBinding.clearCookie(options.redirectUri());
        try {
            return completeLogin(client, store, options, request, clear);
        } catch (VirtualMachineError e) {
            throw e;
        } catch (Throwable e) {
            // Any other failure, an Error from an application hook included, still clears the cookie.
            LOG.warn("axiam_sdk.oidc: the login callback failed unexpectedly: {}", e.getClass().getName());
            LOG.debug("axiam_sdk.oidc: callback failure detail", e);
            return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "server_error",
                    "the login could not be completed", clear);
        }
    }

    private static ServerResponse completeLogin(AxiamClient client, OidcStateStore store, Options options,
            ServerRequest request, String clear) {

        String idpError = request.param("error").orElse(null);
        if (idpError != null) {
            String description = request.param("error_description").orElse(idpError);
            LOG.debug("axiam_sdk.oidc: idp returned an authorization error: {}", idpError);
            return errorResponse(HttpStatus.UNAUTHORIZED, "authentication_failed", idpError + ": " + description, clear);
        }

        String state = request.param("state").orElse(null);
        String code = request.param("code").orElse(null);
        if (state == null || code == null) {
            return errorResponse(HttpStatus.BAD_REQUEST, "invalid_request", "callback is missing the state or code query parameter", clear);
        }

        // Consume FIRST (§12.8 rule 1 (c)): the state is single-use whatever happens next.
        OidcStateEntry entry = store.consume(state);
        // One status and one body for "unknown state" and "wrong browser", so the refusal says nothing about which.
        if (entry == null) {
            LOG.debug("axiam_sdk.oidc: no stored login state for the callback state");
            return uniformStateRefusal(clear);
        }
        if (!OidcLoginBinding.matches(bindingCookie(request, options), entry.bindingDigest())) {
            LOG.debug("axiam_sdk.oidc: callback is not bound to the browser that started the login");
            return uniformStateRefusal(clear);
        }

        OidcTokenSet tokens;
        try {
            OidcConfiguration configuration = client.oidcDiscover();
            tokens = client.oidcExchange(configuration, code, entry.codeVerifier(), entry.redirectUri(), entry.nonce(), null);
        } catch (NetworkError e) {
            LOG.debug("axiam_sdk.oidc: token exchange transport failure", e);
            return errorResponse(HttpStatus.SERVICE_UNAVAILABLE, "oidc_unavailable", "the AXIAM token endpoint is unreachable", clear);
        } catch (AuthError e) {
            // Includes OAuthProtocolError and every §12.4 reason code: a
            // login that cannot be proven is a failed login.
            LOG.debug("axiam_sdk.oidc: token exchange failed: {}", e.getMessage());
            return errorResponse(HttpStatus.UNAUTHORIZED, "authentication_failed", e.getMessage(), clear);
        }

        if (options.onSuccess() != null) {
            options.onSuccess().accept(tokens);
        }
        if (options.onSuccessWithRequest() != null) {
            options.onSuccessWithRequest().onSuccess(tokens, entry, request);
        }

        // §12.8 rule 3: re-checked before redirecting; a stored value that fails is not followed.
        String returnTo = entry.returnTo() != null && returnToAllowed(options, entry.returnTo()) ? entry.returnTo() : null;
        String destination = options.successRedirect() != null ? options.successRedirect() : returnTo;
        if (destination != null) {
            // Decision 7 (JAV-R1-2, GLUE-R1-1): the Location header is the percent-encoded form of
            // the destination, written here and nowhere else. java.net.URI is not involved, so a
            // value it would reject (a space, a malformed %) neither fails the request after the
            // success hook has run nor skips the cookie clear.
            return ServerResponse.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, OidcLoginBinding.encodeRedirectLocation(destination))
                    .header(HttpHeaders.SET_COOKIE, clear).build();
        }

        ObjectNode body = MAPPER.createObjectNode();
        body.put("authenticated", true);
        if (tokens.idClaims() != null) {
            body.put("sub", tokens.idClaims().sub());
        }
        body.put("expiresIn", tokens.expiresIn());
        return jsonResponse(HttpStatus.OK, body, clear);
    }

    private static ServerResponse uniformStateRefusal(String clearCookie) {
        return errorResponse(HttpStatus.UNAUTHORIZED, "authentication_failed", "unknown, expired, or already-used login state", clearCookie);
    }

    /** The binding cookie value under the one name this deployment uses, or {@code null}. */
    private static @Nullable String bindingCookie(ServerRequest request, Options options) {
        var cookies = request.cookies().get(OidcLoginBinding.cookieName(options.redirectUri()));
        return cookies == null || cookies.isEmpty() ? null : cookies.get(0).getValue();
    }

    /** The default rule, then the integrator's predicate only for a value the default refuses. */
    private static boolean returnToAllowed(Options options, String returnTo) {
        if (OidcLoginBinding.isSafeReturnTo(returnTo)) {
            return true;
        }
        Predicate<String> widen = options.allowReturnTo();
        if (widen == null) {
            return false;
        }
        try {
            return widen.test(returnTo);
        } catch (VirtualMachineError e) {
            throw e;
        } catch (Throwable t) {
            // A predicate that throws, an Error included (N4), accepts nothing.
            return false;
        }
    }

    private static ServerResponse errorResponse(HttpStatus status, String error, String message) {
        return errorResponse(status, error, message, null);
    }

    private static ServerResponse errorResponse(HttpStatus status, String error, String message,
            @Nullable String setCookie) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("error", error);
        body.put("message", message);
        return jsonResponse(status, body, setCookie);
    }

    private static ServerResponse jsonResponse(HttpStatus status, ObjectNode body, @Nullable String setCookie) {
        ServerResponse.BodyBuilder builder = ServerResponse.status(status).contentType(MediaType.APPLICATION_JSON);
        if (setCookie != null) {
            builder.header(HttpHeaders.SET_COOKIE, setCookie);
        }
        return builder.body(body);
    }
}
