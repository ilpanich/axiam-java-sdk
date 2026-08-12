package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.annotations.AxiamRequireAccess;
import io.axiam.sdk.annotations.AxiamRequireAuth;
import io.axiam.sdk.annotations.AxiamRequireRole;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.oidc.RequestedPermission;
import io.axiam.sdk.oidc.UmaChallenge;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Spring MVC {@link HandlerInterceptor} that enforces the CONTRACT.md &sect;11
 * declarative authorization annotations
 * ({@link io.axiam.sdk.annotations.AxiamRequireAuth},
 * {@link io.axiam.sdk.annotations.AxiamRequireAccess},
 * {@link io.axiam.sdk.annotations.AxiamRequireRole}) on {@code @Controller}
 * handler methods.
 *
 * <p>It runs strictly <em>after</em> the &sect;10
 * {@link AxiamAuthenticationFilter} (interceptors execute inside the
 * {@code DispatcherServlet}, after the security filter chain has populated
 * {@code SecurityContextHolder}); it consumes the injected identity and never
 * re-implements token extraction, JWKS verification, the tenant check, or the
 * &sect;3a CSRF check.
 *
 * <p>For each annotated handler
 * ({@link #preHandle(HttpServletRequest, HttpServletResponse, Object) preHandle}):
 * <ol>
 *   <li>Method-level annotations take precedence over type-level ones of the
 *       same kind.</li>
 *   <li>The authenticated principal is read from {@code SecurityContextHolder};
 *       absent (or anonymous) &rarr; HTTP 401 ({@code authentication_failed}).
 *       Its name is the {@code subject_id} used for the check.</li>
 *   <li>{@link AxiamRequireRole}: a local check against the caller's granted
 *       authorities &mdash; none match &rarr; HTTP 403.</li>
 *   <li>{@link AxiamRequireAccess}: the resource UUID is resolved from the
 *       static {@code resourceId} literal, else the {@code resourceParam} path
 *       variable read from {@link HandlerMapping#URI_TEMPLATE_VARIABLES_ATTRIBUTE};
 *       missing/non-UUID &rarr; HTTP 400 ({@code invalid_request}). It then
 *       calls {@link AxiamClient#checkAccess(String, String, String, String)}
 *       with the subject id: denied &rarr; HTTP 403
 *       ({@code authorization_denied}); {@link NetworkError} &rarr; HTTP 503
 *       ({@code authz_unavailable}, fail closed). No decision is cached.</li>
 * </ol>
 *
 * <p>Error responses use the same standardized JSON body as &sect;10:
 * {@code { "error": ..., "message": ... }}. No token material is ever logged or
 * echoed; a denied check logs the {@code action} and {@code resource_id} at
 * debug level only.
 */
public final class AxiamAuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger LOG = LoggerFactory.getLogger(AxiamAuthorizationInterceptor.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ROLE_PREFIX = "ROLE_";

    private final AxiamClient client;
    private final @Nullable UmaChallenger challenger;

    /**
     * Creates an interceptor that enforces the &sect;11 annotations by calling
     * {@code client} for {@link AxiamRequireAccess} checks.
     *
     * @param client the AXIAM client used to evaluate authorization checks; the
     *               request's authenticated user id is passed as the check
     *               subject, so this client's own session need only be able to
     *               reach the authz endpoint
     */
    public AxiamAuthorizationInterceptor(AxiamClient client) {
        this(client, null);
    }

    /**
     * Creates an interceptor that additionally answers an
     * {@link AxiamRequireAccess} denial with a {@code WWW-Authenticate: UMA}
     * challenge (&sect;20.3, emit half).
     *
     * @param client     as above
     * @param challenger the challenge emitter, or {@code null} for the plain
     *                   &sect;11 behaviour. See {@link UmaChallenger} for why
     *                   this is opt-in and why a minting failure still denies
     *                   rather than escalating
     */
    public AxiamAuthorizationInterceptor(AxiamClient client, @Nullable UmaChallenger challenger) {
        this.client = client;
        this.challenger = challenger;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            // Not a controller method (static resource, default handler, ...):
            // nothing to enforce.
            return true;
        }

        AxiamRequireAuth requireAuth = resolve(handlerMethod, AxiamRequireAuth.class);
        AxiamRequireRole requireRole = resolve(handlerMethod, AxiamRequireRole.class);
        AxiamRequireAccess requireAccess = resolve(handlerMethod, AxiamRequireAccess.class);

        if (requireAuth == null && requireRole == null && requireAccess == null) {
            return true; // no §11 annotation on this handler
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!isAuthenticated(authentication)) {
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "authentication_failed", "authentication required");
            return false;
        }
        String subjectId = authentication.getName();

        if (requireRole != null && !hasAnyRole(authentication, requireRole.value())) {
            writeError(response, HttpServletResponse.SC_FORBIDDEN,
                    "authorization_denied", "caller lacks a required role");
            return false;
        }

        if (requireAccess != null) {
            return enforceAccess(request, response, requireAccess, subjectId);
        }

        return true;
    }

    /** Runs the resource-level authorization check for an {@link AxiamRequireAccess} handler. */
    private boolean enforceAccess(HttpServletRequest request, HttpServletResponse response,
            AxiamRequireAccess requireAccess, String subjectId) throws IOException {
        String resourceId = resolveResourceId(request, requireAccess);
        if (resourceId == null || !isUuid(resourceId)) {
            writeError(response, HttpServletResponse.SC_BAD_REQUEST,
                    "invalid_request", "missing or invalid resource identifier");
            return false;
        }

        String scope = requireAccess.scope().isEmpty() ? null : requireAccess.scope();
        String action = requireAccess.action();
        try {
            AxiamClient.AccessResult result = client.checkAccess(subjectId, action, resourceId, scope);
            if (!result.allowed()) {
                deny(response, action, resourceId);
                return false;
            }
            return true;
        } catch (NetworkError e) {
            // Fail closed (§11.2.5): a transport failure is "couldn't decide",
            // never a silent allow.
            LOG.debug("authz check unavailable: action={} resource_id={}", action, resourceId);
            writeError(response, 503, "authz_unavailable", "authorization service unavailable");
            return false;
        } catch (AuthzError e) {
            deny(response, action, resourceId);
            return false;
        } catch (AuthError e) {
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "authentication_failed", "authentication required");
            return false;
        }
    }

    /**
     * The single deny path for a resource check: a 403, carrying a
     * {@code WWW-Authenticate: UMA} challenge when — and only when — this
     * interceptor was built with a {@link UmaChallenger}.
     */
    private void deny(HttpServletResponse response, String action, String resourceId) throws IOException {
        LOG.debug("authorization denied: action={} resource_id={}", action, resourceId);
        UmaChallenger emitter = challenger;
        if (emitter != null) {
            String header = mintChallenge(emitter, action, resourceId);
            if (header != null) {
                response.setHeader("WWW-Authenticate", header);
            }
        }
        writeError(response, HttpServletResponse.SC_FORBIDDEN, "authorization_denied", "access denied");
    }

    /**
     * Mints one ticket for the pair that was just refused and formats the
     * challenge, or returns {@code null} when that fails.
     *
     * <p>The requested scope is the AXIAM <em>action</em> (§20.2): asking for
     * anything else would offer the caller authority other than the one they
     * were denied, and would step outside the grants the engine just evaluated.
     *
     * <p>Every failure is swallowed deliberately. A PAT that expired, a
     * Protection API that is down, a resource that declares none of the
     * requested scopes — none of these change the answer to the request, which
     * was already "no". Letting them turn a deny into a 500 would give the
     * outage a second consequence; letting them turn it into an allow would be
     * a security bug.
     */
    private static @Nullable String mintChallenge(UmaChallenger emitter, String action, String resourceId) {
        try {
            Sensitive ticket = emitter.client().umaRequestTicket(
                    emitter.pat(),
                    List.of(RequestedPermission.of(UUID.fromString(resourceId), List.of(action))));
            return UmaChallenge.header(emitter.realm(), emitter.asUri(), ticket);
        } catch (RuntimeException e) {
            // The class of the failure, never its message: an error body from
            // the Protection API is not something to widen into a response.
            LOG.debug("uma ticket minting failed ({}); denying without a challenge",
                    e.getClass().getSimpleName());
            return null;
        }
    }

    /**
     * Resolves the resource UUID string per §11.3 precedence: a static
     * {@code resourceId} literal first, else the {@code resourceParam} path
     * variable; {@code null} when neither yields a value.
     */
    private static @Nullable String resolveResourceId(HttpServletRequest request, AxiamRequireAccess requireAccess) {
        if (!requireAccess.resourceId().isEmpty()) {
            return requireAccess.resourceId();
        }
        Object attribute = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (attribute instanceof Map<?, ?> pathVariables) {
            Object value = pathVariables.get(requireAccess.resourceParam());
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    /**
     * Method-level annotation first, then the handler's declaring type; the
     * method-level annotation overrides a type-level one of the same kind.
     */
    private static <A extends Annotation> @Nullable A resolve(HandlerMethod handlerMethod, Class<A> type) {
        A onMethod = handlerMethod.getMethodAnnotation(type);
        if (onMethod != null) {
            return onMethod;
        }
        return handlerMethod.getBeanType().getAnnotation(type);
    }

    /** An identity is usable only when present, authenticated, and not anonymous. */
    private static boolean isAuthenticated(@Nullable Authentication authentication) {
        return authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }

    /**
     * Local role check: true when the caller holds at least one of {@code roles},
     * matched against granted-authority names verbatim and with the {@code ROLE_}
     * prefix.
     */
    private static boolean hasAnyRole(Authentication authentication, String[] roles) {
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String name = authority.getAuthority();
            for (String role : roles) {
                if (name.equals(role) || name.equals(ROLE_PREFIX + role)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isUuid(String value) {
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Writes the standardized JSON error body via Jackson (never manual string
     * concatenation) so a message with quotes/control characters can never
     * produce malformed or injected JSON. No token material is ever included.
     */
    private static void writeError(HttpServletResponse response, int status, String error, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        ObjectNode body = MAPPER.createObjectNode();
        body.put("error", error);
        body.put("message", message);
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }
}
