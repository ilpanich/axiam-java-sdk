package io.axiam.sdk.mcp;

import io.axiam.sdk.errors.FieldError;
import io.axiam.sdk.errors.ValidationError;

import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MCP resource-server helpers (CONTRACT.md &sect;28, RFC 9728 + RFC 6750) —
 * the ONE &sect;28 implementation every Spring MVC surface (and, per the
 * &sect;9 plan table, the Kotlin port that reuses this Spring Boot filter) is
 * built on, mirroring how {@code JwksVerifier} is the one &sect;10
 * verification path.
 *
 * <p>&sect;28.1's canonical operation set: {@link #protectedResourceMetadata}
 * (and its short-form overload), {@link #bearerChallenge} (and its
 * short-form overload). {@code serveProtectedResourceMetadata} is
 * {@link io.axiam.sdk.spring.AxiamProtectedResourceMetadataController} — it
 * needs a Spring {@code RequestMappingHandlerMapping} to register a route on,
 * which does not belong in this framework-independent class.
 *
 * <p>No method here performs network I/O (&sect;28.0), so &sect;16 (retry)
 * and &sect;9 (single-flight refresh) do not apply.
 */
public final class Mcp {

    private Mcp() {
    }

    /** RFC 9728 &sect;3.1's well-known prefix — inserted between a resource's authority and its path (&sect;28.3). */
    public static final String PROTECTED_RESOURCE_METADATA_PREFIX = "/.well-known/oauth-protected-resource";

    /** The default, and in this contract version the only accepted, value of {@code bearer_methods_supported} (&sect;28.2 rule 6). */
    private static final List<String> DEFAULT_BEARER_METHODS = List.of("header");

    /**
     * The three hosts &sect;28.2 rule 2 lets an {@code http} URL use, and the
     * only ones. AXIAM's RFC 8252 &sect;7.3 loopback hosts, reused verbatim —
     * there is deliberately no flag, environment variable or debug build that
     * widens this.
     */
    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "[::1]", "localhost");

    private static final Set<String> NO_GRANT_REASON_CODES = Set.of("no_grant");

    /**
     * {@code scheme://authority[path][?query][#fragment]}, matched against
     * the caller's string exactly as given.
     *
     * <p>Deliberately not {@link java.net.URI}: that parser <em>normalises</em>
     * — it can resolve {@code ..} segments and re-encode. &sect;28.2 forbids
     * adjusting a value to make it pass, and &sect;28.3 derives the document's
     * own path from this string, so what is validated must be what was
     * written.
     */
    private static final Pattern ABSOLUTE_URI =
            Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^?#]*)(\\?[^#]*)?(#[\\s\\S]*)?$");

    // ------------------------------------------------------------------
    // Refusals (§28.2, §28.4, §28.5) — always ValidationError, no new type
    // ------------------------------------------------------------------

    /**
     * Raises &sect;28's refusal.
     *
     * <p>&sect;28.6 pins the error taxonomy: "&sect;28's refusals are
     * {@code ValidationError}; no new type". This SDK's {@link ValidationError}
     * is &sect;27.4 rule 7's sub-type, so {@code status} names the HTTP code an
     * AXIAM server would answer with for the same rejected field —
     * <strong>400</strong> — even though no server was asked and no request
     * was made. {@code operation} names the &sect;28 operation that refused,
     * the way a management refusal names {@code users.get}.
     */
    private static RuntimeException refuse(String operation, String field, String message) {
        // Returns rather than throws: every call site reads `throw refuse(...)`,
        // so the caller's own throw is what actually raises it. Throwing from
        // inside this helper would still be correct at runtime (the exception
        // propagates either way), but it makes the call site's `throw` keyword
        // unreachable bytecode — never a coverage tool's fault to report.
        return new ValidationError(
                operation, 400, field + ": " + message + " (CONTRACT.md §28)", List.of(new FieldError(field, message)));
    }

    // ------------------------------------------------------------------
    // Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4
    // ------------------------------------------------------------------

    /** {@code NQCHAR}: {@code %x21} / {@code %x23}–{@code %x5B} / {@code %x5D}–{@code %x7E}. No space, no `"`, no `\`, no control, no non-ASCII. */
    private static boolean isNqchar(int c) {
        return c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e);
    }

    /** {@code NQSCHAR}: {@code NQCHAR} plus the space ({@code %x20}). */
    private static boolean isNqschar(int c) {
        return c == 0x20 || isNqchar(c);
    }

    private static boolean isAll(String value, java.util.function.IntPredicate predicate) {
        for (int i = 0; i < value.length(); i++) {
            if (!predicate.test(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Absolute-URI parsing (§28.2 rules 1, 2, 3, 7)
    // ------------------------------------------------------------------

    /** The pieces of an absolute URI, sliced out of the caller's string without normalisation. */
    private record ParsedUri(String scheme, String authority, String path, boolean hasQuery, boolean hasFragment) {
    }

    private static @Nullable ParsedUri parseAbsoluteUri(String raw) {
        Matcher m = ABSOLUTE_URI.matcher(raw);
        if (!m.matches()) {
            return null;
        }
        String authority = m.group(2) == null ? "" : m.group(2);
        if (authority.isEmpty()) {
            return null;
        }
        return new ParsedUri(m.group(1), authority, m.group(3) == null ? "" : m.group(3),
                m.group(4) != null, m.group(5) != null);
    }

    /**
     * The host inside an authority: {@code userinfo@} stripped, port
     * stripped, an IPv6 literal's brackets kept (so {@code [::1]} compares as
     * &sect;28.2 rule 2 spells it).
     *
     * <p>Stripping {@code userinfo} is what makes
     * {@code http://localhost@evil.example.com/} a refusal rather than a
     * loopback pass — the host there is {@code evil.example.com}.
     */
    private static String hostOf(String authority) {
        int at = authority.lastIndexOf('@');
        String hostport = at >= 0 ? authority.substring(at + 1) : authority;
        if (hostport.startsWith("[")) {
            int close = hostport.indexOf(']');
            return close < 0 ? hostport : hostport.substring(0, close + 1);
        }
        int colon = hostport.indexOf(':');
        return colon < 0 ? hostport : hostport.substring(0, colon);
    }

    /** How much of &sect;28.2 rule 1 a particular member is held to — rule 7 and &sect;28.4's {@code resource_metadata} relax two parts of it. */
    private record UriPolicy(boolean allowQuery, boolean allowFragment) {
    }

    private static final UriPolicy IDENTIFIER = new UriPolicy(false, false);
    private static final UriPolicy LOCATOR = new UriPolicy(true, true);

    /** &sect;28.2 rules 1 and 2, applied to one member. Returns the parse so a caller that needs the path (&sect;28.3) does not parse twice. */
    private static ParsedUri requireAbsoluteUri(String operation, String field, @Nullable String raw, UriPolicy policy) {
        if (raw == null || raw.isEmpty()) {
            throw refuse(operation, field, "must be a non-empty absolute URI");
        }
        ParsedUri parsed = parseAbsoluteUri(raw);
        if (parsed == null) {
            throw refuse(operation, field, "must be an absolute URI with a scheme and an authority, not \"" + raw + "\"");
        }
        if (parsed.hasQuery() && !policy.allowQuery()) {
            throw refuse(operation, field, "must carry no query — §28.3 derives the metadata path from it");
        }
        if (parsed.hasFragment() && !policy.allowFragment()) {
            throw refuse(operation, field, "must carry no fragment");
        }
        String scheme = parsed.scheme().toLowerCase(Locale.ROOT);
        if (scheme.equals("https")) {
            return parsed;
        }
        if (scheme.equals("http") && LOOPBACK_HOSTS.contains(hostOf(parsed.authority()).toLowerCase(Locale.ROOT))) {
            return parsed;
        }
        throw refuse(operation, field,
                "must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and \"" + raw + "\" is neither");
    }

    // ------------------------------------------------------------------
    // §28.1 / §28.2 — protectedResourceMetadata
    // ------------------------------------------------------------------

    /**
     * {@link #protectedResourceMetadata(String, List, List, List, String)}
     * with the default {@code bearerMethodsSupported} ({@code ["header"]})
     * and no {@code resourceDocumentation}.
     *
     * @param resource the resource identifier
     * @param authorizationServers the authorization server issuer identifiers
     * @param scopesSupported the supported scope tokens
     * @return the validated document, its path and its URL
     * @throws ValidationError when any CONTRACT.md &sect;28.2 rule is violated
     */
    public static ProtectedResourceMetadata protectedResourceMetadata(
            String resource, List<String> authorizationServers, List<String> scopesSupported) {
        return protectedResourceMetadata(resource, authorizationServers, scopesSupported, null, null);
    }

    /**
     * {@code protectedResourceMetadata(...)} (CONTRACT.md &sect;28.1) — build
     * and validate the RFC 9728 protected-resource metadata document this
     * server publishes about itself, and derive the path and URL it is served
     * at.
     *
     * <p><strong>Validation happens here and it refuses; it never
     * repairs.</strong> Every &sect;28.2 rule is checked before any route
     * exists and before any request is served, and a violation throws
     * {@link ValidationError}. Nothing is normalised, trimmed, lowercased or
     * re-encoded to make it pass: a value that needs adjusting is a
     * configuration mistake an operator fixes in one line, and a helper that
     * quietly fixed it would publish a document describing a resource server
     * that does not exist.
     *
     * <p><strong>Nothing in the document may come from a request</strong>
     * (&sect;28.2 rule 8). Both {@code resource} and
     * {@code authorizationServers} are configuration; this SDK offers no
     * option to build either from the {@code Host} header, the
     * {@code Forwarded}/{@code X-Forwarded-*} family or the request URL,
     * because a document assembled from the request is a document an
     * attacker can point at an authorization server of their choosing — the
     * whole handshake redirected with one header.
     *
     * @param resource the resource identifier: absolute, {@code https} (or
     *                 {@code http} on a loopback host), no query, no
     *                 fragment. A trailing slash is significant
     * @param authorizationServers the issuer identifiers of the authorization
     *                            servers guarding it — at least one, no
     *                            duplicates, no query, no fragment
     * @param scopesSupported the scope tokens this resource server
     *                        understands. Order is preserved, duplicates are
     *                        refused, and an empty list omits the member
     * @param bearerMethodsSupported {@code null} defaults to {@code ["header"]},
     *                               which is the only accepted value in this
     *                               contract version
     * @param resourceDocumentation optional documentation page for a human.
     *                              May carry a query and a fragment; omitted
     *                              from the document when {@code null}
     * @return the validated document, its path and its URL
     * @throws ValidationError when any CONTRACT.md &sect;28.2 rule is violated
     */
    public static ProtectedResourceMetadata protectedResourceMetadata(
            String resource,
            List<String> authorizationServers,
            List<String> scopesSupported,
            @Nullable List<String> bearerMethodsSupported,
            @Nullable String resourceDocumentation) {
        String op = "protectedResourceMetadata";

        // Rule 1 + rule 2.
        ParsedUri parsed = requireAbsoluteUri(op, "resource", resource, IDENTIFIER);

        // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
        if (authorizationServers.isEmpty()) {
            throw refuse(op, "authorization_servers",
                    "must name at least one authorization server — a document that names none answers none of the "
                            + "question the client asked");
        }
        Set<String> seenServers = new LinkedHashSet<>();
        for (String entry : authorizationServers) {
            requireAbsoluteUri(op, "authorization_servers", entry, IDENTIFIER);
            if (!seenServers.add(entry)) {
                throw refuse(op, "authorization_servers", "duplicate entry \"" + entry + "\"");
            }
        }

        // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
        Set<String> seenScopes = new LinkedHashSet<>();
        List<String> scopes = new ArrayList<>();
        for (String scope : scopesSupported) {
            if (scope.isEmpty() || !isAll(scope, Mcp::isNqchar)) {
                throw refuse(op, "scopes_supported", "\"" + scope
                        + "\" is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', no control "
                        + "character, no non-ASCII)");
            }
            if (!seenScopes.add(scope)) {
                throw refuse(op, "scopes_supported", "duplicate scope \"" + scope + "\"");
            }
            scopes.add(scope);
        }

        // Rule 6: exactly ["header"].
        List<String> methods = bearerMethodsSupported == null ? DEFAULT_BEARER_METHODS : bearerMethodsSupported;
        if (methods.size() != 1 || !methods.get(0).equals("header")) {
            throw refuse(op, "bearer_methods_supported",
                    "must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential "
                            + "from the Authorization header alone, so " + methods + " would describe behaviour this "
                            + "SDK does not have");
        }

        // Rule 7: absolute URL, query and fragment permitted, omitted when absent.
        if (resourceDocumentation != null) {
            requireAbsoluteUri(op, "resource_documentation", resourceDocumentation, LOCATOR);
        }

        ProtectedResourceMetadataDocument document = new ProtectedResourceMetadataDocument(
                resource, List.copyOf(seenServers), scopes, DEFAULT_BEARER_METHODS, resourceDocumentation);

        String metadataPath = deriveMetadataPath(parsed.path());
        String metadataUrl = parsed.scheme() + "://" + parsed.authority() + metadataPath;
        return new ProtectedResourceMetadata(document, metadataPath, metadataUrl);
    }

    /**
     * &sect;28.3's derivation: RFC 9728 &sect;3.1 inserts the well-known
     * segment between the authority and the path. An empty path and a bare
     * {@code /} both reach the root form; anything else is appended,
     * <strong>trailing slash included</strong> — it is part of the identifier
     * a client compares, and two resources that differ only by it are two
     * resources.
     */
    private static String deriveMetadataPath(String resourcePath) {
        if (resourcePath.isEmpty() || resourcePath.equals("/")) {
            return PROTECTED_RESOURCE_METADATA_PREFIX;
        }
        return PROTECTED_RESOURCE_METADATA_PREFIX + resourcePath;
    }

    // ------------------------------------------------------------------
    // §28.4 — bearerChallenge
    // ------------------------------------------------------------------

    /**
     * {@link #bearerChallenge(String, BearerChallengeError, String, String)}
     * naming no error, no description and no scope — &sect;28.4's first test
     * vector.
     *
     * @param resourceMetadataUrl the document's URL
     * @return the {@code WWW-Authenticate} header value
     * @throws ValidationError when {@code resourceMetadataUrl} is outside RFC 6750's syntax
     */
    public static String bearerChallenge(String resourceMetadataUrl) {
        return bearerChallenge(resourceMetadataUrl, null, null, null);
    }

    /**
     * {@code bearerChallenge(...)} (CONTRACT.md &sect;28.4) — build the
     * <strong>value</strong> of a {@code WWW-Authenticate} header, never the
     * whole header line and never a map. The caller sets the header.
     *
     * <p>Parameters appear in a fixed order — {@code error},
     * {@code error_description}, {@code scope}, {@code resource_metadata} —
     * separated by exactly {@code ", "}. {@code resource_metadata} is always
     * present; the other three are omitted when not given.
     *
     * <p><strong>Every value is quoted and no value is ever escaped.</strong>
     * RFC 6750 &sect;3 restricts each parameter to a character set that
     * cannot contain {@code "} or {@code \}, so a value needing an escape is
     * a value that does not belong in a challenge: this method refuses it
     * rather than escaping, truncating or stripping it. A challenge is built
     * from the code's own constants and a route's own configuration, so an
     * invalid one is a programming error, not a runtime condition to degrade
     * around.
     *
     * @param resourceMetadataUrl the document's URL — the one parameter that
     *                            is always present. May carry a query and a
     *                            fragment
     * @param error one of RFC 6750 &sect;3.1's three codes, or {@code null}
     *              when the request carried no authentication information at
     *              all
     * @param errorDescription a human-readable description, for an
     *                         application building <strong>its own</strong>
     *                         challenge for its own 400. This SDK's own
     *                         guards never set it: every distinction a 401
     *                         draws for an unauthenticated stranger is an
     *                         oracle
     * @param scope the scope the route asked for, verbatim — one or more
     *              tokens joined by a single space
     * @return the {@code WWW-Authenticate} header value
     * @throws ValidationError when any parameter is outside RFC 6750's syntax
     */
    public static String bearerChallenge(
            String resourceMetadataUrl,
            @Nullable BearerChallengeError error,
            @Nullable String errorDescription,
            @Nullable String scope) {
        String op = "bearerChallenge";
        List<String> params = new ArrayList<>();

        if (error != null) {
            params.add("error=\"" + error.wireValue() + "\"");
        }

        if (errorDescription != null) {
            if (errorDescription.isEmpty() || !isAll(errorDescription, Mcp::isNqschar)) {
                throw refuse(op, "error_description",
                        "must be one or more NQSCHAR (no '\"', no '\\', no control character, no non-ASCII) — a "
                                + "value needing an escape does not belong in a challenge");
            }
            params.add("error_description=\"" + errorDescription + "\"");
        }

        if (scope != null) {
            if (scope.isEmpty()) {
                throw refuse(op, "scope", "must be one or more scope tokens joined by a single space");
            }
            for (String token : scope.split(" ", -1)) {
                if (token.isEmpty() || !isAll(token, Mcp::isNqchar)) {
                    throw refuse(op, "scope", "\"" + scope
                            + "\" is not a space-joined list of scope tokens — no leading, trailing or doubled "
                            + "space, and no empty token");
                }
            }
            params.add("scope=\"" + scope + "\"");
        }

        requireAbsoluteUri(op, "resource_metadata", resourceMetadataUrl, LOCATOR);
        if (!isAll(resourceMetadataUrl, Mcp::isNqchar)) {
            throw refuse(op, "resource_metadata",
                    "must carry no '\"', no '\\', no space and no control character — a correctly encoded URL "
                            + "cannot, so one that does has not been encoded");
        }
        params.add("resource_metadata=\"" + resourceMetadataUrl + "\"");

        return "Bearer " + String.join(", ", params);
    }

    // ------------------------------------------------------------------
    // §28.5 — the resourceMetadataUrl guard option
    // ------------------------------------------------------------------

    /**
     * {@link #mcpGuardChallenges(String, String, String, String)} with no
     * route-specific scope: {@link McpGuardChallenges#insufficientScope()} is
     * {@code null} on the result.
     *
     * @param resourceMetadataUrl the guard's &sect;28.5 option, or {@code null} when unset
     * @param expectedAudience the guard's existing &sect;10.1 row 6 expected audience, or {@code null} when unset
     * @param operation the guard factory's name, so a refusal says which guard refused
     * @return the precomputed challenges, or {@code null} when {@code resourceMetadataUrl} is {@code null}
     * @throws ValidationError when {@code resourceMetadataUrl} is set without {@code expectedAudience}, or either is outside §28.4's syntax
     */
    public static @Nullable McpGuardChallenges mcpGuardChallenges(
            @Nullable String resourceMetadataUrl, @Nullable String expectedAudience, String operation) {
        return mcpGuardChallenges(resourceMetadataUrl, expectedAudience, operation, null);
    }

    /**
     * Validates a guard's &sect;28 configuration and precomputes the
     * challenges it will emit. Called by every guard factory at construction
     * time — route-setup time, never per-request.
     *
     * <p>Returns {@code null} when {@code resourceMetadataUrl} is {@code null}:
     * &sect;28 is opt-in, and with the option absent the guard behaves
     * exactly as it did before &sect;28 existed — no header on any response,
     * no status changed, no body changed.
     *
     * <p><strong>{@code expectedAudience} is mandatory once
     * {@code resourceMetadataUrl} is set</strong>, and the refusal names both
     * options. A resource server that publishes "tokens for me carry this
     * {@code aud}" and then does not check {@code aud} has published a claim
     * it does not honour, and a token minted for a <em>different</em>
     * resource server opens it. That is the confusion RFC 8707 exists to
     * prevent, so this is a refusal rather than a warning.
     *
     * @param resourceMetadataUrl the guard's &sect;28.5 option, or {@code null} when unset
     * @param expectedAudience the guard's existing &sect;10.1 row 6 expected audience, or {@code null} when unset
     * @param operation the guard factory's name, so a refusal says which guard refused
     * @param scope the route's {@code scope} argument, where it has one (&sect;28.5 rule 5)
     * @return the precomputed challenges, or {@code null} when {@code resourceMetadataUrl} is {@code null}
     * @throws ValidationError when {@code resourceMetadataUrl} is set without {@code expectedAudience}, or either it or {@code scope} is outside §28.4's syntax
     */
    public static @Nullable McpGuardChallenges mcpGuardChallenges(
            @Nullable String resourceMetadataUrl,
            @Nullable String expectedAudience,
            String operation,
            @Nullable String scope) {
        if (resourceMetadataUrl == null) {
            return null;
        }

        if (expectedAudience == null || expectedAudience.isEmpty()) {
            throw refuse(operation, "resourceMetadataUrl",
                    "requires expectedAudience to be set on the same guard (CONTRACT.md §28.5 rule 2) — announcing a "
                            + "resource identifier obliges this server to check that an inbound token's `aud` is that "
                            + "identifier, and a resource server that announces itself without checking is opened by "
                            + "a token minted for somebody else");
        }

        ParsedUri parsed = requireAbsoluteUri(operation, "resourceMetadataUrl", resourceMetadataUrl, LOCATOR);
        String noCredential = bearerChallenge(resourceMetadataUrl);
        String invalidToken = bearerChallenge(resourceMetadataUrl, BearerChallengeError.INVALID_TOKEN, null, null);
        String insufficientScope = scope == null
                ? null
                : bearerChallenge(resourceMetadataUrl, BearerChallengeError.INSUFFICIENT_SCOPE, null, scope);
        String metadataPath = parsed.path().isEmpty() ? "/" : parsed.path();
        return new McpGuardChallenges(noCredential, invalidToken, insufficientScope, metadataPath);
    }

    /**
     * Picks between &sect;28.4's first two vectors for a 401:
     * {@link McpGuardChallenges#invalidToken()} when the request carried a
     * credential, {@link McpGuardChallenges#noCredential()} when it carried
     * none.
     *
     * <p>&sect;28.4 is explicit that the absent {@code error} is not an
     * oversight — RFC 6750 &sect;3 says a resource server SHOULD NOT name an
     * error code when the request carried no authentication information,
     * because no credential is not a bad credential.
     *
     * @param challenges the guard's precomputed challenges
     * @param credentialPresented whether the request carried a credential
     * @return the challenge to emit on the 401
     */
    public static String challengeFor401(McpGuardChallenges challenges, boolean credentialPresented) {
        return credentialPresented ? challenges.invalidToken() : challenges.noCredential();
    }

    /**
     * &sect;28.5 rule 5: the one class of 403 that carries a challenge, and
     * only it.
     *
     * <p>A {@code no_grant} denial on a route that named a scope means
     * <em>ask for more</em>, which is exactly what a challenge invites a
     * client to do. A {@code denied_by_rule} denial means <em>an
     * administrator has already decided</em>, and challenging on it sends an
     * MCP client all the way around the authorization loop to arrive at the
     * identical 403. An absent or unrecognised {@code reasonCode} — an older
     * server, a value this SDK predates — is not eligible either: &sect;11
     * rule 9 requires an unknown code to leave the outcome alone, and the
     * outcome here is a header-free 403.
     *
     * <p>Unlike {@link #challengeFor401}, this is not read off a precomputed
     * {@link McpGuardChallenges}: a Spring MVC guard built on this class (see
     * {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor}) is typically
     * one interceptor instance shared by every {@code @AxiamRequireAccess}
     * handler in the application, each with its own {@code scope}, so the
     * scope-specific vector is built fresh per request from the guard's
     * already-validated {@code resourceMetadataUrl} rather than baked in at
     * construction for one route.
     *
     * @param resourceMetadataUrl the guard's &sect;28.5 option — already validated by
     *                            a prior {@link #mcpGuardChallenges} call at
     *                            construction time — or {@code null} when unset
     * @param reasonCode the decision's {@code reason_code}, verbatim
     * @param scope the route's own scope argument, verbatim, or {@code null} for none
     * @return the challenge to emit, or {@code null} when this 403 gains no header
     * @throws ValidationError when {@code scope} is outside §28.4's syntax
     */
    public static @Nullable String challengeFor403(
            @Nullable String resourceMetadataUrl, @Nullable String reasonCode, @Nullable String scope) {
        if (resourceMetadataUrl == null || scope == null || reasonCode == null) {
            return null;
        }
        if (!NO_GRANT_REASON_CODES.contains(reasonCode)) {
            return null;
        }
        return bearerChallenge(resourceMetadataUrl, BearerChallengeError.INSUFFICIENT_SCOPE, null, scope);
    }

    /**
     * Is this request the unauthenticated {@code GET}/{@code HEAD} of the
     * metadata document?
     *
     * <p>&sect;28.3 rule 2 requires the document to be reachable with no
     * credential of any kind, and requires the SDK to exempt the path
     * explicitly where the &sect;10 guard is applied globally — which is the
     * normal {@code OncePerRequestFilter} arrangement. A document that 401s
     * cannot start the handshake it exists to start: the client would be
     * holding a 401 and being told to go read a page that answers 401.
     *
     * <p>The exemption is derived from {@code challenges}, so it exists only
     * where &sect;28 is configured and covers exactly the one path that
     * option names.
     *
     * @param challenges the guard's precomputed challenges, or {@code null} when §28 is off
     * @param method the request's HTTP method
     * @param requestPath the request's path, with no query string (as {@code HttpServletRequest#getRequestURI()} returns it)
     * @return {@code true} when this request must be exempted from authentication
     */
    public static boolean isMetadataDocumentRequest(
            @Nullable McpGuardChallenges challenges, String method, String requestPath) {
        if (challenges == null) {
            return false;
        }
        String verb = method.toUpperCase(Locale.ROOT);
        if (!verb.equals("GET") && !verb.equals("HEAD")) {
            return false;
        }
        return requestPath.equals(challenges.metadataPath());
    }

    // ------------------------------------------------------------------
    // §28.3 — serveProtectedResourceMetadata's §28.5 rule 3 cross-check
    // ------------------------------------------------------------------

    /**
     * &sect;28.5 rule 3: where a controller serving the document can see the
     * guard it is paired with, it MUST refuse the configuration at startup
     * unless the two agree — the guard's {@code resourceMetadataUrl} equals
     * the document's {@link ProtectedResourceMetadata#metadataUrl()}, and the
     * guard's expected audience equals the document's
     * {@link ProtectedResourceMetadataDocument#resource()}.
     *
     * <p>Both comparisons are simple string equality (RFC 3986 &sect;6.2.1):
     * no normalisation, no case folding of the host, no trailing-slash
     * tolerance. Passing both arguments as {@code null} skips the check
     * entirely — the guard is configured in another process, this side can
     * see only its own value, and nothing can be checked.
     *
     * @param metadata the document {@link #protectedResourceMetadata} built
     * @param guardResourceMetadataUrl the paired guard's {@code resourceMetadataUrl}, or {@code null} to skip the check
     * @param guardExpectedAudience the paired guard's expected audience, or {@code null} to skip the check
     * @throws ValidationError when either value is given and does not match
     */
    public static void requireMetadataMatchesGuard(
            ProtectedResourceMetadata metadata,
            @Nullable String guardResourceMetadataUrl,
            @Nullable String guardExpectedAudience) {
        if (guardResourceMetadataUrl == null && guardExpectedAudience == null) {
            return;
        }
        String op = "serveProtectedResourceMetadata";
        if (!Objects.equals(guardResourceMetadataUrl, metadata.metadataUrl())) {
            throw refuse(op, "resourceMetadataUrl", "is \"" + guardResourceMetadataUrl
                    + "\" but this document is published at \"" + metadata.metadataUrl()
                    + "\" — the challenge would point at a document that is not this resource server's");
        }
        if (!Objects.equals(guardExpectedAudience, metadata.document().resource())) {
            throw refuse(op, "expectedAudience", "is \"" + guardExpectedAudience
                    + "\" but this document announces \"" + metadata.document().resource()
                    + "\" — the document would announce one identifier while the guard checked `aud` against "
                    + "another, so every token the flow produced would be refused");
        }
    }
}
