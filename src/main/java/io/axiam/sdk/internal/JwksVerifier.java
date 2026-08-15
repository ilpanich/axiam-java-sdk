package io.axiam.sdk.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.errors.AuthError;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Local JWT verification against the organization-wide EdDSA JWKS (D-19,
 * CONTRACT.md &sect;9's local-verify companion). Sources keys from
 * {@code {baseUrl}/oauth2/jwks} via nimbus's {@link RemoteJWKSet}, cached
 * with {@link DefaultJWKSetCache} (TTL 300s / forced-refetch cooldown 60s,
 * matching the Rust/Go/Python reference SDKs' proven defaults) and rotated
 * on an unknown {@code kid} (built into {@link RemoteJWKSet#get}).
 *
 * <p><strong>Implementation note (Assumption A5 resolved against the
 * installed nimbus-jose-jwt 10.7 sources):</strong> the "obvious" nimbus
 * pipeline researched for this phase &mdash;
 * {@code DefaultJWTProcessor} + {@code JWSVerificationKeySelector(EdDSA,
 * jwkSource)} &mdash; does NOT work for OKP/Ed25519 keys in this release:
 * {@code JWSVerificationKeySelector.selectJWSKeys} converts every matched
 * {@link JWK} to a raw {@code java.security.Key} via
 * {@code KeyConverter.toJavaKeys}, which for an {@link OctetKeyPair} calls
 * {@code OctetKeyPair.toKeyPair()} &mdash; a method that unconditionally
 * throws {@code JOSEException("Export to java.security.KeyPair not
 * supported")} in nimbus-jose-jwt 10.7. That exception is silently
 * swallowed by {@code KeyConverter.toJavaKeys} ("Key conversion exceptions
 * are silently ignored"), so a correctly-signed EdDSA token is rejected
 * with a misleading {@code BadJOSEException("...no matching key(s)
 * found")} even though the JWKS fetch and key match succeeded. Separately,
 * {@code DefaultJWSVerifierFactory.createJWSVerifier} has no EdDSA/OKP
 * branch at all (only HMAC/RSA/EC) even if a converted key did exist. This
 * class therefore builds the key lookup directly against the same
 * {@link RemoteJWKSet} + {@link DefaultJWKSetCache} (preserving D-19's
 * "Don't Hand-Roll: use RemoteJWKSet+DefaultJWKSetCache" mandate for
 * fetch/cache/rotation) and constructs {@link Ed25519Verifier} directly
 * from the matched {@link OctetKeyPair}, which nimbus DOES support
 * natively.
 *
 * <p><strong>Algorithm pinning (T-20-06):</strong> the header {@code alg}
 * is checked against an explicit {@code EdDSA} allowlist BEFORE any JWKS
 * lookup is attempted &mdash; the token's own {@code alg} header never
 * selects the verification algorithm (algorithm-confusion defense; the
 * same idiom the Go/Rust/Python sibling SDKs implement by hand, since
 * nimbus's own algorithm-pinning key-selector class cannot drive OKP
 * verification in this release).
 *
 * <p><strong>Two entry points, deliberately named apart (CONTRACT.md
 * &sect;10.1):</strong>
 * <ul>
 *   <li>{@link #verifyAccessToken(String, String)} is <strong>the</strong>
 *       guard entry point. It applies the complete &sect;10.1 minimum
 *       local-verification set &mdash; signature with {@code alg} pinned to
 *       EdDSA before key lookup, a <strong>required</strong> {@code exp},
 *       {@code nbf} when present, a <strong>required</strong>
 *       {@code tenant_id} asserted against the caller's configured tenant,
 *       and {@code iss}/{@code aud} whenever this verifier was configured
 *       with an expected value &mdash; all under a bounded, named clock
 *       skew.</li>
 *   <li>{@link #verifySignatureOnlyUnchecked(String)} is the raw
 *       signature-only primitive &sect;10.1 permits for integrators writing
 *       their own policy. Its name states the omission at the call site; the
 *       SDK's own guards never route through it.</li>
 * </ul>
 *
 * <p><strong>nimbus caveat this class exists to close (the {@code SEC-080}
 * defect):</strong> nimbus-jose-jwt's {@link JWTClaimsSet} accessors are
 * pure getters &mdash; {@link JWTClaimsSet#getExpirationTime()} returns
 * {@code null} for a token carrying no {@code exp} at all, and nothing in
 * the library treats that as an error. A caller that writes the natural
 * {@code if (exp != null && exp.before(now))} therefore accepts a permanent
 * credential. {@link #verifyAccessToken(String, String)} requires the claim
 * instead of merely checking it when present. (nimbus does reject a
 * <em>wrong-typed</em> {@code exp} &mdash; a string, a boolean &mdash; at
 * {@code getJWTClaimsSet()} parse time, which surfaces here as
 * "malformed claims".)
 *
 * <p><strong>Cross-tenant carry-forward (T-20-07, MUST-carry-forward
 * control, &sect;10.1 rule 4):</strong> the JWKS endpoint is
 * organization-wide, not tenant-scoped &mdash; signature validity alone does
 * NOT imply tenant authorization. {@link #verifyAccessToken(String, String)}
 * enforces this itself; a caller using the raw
 * {@link #verifySignatureOnlyUnchecked(String)} primitive MUST call
 * {@link #assertTenant(JWTClaimsSet, String)} (and every other &sect;10.1
 * rule) for itself.
 */
public final class JwksVerifier {

    /**
     * CONTRACT.md &sect;10.1 rule 7 &mdash; the RECOMMENDED clock-skew
     * leeway, in seconds, applied to BOTH {@code exp} and {@code nbf}. A
     * named constant, never an inline literal.
     */
    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 60L;

    /**
     * CONTRACT.md &sect;10.1 rule 7 &mdash; the hard upper bound, in
     * seconds, on an operator-supplied clock skew. The leeway MUST NOT be
     * configurable to an unbounded value, so anything above this (or below
     * zero) is rejected when the policy is constructed rather than silently
     * widening the acceptance window.
     *
     * <p>Lowered 300 &rarr; 60 (&sect;13.4 observation 5). The old ceiling
     * satisfied rule 7 &mdash; it was named and bounded &mdash; but it was
     * 5&times; the RECOMMENDED leeway and 5&times; what every sibling SDK fixes
     * its value at, so an operator could widen the acceptance window on an
     * expired token to five minutes and still be "conformant". The ceiling now
     * equals the recommendation.
     */
    public static final long MAX_CLOCK_SKEW_SECONDS = 60L;

    /**
     * The audience a &sect;10 guard fronting a user-facing resource server
     * SHOULD expect (CONTRACT.md &sect;10.1 rule 6). Exposed for callers to
     * pass into {@link LocalVerificationPolicy}; never applied implicitly,
     * since rule 6 is conditional on the SDK being <em>configured</em> with
     * an expected value.
     */
    public static final String RECOMMENDED_RESOURCE_SERVER_AUDIENCE = "axiam:user";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final RemoteJWKSet<SecurityContext> jwkSource;

    private final LocalVerificationPolicy policy;

    /**
     * Serializes the forced-refetch path so a concurrent burst of
     * unknown-{@code kid} verifications collapses to exactly one Nimbus
     * refetch (D-08/D-09) &mdash; we do NOT rely on {@link RemoteJWKSet}'s
     * own thread-safety for this guarantee (Assumption A3). The lock wraps
     * only the fetch/refetch decision below; the EdDSA signature
     * verification in {@link #verifySignatureOnlyUnchecked(String)} is unaffected.
     */
    private final ReentrantLock refreshLock = new ReentrantLock();

    /**
     * Creates a verifier sourcing its JWKS from {@code {baseUrl}/oauth2/jwks}.
     *
     * @param baseUrl the AXIAM server base URL (trailing slash tolerated);
     *                the JWKS URL is derived as {@code {baseUrl}/oauth2/jwks}
     */
    public JwksVerifier(String baseUrl) {
        this(deriveJwksUrl(baseUrl), LocalVerificationPolicy.defaults());
    }

    /**
     * Creates a verifier sourcing its JWKS from {@code {baseUrl}/oauth2/jwks}
     * and applying {@code policy}'s CONTRACT.md &sect;10.1 rule 5&ndash;7
     * settings (expected issuer, expected audience, clock skew) to every
     * {@link #verifyAccessToken(String, String)} call.
     *
     * @param baseUrl the AXIAM server base URL (trailing slash tolerated);
     *                the JWKS URL is derived as {@code {baseUrl}/oauth2/jwks}
     * @param policy  the &sect;10.1 rule 5&ndash;7 policy; use
     *                {@link LocalVerificationPolicy#defaults()} for "no
     *                issuer check, no audience check, RECOMMENDED skew"
     */
    public JwksVerifier(String baseUrl, LocalVerificationPolicy policy) {
        this(deriveJwksUrl(baseUrl), policy);
    }

    /**
     * The CONTRACT.md &sect;10.1 rule 5&ndash;7 policy: which conditional
     * claims this verifier is configured to check, and how much clock skew
     * it tolerates.
     *
     * <p>Rules 5 and 6 are <strong>conditional</strong> &mdash; "checked when
     * the SDK is configured with an expected value; absent configuration
     * means no check" &mdash; so both fields default to {@code null} and no
     * issuer or audience is ever assumed or hardcoded. Rule 7 requires the
     * skew to be a named, bounded value, which
     * {@link #LocalVerificationPolicy(String, String, long)} enforces.
     *
     * @param expectedIssuer   the {@code iss} every locally-verified access
     *                         token must carry, or {@code null} to not check
     *                         {@code iss} at all
     * @param expectedAudience the value that must appear in the {@code aud}
     *                         claim, or {@code null} to not check
     *                         {@code aud} at all; a user-facing resource
     *                         server should pass
     *                         {@link #RECOMMENDED_RESOURCE_SERVER_AUDIENCE}
     * @param clockSkewSeconds leeway in seconds applied to BOTH {@code exp}
     *                         and {@code nbf}, bounded to
     *                         {@code 0 .. }{@link #MAX_CLOCK_SKEW_SECONDS}
     */
    public record LocalVerificationPolicy(
            @Nullable String expectedIssuer, @Nullable String expectedAudience, long clockSkewSeconds) {

        /**
         * Validates the skew bound CONTRACT.md &sect;10.1 rule 7 places on an
         * operator-supplied leeway.
         *
         * @throws IllegalArgumentException if {@code clockSkewSeconds} is
         *                                  negative or above
         *                                  {@link #MAX_CLOCK_SKEW_SECONDS}
         */
        public LocalVerificationPolicy {
            if (clockSkewSeconds < 0 || clockSkewSeconds > MAX_CLOCK_SKEW_SECONDS) {
                throw new IllegalArgumentException("clockSkewSeconds must be between 0 and "
                        + MAX_CLOCK_SKEW_SECONDS + " seconds (CONTRACT.md §10.1 rule 7), got " + clockSkewSeconds);
            }
        }

        /**
         * The default policy: no issuer check, no audience check (both rules
         * are conditional and unconfigured), and the RECOMMENDED
         * {@link #DEFAULT_CLOCK_SKEW_SECONDS} leeway.
         *
         * @return the default &sect;10.1 rule 5&ndash;7 policy
         */
        public static LocalVerificationPolicy defaults() {
            return new LocalVerificationPolicy(null, null, DEFAULT_CLOCK_SKEW_SECONDS);
        }
    }

    /**
     * Creates a verifier sourcing its JWKS from {@code jwksUri} directly —
     * used by the CONTRACT.md &sect;12 OIDC relying-party path, which reads
     * {@code jwks_uri} from the discovery document rather than deriving it
     * from a base URL (&sect;12.3 rule 6: the two may legitimately differ,
     * e.g. behind a proxy). Extends this class rather than forking it, per
     * &sect;12's "no SDK may fork, duplicate, or re-implement" rule.
     *
     * @param jwksUri the JWKS document URI, as advertised by the discovery
     *                document's {@code jwks_uri} field
     * @return a new verifier sourcing keys from {@code jwksUri}
     * @throws AuthError if {@code jwksUri} is not a valid URL
     */
    public static JwksVerifier forJwksUri(String jwksUri) {
        try {
            return new JwksVerifier(URI.create(jwksUri).toURL(), LocalVerificationPolicy.defaults());
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new AuthError("invalid jwks_uri in discovery document: " + jwksUri);
        }
    }

    private JwksVerifier(URL jwksUrl, LocalVerificationPolicy policy) {
        this.policy = policy;
        // TTL 300s, forced-refetch cooldown 60s — matches the Rust
        // (JWKS_CACHE_TTL=300s / FORCED_REFETCH_MIN_INTERVAL=60s), Go
        // (jwx minInterval=60s / maxInterval=300s), and Python
        // (PyJWKClient lifespan=300) reference SDKs' proven defaults.
        JWKSetCache cache = new DefaultJWKSetCache(300, 60, TimeUnit.SECONDS);
        this.jwkSource = new RemoteJWKSet<>(jwksUrl, null, cache);
    }

    private static URL deriveJwksUrl(String baseUrl) {
        String trimmed = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        try {
            return URI.create(trimmed + "/oauth2/jwks").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("invalid AXIAM base URL: " + baseUrl, e);
        }
    }

    /**
     * Applies the <strong>complete</strong> CONTRACT.md &sect;10.1 minimum
     * local-verification set to {@code token} and returns its claims. This is
     * the documented guard entry point; every SDK route guard and middleware
     * goes through it.
     *
     * <p>The seven rules, in order:
     * <ol>
     *   <li>{@code alg} pinned to {@code EdDSA} and checked BEFORE any keyset
     *       lookup, so {@code alg: none} and HS-family confusion are rejected
     *       without ever consulting a key.</li>
     *   <li>{@code exp} is REQUIRED. An absent {@code exp} is a permanent
     *       credential, never "no expiry constraint"; a wrong-typed
     *       {@code exp} fails at claims-parse time as malformed claims.</li>
     *   <li>{@code nbf} is honoured when present and may be absent.</li>
     *   <li>{@code tenant_id} is REQUIRED and must equal
     *       {@code expectedTenantId}. With no configured tenant to compare
     *       against, this fails closed — the JWKS trust anchor is
     *       organization-wide, so signature validity alone does not bound a
     *       token to a tenant.</li>
     *   <li>{@code iss} is checked only when this verifier's policy carries
     *       an expected issuer.</li>
     *   <li>{@code aud} is checked only when this verifier's policy carries
     *       an expected audience.</li>
     *   <li>Rules 2 and 3 allow the policy's bounded, named clock skew
     *       (default {@link #DEFAULT_CLOCK_SKEW_SECONDS}).</li>
     * </ol>
     *
     * <p>Fail-closed throughout: a required claim that is absent,
     * unparseable, or of the wrong JSON type causes rejection.
     *
     * @param token            the compact-serialized access token presented by the caller
     * @param expectedTenantId the tenant this resource server serves; {@code null}
     *                         or blank is a configuration error and fails closed
     * @return the token's claims, once every rule above has passed
     * @throws AuthError on any rule violation — the single failure type
     *                    callers map to HTTP 401 (CONTRACT.md &sect;2/&sect;10)
     */
    public JWTClaimsSet verifyAccessToken(String token, @Nullable String expectedTenantId) {
        if (expectedTenantId == null || expectedTenantId.isBlank()) {
            // Rule 4, fail-closed half: no configured tenant means there is
            // nothing to assert the token against, which is a rejection, not
            // a skipped check.
            throw new AuthError("no configured tenant to assert the token's tenant_id against");
        }

        // Rule 1 — signature, alg pinned to EdDSA before any key lookup.
        JWTClaimsSet claims = verifySignatureOnlyUnchecked(token);

        Instant now = Instant.now();
        Duration skew = Duration.ofSeconds(policy.clockSkewSeconds());

        // Rule 2 — exp REQUIRED. nimbus's getExpirationTime() returns null
        // for an absent claim and the library treats that as fine; the
        // natural "check it if it's there" shape is exactly the SEC-080
        // defect, so require it here.
        Date expiration = claims.getExpirationTime();
        if (expiration == null) {
            throw new AuthError("token is missing the required exp claim");
        }
        if (expiration.toInstant().plus(skew).isBefore(now)) {
            throw new AuthError("token expired");
        }

        // Rule 3 — nbf honoured when present; absent is valid.
        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null && notBefore.toInstant().minus(skew).isAfter(now)) {
            throw new AuthError("token is not yet valid (nbf)");
        }

        // Rule 4 — tenant_id REQUIRED and asserted.
        assertTenant(claims, expectedTenantId);

        // Rule 5 — iss, checked only when configured.
        String expectedIssuer = policy.expectedIssuer();
        if (expectedIssuer != null && !expectedIssuer.equals(claims.getIssuer())) {
            throw new AuthError("token iss does not match the configured issuer");
        }

        // Rule 6 — aud, checked only when configured.
        String expectedAudience = policy.expectedAudience();
        if (expectedAudience != null && !claims.getAudience().contains(expectedAudience)) {
            throw new AuthError("token aud does not contain the configured audience");
        }

        return claims;
    }

    /**
     * Verifies the token's signature (alg pinned to EdDSA, key sourced from
     * the cached/rotated JWKS) and returns its claims — <strong>signature
     * only</strong>.
     *
     * <p>This is the raw primitive CONTRACT.md &sect;10.1 permits for
     * integrators deliberately implementing their own policy. The
     * {@code Unchecked} suffix is the contract's reference spelling and is
     * load-bearing: this method does NOT check {@code exp}, {@code nbf},
     * {@code tenant_id}, {@code iss}, or {@code aud}, and a caller that stops
     * here has no guard at all. Route guards through
     * {@link #verifyAccessToken(String, String)} instead.
     *
     * @param token the compact-serialized JWS to verify
     * @return the token's claims, once the signature has verified successfully
     * @throws AuthError if the token is malformed, the alg is not EdDSA,
     *                    no matching key is found in the JWKS (including
     *                    after a forced refetch on an unknown {@code kid}),
     *                    or the signature is invalid
     */
    public JWTClaimsSet verifySignatureOnlyUnchecked(String token) {
        // Algorithm pinning FIRST, straight off the raw JOSE header and
        // before any JWS parsing or JWKS lookup (CONTRACT.md §10.1 rule 1,
        // T-20-06): `alg: none` is a header shape nimbus's own JWS parser
        // rejects with a generic "Not a JWS header", so relying on that
        // would make the alg pin incidental to the library rather than
        // explicit here. This is the same raw-header peek verifyForOidc
        // uses, applied to the §10 path too.
        String headerAlg = peekHeaderAlg(token);
        if (!"EdDSA".equals(headerAlg)) {
            throw new AuthError("unexpected JWS algorithm "
                    + (headerAlg != null ? headerAlg : "<absent>") + ": only EdDSA is accepted");
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new AuthError("malformed token: " + e.getMessage());
        }

        JWSHeader header = jwt.getHeader();

        // Belt-and-braces: re-assert the pin against the PARSED header, so
        // the check does not depend on the raw peek and the parsed view
        // agreeing.
        if (!JWSAlgorithm.EdDSA.equals(header.getAlgorithm())) {
            throw new AuthError("unexpected JWS algorithm " + header.getAlgorithm() + ": only EdDSA is accepted");
        }

        OctetKeyPair key = selectKey(header);

        JWSVerifier verifier;
        try {
            verifier = new Ed25519Verifier(key);
        } catch (JOSEException e) {
            throw new AuthError("failed to construct EdDSA verifier: " + e.getMessage());
        }

        boolean valid;
        try {
            valid = jwt.verify(verifier);
        } catch (JOSEException e) {
            throw new AuthError("signature verification failed: " + e.getMessage());
        }
        if (!valid) {
            throw new AuthError("invalid token signature");
        }

        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new AuthError("malformed claims: " + e.getMessage());
        }
    }

    /**
     * {@link #verifyAccessToken} plus CONTRACT.md §10.1 <b>rule 9</b> — the sender
     * constraint (RFC 8705 §3 / RFC 7800, contract 1.15).
     *
     * <p>This is the guard entry point for a resource server that accepts
     * <b>certificate-bound</b> access tokens. Pass the {@code x5t#S256} thumbprint of the
     * client certificate on the current connection, or {@code null} if there is none;
     * {@link #certificateThumbprintS256} computes it from DER bytes.
     *
     * <p>A separate method rather than a parameter on {@link #verifyAccessToken} because
     * the two have different <i>inputs</i>: most integrations have no transport-level
     * certificate to offer, and folding the thumbprint in would force every caller to
     * thread a {@code null} they do not have — which reads as "no certificate" and rejects
     * every bound token.
     *
     * <p><b>An unbound token is still accepted</b> here, with or without a certificate.
     * Rule 9 constrains tokens that claim a constraint; it does not make certificates
     * mandatory.
     *
     * @param token the caller's access token
     * @param expectedTenantId as {@link #verifyAccessToken}
     * @param presentedThumbprint the RFC 8705 §3.1 {@code x5t#S256} of the peer
     *     certificate on this connection, or {@code null}
     * @return the token's claims, once rules 1-9 have all passed
     * @throws AuthError on any rule violation, rules 1–8 and 9 alike
     */
    public JWTClaimsSet verifySenderConstrained(
            String token, @Nullable String expectedTenantId, @Nullable String presentedThumbprint) {
        JWTClaimsSet claims = verifyAccessToken(token, expectedTenantId);
        verifyCertificateBinding(claims, presentedThumbprint);
        return claims;
    }

    /**
     * CONTRACT.md §10.1 <b>rule 9</b> — enforce a token's sender constraint against the
     * certificate the caller presented on <b>this</b> connection.
     *
     * <p>A token carrying {@code cnf} is <b>not</b> a bearer token. Accepting one without
     * proving the caller holds the named key converts it straight back into one,
     * discarding the whole protection the operator turned on — which is why this is a rule
     * and not a recommendation.
     *
     * <p>The four cases:
     *
     * <table>
     *   <caption>Rule 9 decision table</caption>
     *   <tr><th>token's {@code cnf}</th><th>presented</th><th>result</th></tr>
     *   <tr><td>absent</td><td>anything</td><td>returns — an ordinary bearer token</td></tr>
     *   <tr><td>{@code x5t#S256}</td><td>equal</td><td>returns</td></tr>
     *   <tr><td>{@code x5t#S256}</td><td>different, or null</td><td>throws</td></tr>
     *   <tr><td>present, no {@code x5t#S256}</td><td>anything</td><td>throws</td></tr>
     * </table>
     *
     * <p>The first row is why adopting this rule breaks nothing. The last row is the one
     * that is easy to get wrong — a {@code cnf} naming a method this SDK cannot check is an
     * <i>unverifiable constraint</i>, never <i>no constraint</i>. Read the other way, a
     * sender-constrained token silently degrades to a bearer token the day a newer AXIAM
     * issues a confirmation this SDK predates.
     *
     * <p><b>The thumbprint must come from the transport</b> — the TLS peer certificate
     * (under a servlet container, {@code jakarta.servlet.request.X509Certificate}), or a
     * value a <i>trusted</i> terminating proxy forwarded over a channel your application
     * controls. Never from a caller-settable request header: a forgeable input makes the
     * whole mechanism decorative.
     *
     * @param claims the verified claims of the token being guarded
     * @param presentedThumbprint the RFC 8705 §3.1 {@code x5t#S256} of the peer
     *     certificate on this connection, or {@code null} when there is none
     * @throws AuthError on any of the three rejecting rows
     */
    public static void verifyCertificateBinding(
            JWTClaimsSet claims, @Nullable String presentedThumbprint) {
        Object cnf = claims.getClaim("cnf");
        if (cnf == null) {
            return;
        }
        if (!(cnf instanceof Map<?, ?> cnfMap)) {
            throw new AuthError("token cnf claim is malformed");
        }

        Object expected = cnfMap.get("x5t#S256");
        if (!(expected instanceof String expectedThumbprint) || expectedThumbprint.isEmpty()) {
            // Includes the DPoP case: this entry point has no proof to check, so a
            // jkt-bound token is refused rather than silently downgraded.
            throw new AuthError(
                    "token carries a cnf confirmation naming a method this entry point cannot "
                            + "verify (CONTRACT.md §10.1 rule 9 — an unverifiable constraint is "
                            + "not an absent one; use verifyTokenBinding for DPoP)");
        }
        // A token naming BOTH methods is a conjunction (contract 1.16): this method can
        // establish one half and must not answer for the whole. Refusing here is what
        // stops "check whichever we can".
        if (cnfMap.get("jkt") instanceof String jkt && !jkt.isEmpty()) {
            throw new AuthError(
                    "token names both a certificate and a DPoP key; both must hold "
                            + "(CONTRACT.md §10.1 rule 9) — use verifyTokenBinding");
        }
        if (presentedThumbprint == null || presentedThumbprint.isEmpty()) {
            throw new AuthError(
                    "token is certificate-bound but no client certificate was presented");
        }
        // Constant-time. The thumbprint is usually public — it derives from a certificate
        // sent in the clear during the handshake — so this is defence in depth. It matters
        // most for a self-signed client, where the registered thumbprint is the whole
        // credential.
        if (!MessageDigest.isEqual(
                expectedThumbprint.getBytes(StandardCharsets.UTF_8),
                presentedThumbprint.getBytes(StandardCharsets.UTF_8))) {
            throw new AuthError(
                    "token is bound to a different client certificate than the one presented");
        }
    }

    /**
     * What the caller proved about <b>this</b> connection and <b>this</b> request, for
     * {@link #verifyTokenBinding}.
     *
     * <p>A record rather than two string parameters on purpose: two same-typed nullable
     * thumbprints are exactly the pair a positional call transposes silently, and
     * transposing them would check each proof against the wrong confirmation.
     *
     * @param certificateThumbprint the peer certificate's RFC 8705 {@code x5t#S256}, taken
     *     from the TLS connection or from a trusted terminating proxy over a channel the
     *     application controls — <b>never</b> from a caller-settable header, which would
     *     make the whole mechanism decorative
     * @param dpopThumbprint the {@code jkt} of an <b>already verified</b> DPoP proof.
     *     Supply it only after checking the proof's signature, {@code htm}, {@code htu},
     *     {@code iat} and {@code jti} for this request — {@link DpopVerifier#verifyProof}
     *     does all ten §21.7.2 checks and returns exactly this value. A thumbprint lifted
     *     off an unverified proof would let a proof captured from any other endpoint
     *     authorize this one.
     */
    public record PresentedProofs(
            @Nullable String certificateThumbprint, @Nullable String dpopThumbprint) {

        /**
         * Neither proof — the ordinary bearer case.
         *
         * @return a pair with both thumbprints absent
         */
        public static PresentedProofs none() {
            return new PresentedProofs(null, null);
        }

        /**
         * Only a client certificate was presented.
         *
         * @param thumbprint the peer certificate's {@code x5t#S256}
         * @return a pair carrying only the certificate thumbprint
         */
        public static PresentedProofs certificate(String thumbprint) {
            return new PresentedProofs(thumbprint, null);
        }

        /**
         * Only a verified DPoP proof was presented.
         *
         * @param thumbprint the {@code jkt} of an already verified proof
         * @return a pair carrying only the DPoP thumbprint
         */
        public static PresentedProofs dpop(String thumbprint) {
            return new PresentedProofs(null, thumbprint);
        }
    }

    /**
     * CONTRACT.md §10.1 <b>rule 9</b> in full — enforce a token's sender constraint against
     * <b>every</b> proof the caller presented (contract 1.16).
     *
     * <p>This is the complete rule, and the one to use unless your transport genuinely
     * cannot produce a DPoP thumbprint.
     *
     * <p>The ten cases:
     *
     * <table>
     *   <caption>Rule 9 decision table, extended for DPoP</caption>
     *   <tr><th>token's {@code cnf}</th><th>certificate</th><th>DPoP</th><th>result</th></tr>
     *   <tr><td>absent</td><td>anything</td><td>anything</td><td>returns</td></tr>
     *   <tr><td>{@code x5t#S256}</td><td>equal</td><td>ignored</td><td>returns</td></tr>
     *   <tr><td>{@code x5t#S256}</td><td>different</td><td>ignored</td><td>throws</td></tr>
     *   <tr><td>{@code x5t#S256}</td><td>null</td><td>ignored</td><td>throws</td></tr>
     *   <tr><td>{@code jkt}</td><td>ignored</td><td>equal</td><td>returns</td></tr>
     *   <tr><td>{@code jkt}</td><td>ignored</td><td>different</td><td>throws</td></tr>
     *   <tr><td>{@code jkt}</td><td>ignored</td><td>null</td><td>throws</td></tr>
     *   <tr><td>both</td><td>equal</td><td>equal</td><td>returns</td></tr>
     *   <tr><td>both</td><td>wrong/missing</td><td>—</td><td>throws</td></tr>
     *   <tr><td>present, names neither</td><td>anything</td><td>anything</td><td>throws</td></tr>
     * </table>
     *
     * <p>Two rows carry the weight. <b>Both named is a conjunction</b>: an operator who
     * turned on two constraints asked for two, and satisfying the more convenient one is
     * not compliance. <b>Names neither is a refusal</b>: a confirmation this SDK cannot
     * interpret is an unverifiable constraint, and reading it as "unconstrained" is the
     * exact downgrade rule 9 exists to prevent. That includes an <i>empty</i> {@code cnf},
     * which is also how proto3 delivers an empty {@code CnfClaim} over gRPC (§10.3 rule 3).
     *
     * @param claims the verified claims of the token being guarded
     * @param proofs what the caller proved on this connection and request
     * @throws AuthError on any rejecting row
     */
    public static void verifyTokenBinding(JWTClaimsSet claims, PresentedProofs proofs) {
        Object cnf = claims.getClaim("cnf");
        // The fast path, and the common one. First on purpose: an unbound token is
        // accepted with no proofs at all, which is what keeps existing deployments working
        // when a guard adopts this rule.
        if (cnf == null) {
            return;
        }
        if (!(cnf instanceof Map<?, ?> cnfMap)) {
            throw new AuthError("token cnf claim is malformed");
        }

        String expectedCert =
                cnfMap.get("x5t#S256") instanceof String s && !s.isEmpty() ? s : null;
        String expectedJkt = cnfMap.get("jkt") instanceof String s && !s.isEmpty() ? s : null;

        if (expectedCert == null && expectedJkt == null) {
            throw new AuthError(
                    "token carries a cnf confirmation naming no method this SDK can verify "
                            + "(CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an "
                            + "absent one)");
        }

        // Each arm that applies must pass. Two independent checks rather than a branch on
        // the pair, precisely so "both named" needs no case of its own — it is simply
        // where both run.
        if (expectedCert != null) {
            if (proofs.certificateThumbprint() == null
                    || proofs.certificateThumbprint().isEmpty()) {
                throw new AuthError(
                        "token is certificate-bound but no client certificate was presented");
            }
            if (!MessageDigest.isEqual(
                    expectedCert.getBytes(StandardCharsets.UTF_8),
                    proofs.certificateThumbprint().getBytes(StandardCharsets.UTF_8))) {
                throw new AuthError(
                        "token is bound to a different client certificate than the one "
                                + "presented");
            }
        }

        if (expectedJkt != null) {
            if (proofs.dpopThumbprint() == null || proofs.dpopThumbprint().isEmpty()) {
                throw new AuthError(
                        "token is DPoP-bound but no verified DPoP proof was presented");
            }
            if (!MessageDigest.isEqual(
                    expectedJkt.getBytes(StandardCharsets.UTF_8),
                    proofs.dpopThumbprint().getBytes(StandardCharsets.UTF_8))) {
                throw new AuthError(
                        "token is bound to a different DPoP key than the one presented");
            }
        }
    }

    /**
     * Compute the RFC 8705 §3.1 {@code x5t#S256} thumbprint of a DER client certificate:
     * base64url-encoded SHA-256, <b>without</b> padding.
     *
     * <p>Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as omitting
     * {@code =}, and a padded value will not compare equal to what AXIAM put in the token.
     *
     * @param der the DER encoding of the peer's leaf certificate
     *     ({@code X509Certificate.getEncoded()})
     * @return the 43-character base64url thumbprint
     */
    public static String certificateThumbprintS256(byte[] der) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(der);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every conforming JRE (JCA standard names).
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }


    /**
     * CONTRACT.md &sect;12.4 rules 1&ndash;2 entry point for OIDC ID-token
     * validation: verifies {@code token}'s EdDSA signature using the SAME
     * cache + single-forced-refetch-then-fail key lookup {@link #verifySignatureOnlyUnchecked}
     * uses (never forked), but raises {@link AuthError} carrying a stable
     * &sect;12.3 rule 3 reason code ({@code invalid_alg}, {@code unknown_kid},
     * {@code invalid_signature}) distinguishing which rule failed &mdash;
     * unlike {@link #verifySignatureOnlyUnchecked}'s generic messages, which the resource-server
     * path (with no reason-code contract) does not need.
     *
     * <p>The header {@code alg} is read directly from the token's raw JOSE
     * header (before any JWS parsing is attempted) and checked against an
     * exact {@code "EdDSA"} allowlist: {@code alg: none} and every other
     * algorithm are rejected by the same equality test, with no special
     * case, so the token can never select its own verification algorithm. A
     * missing or unparsable {@code kid} is treated as {@code unknown_kid}
     * (port-brief-addendum item 12), matching an unmatched {@code kid} after
     * the single forced refetch.
     *
     * <p>This method does NOT check expiry, issuer, audience, or nonce
     * (&sect;12.4 rules 3&ndash;6) &mdash; callers apply those separately
     * over the returned claims.
     *
     * @param token the compact-serialized ID token to verify
     * @return the token's claims, once the signature has verified successfully
     * @throws AuthError with reason {@code invalid_alg}, {@code unknown_kid},
     *                    or {@code invalid_signature} on the matching failure
     */
    public JWTClaimsSet verifyForOidc(String token) {
        String headerAlg = peekHeaderAlg(token);
        if (!"EdDSA".equals(headerAlg)) {
            throw oidcAuthError("invalid_alg", "expected alg \"EdDSA\", got "
                    + (headerAlg != null ? "\"" + headerAlg + "\"" : "no alg header"));
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw oidcAuthError("invalid_signature", "malformed ID token: " + e.getMessage());
        }

        JWSHeader header = jwt.getHeader();
        if (header.getKeyID() == null) {
            throw oidcAuthError("unknown_kid", "ID token has no kid header");
        }

        OctetKeyPair key;
        try {
            key = selectKey(header);
        } catch (RuntimeException e) {
            throw oidcAuthError("unknown_kid", "no JWKS key matches the token's kid");
        }

        JWSVerifier verifier;
        try {
            verifier = new Ed25519Verifier(key);
        } catch (JOSEException e) {
            throw oidcAuthError("invalid_signature", "failed to construct EdDSA verifier: " + e.getMessage());
        }

        boolean valid;
        try {
            valid = jwt.verify(verifier);
        } catch (JOSEException e) {
            throw oidcAuthError("invalid_signature", "signature verification failed: " + e.getMessage());
        }
        if (!valid) {
            throw oidcAuthError("invalid_signature", "invalid ID token signature");
        }

        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw oidcAuthError("invalid_signature", "malformed claims: " + e.getMessage());
        }
    }

    private static AuthError oidcAuthError(String reason, String message) {
        return new AuthError("id_token validation failed (" + reason + "): " + message, reason);
    }

    /**
     * Reads the {@code alg} field out of {@code token}'s raw JOSE header —
     * decoded and JSON-parsed directly, WITHOUT going through
     * {@link SignedJWT#parse}, so the check runs even for a header shape
     * (e.g. {@code alg: "none"}) that nimbus's own JWS parser rejects before
     * ever constructing a {@link JWSHeader} (&sect;12.4 rule 1: {@code alg}
     * MUST be read from the header and checked before any signature work).
     *
     * @param token the compact-serialized token whose header is inspected
     * @return the header's {@code alg} value, or {@code null} if absent,
     *         non-string, or the header segment could not be decoded/parsed
     */
    private static @Nullable String peekHeaderAlg(String token) {
        int dot = token.indexOf('.');
        if (dot <= 0) {
            return null;
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(padBase64Url(token.substring(0, dot)));
            JsonNode node = MAPPER.readTree(decoded);
            JsonNode alg = node.get("alg");
            return alg != null && alg.isTextual() ? alg.asText() : null;
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    private static String padBase64Url(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "====".substring(rem);
    }

    /**
     * Looks up the EdDSA/Ed25519 signing key matching {@code header}'s
     * {@code kid} in the cached JWKS, sourced from {@link #jwkSource}
     * ({@link RemoteJWKSet}, which itself forces exactly one refetch +
     * retry when the sought {@code kid} is not found in the cached set —
     * key-rotation support carried by the library, not hand-rolled).
     *
     * <p>D-08/D-09: a concurrent burst of unknown-{@code kid} lookups must
     * collapse to exactly one Nimbus refetch. The fast path below matches
     * against {@link RemoteJWKSet#getCachedJWKSet()} — which never triggers
     * a network call — before ever acquiring {@link #refreshLock}. Only on
     * a cache miss is the lock acquired; the cache is re-checked once more
     * under the lock (another thread may have just refreshed it while this
     * one waited), and {@link RemoteJWKSet#get} — the call that may
     * perform the actual network refetch — is invoked only if the key is
     * still missing.
     */
    private OctetKeyPair selectKey(JWSHeader header) {
        JWKMatcher matcher = new JWKMatcher.Builder()
                .keyType(KeyType.OKP)
                .keyID(header.getKeyID())
                .keyUses(KeyUse.SIGNATURE, null)
                .algorithms(JWSAlgorithm.EdDSA, null)
                .curves(Curve.Ed25519, Curve.Ed448)
                .build();
        JWKSelector selector = new JWKSelector(matcher);

        OctetKeyPair fastKey = selectFromCache(selector);
        if (fastKey != null) {
            return fastKey;
        }

        refreshLock.lock();
        try {
            OctetKeyPair recheckKey = selectFromCache(selector);
            if (recheckKey != null) {
                return recheckKey;
            }

            List<JWK> matches;
            try {
                matches = jwkSource.get(selector, null);
            } catch (KeySourceException e) {
                throw new AuthError("JWKS fetch failed: " + e.getMessage());
            }

            OctetKeyPair key = firstOctetKeyPair(matches);
            if (key == null) {
                throw new AuthError("no matching EdDSA key found in JWKS (kid=" + header.getKeyID() + ")");
            }
            return key;
        } finally {
            refreshLock.unlock();
        }
    }

    /**
     * Matches {@code selector} against whatever is currently in
     * {@link RemoteJWKSet#getCachedJWKSet()} WITHOUT triggering a network
     * fetch (returns {@code null} on a cold/empty cache or no match).
     */
    private OctetKeyPair selectFromCache(JWKSelector selector) {
        com.nimbusds.jose.jwk.JWKSet cached = jwkSource.getCachedJWKSet();
        if (cached == null) {
            return null;
        }
        return firstOctetKeyPair(selector.select(cached));
    }

    private static OctetKeyPair firstOctetKeyPair(List<JWK> jwks) {
        for (JWK jwk : jwks) {
            if (jwk instanceof OctetKeyPair okp) {
                return okp;
            }
        }
        return null;
    }

    /**
     * The MUST-carry-forward cross-tenant control (T-20-07): the JWKS
     * endpoint is organization-wide, so signature validity alone does not
     * imply the token belongs to the caller's configured tenant. Throws if
     * the token's {@code tenant_id} claim is absent or does not match
     * {@code configuredTenantId}.
     *
     * @param claims             the verified token's claims (see {@link #verifySignatureOnlyUnchecked(String)})
     * @param configuredTenantId the caller's configured tenant identifier to check against
     * @throws AuthError if {@code tenant_id} is missing or mismatched
     */
    public static void assertTenant(JWTClaimsSet claims, String configuredTenantId) {
        String tenantId;
        try {
            tenantId = claims.getStringClaim("tenant_id");
        } catch (ParseException e) {
            throw new AuthError("token tenant_id claim is malformed");
        }
        if (tenantId == null || !tenantId.equals(configuredTenantId)) {
            throw new AuthError("token tenant_id does not match the configured tenant");
        }
    }
}
