package io.axiam.sdk.oidc;

import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.internal.JwksVerifier;

import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

/**
 * ID-token validation — CONTRACT.md &sect;12.4, OIDC Core &sect;3.1.3.7.
 *
 * <p>Rules 1&ndash;2 (algorithm allowlist, {@code kid} lookup, Ed25519
 * verification, single JWKS re-fetch) reuse
 * {@link JwksVerifier#verifyForOidc(String)} — the SAME verifier the
 * &sect;10 middleware's {@link JwksVerifier#verify(String)} uses, extended
 * rather than forked. This class holds rules 3&ndash;6 (issuer, audience,
 * time, nonce), so both halves are independently testable.
 *
 * <p>Every failure raises {@link AuthError} carrying one of the seven stable
 * reason codes CONTRACT.md &sect;12.3 rule 3 defines. Rule 7 (all-or-nothing
 * discard) is the caller's responsibility ({@code AxiamClient.oidcExchange}):
 * a response whose ID token fails here never yields an {@link OidcTokenSet},
 * so the access/refresh token from the same response is discarded with it.
 */
public final class IdTokenValidator {

    /**
     * Maximum (and default) permitted clock skew in seconds for ID-token time
     * claims. CONTRACT.md &sect;12.4 rule 5 caps this at 60s and forbids any
     * configuration above the bound.
     */
    public static final int MAX_CLOCK_SKEW_SEC = 60;

    private IdTokenValidator() {
    }

    /**
     * Runs the full CONTRACT.md &sect;12.4 checklist (rules 1&ndash;6)
     * against {@code idToken}: signature ({@link JwksVerifier#verifyForOidc})
     * then claims ({@link #checkClaims}).
     *
     * @param verifier      the JWKS verifier sourcing keys from the discovery
     *                      document's {@code jwks_uri}
     * @param idToken       the compact-serialized ID token to validate
     * @param issuer        the discovery document's {@code issuer} — the
     *                      authoritative value to compare {@code iss}
     *                      against
     * @param clientId      the relying party's own {@code client_id},
     *                      matched against {@code aud}/{@code azp}
     * @param nonce         the nonce from {@code oidcBegin}, mandatory for
     *                      {@code oidcExchange}; {@code null} for
     *                      {@code oidcRefresh}/{@code loginClientCredentials},
     *                      which skip rule 6 entirely
     * @param clockSkewSec  permitted clock skew in seconds, clamped to
     *                      {@code [0, MAX_CLOCK_SKEW_SEC]}; {@code null} uses
     *                      the maximum
     * @return the validated {@link IdTokenClaims}
     * @throws AuthError with the matching &sect;12.3 rule 3 reason code on
     *                    the first failing rule
     */
    public static IdTokenClaims validate(JwksVerifier verifier, String idToken, String issuer, String clientId,
            @Nullable String nonce, @Nullable Integer clockSkewSec) {
        JWTClaimsSet claims = verifier.verifyForOidc(idToken);
        return checkClaims(claims, issuer, clientId, nonce, clockSkewSec, System.currentTimeMillis() / 1000L);
    }

    /**
     * CONTRACT.md &sect;12.4 rules 3&ndash;6 — issuer, audience, time, and
     * nonce checks over an already-signature-verified claim set. Returns the
     * validated {@link IdTokenClaims} on success; throws the matching
     * {@link AuthError} reason code on the first failure.
     *
     * @param claims       the verified JWT payload
     * @param issuer       the discovery document's {@code issuer}
     * @param clientId     the relying party's own {@code client_id}
     * @param nonce        the expected nonce, or {@code null} to skip rule 6
     * @param clockSkewSec permitted clock skew in seconds, or {@code null}
     *                     for the maximum
     * @param nowSec       current time in epoch seconds — injectable so tests
     *                     can pin it
     * @return the validated {@link IdTokenClaims}
     * @throws AuthError with the matching reason code on the first failing rule
     */
    public static IdTokenClaims checkClaims(JWTClaimsSet claims, String issuer, String clientId,
            @Nullable String nonce, @Nullable Integer clockSkewSec, long nowSec) {
        int skew = resolveClockSkew(clockSkewSec);

        // Rule 3 — exact string comparison. No normalization, no
        // trailing-slash tolerance, no prefix matching.
        String iss = claims.getIssuer();
        if (!issuer.equals(iss)) {
            throw idTokenError("invalid_issuer", "iss does not equal the discovery document issuer");
        }

        // Rule 4 — aud must contain our client_id; with multiple audiences an
        // azp claim must be present and equal to it.
        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(clientId)) {
            throw idTokenError("invalid_audience", "aud does not contain this client_id");
        }
        if (audiences.size() > 1) {
            String azp = stringClaimOrNull(claims, "azp");
            if (!clientId.equals(azp)) {
                throw idTokenError("invalid_audience",
                        "aud holds multiple audiences and azp is absent or does not equal this client_id");
            }
        }

        // Rule 5 — exp must be in the future, iat must not be in the future,
        // nbf is honored when present; all within `skew` seconds. `exp` is
        // treated as REQUIRED (port-brief-addendum item 11): its absence is
        // an expiry failure, not a free pass.
        Date expDate = claims.getExpirationTime();
        if (expDate == null) {
            throw idTokenError("token_expired", "exp claim is missing");
        }
        long exp = expDate.getTime() / 1000L;
        if (exp + skew <= nowSec) {
            throw idTokenError("token_expired", "exp is in the past");
        }

        Date iatDate = claims.getIssueTime();
        if (iatDate == null) {
            throw idTokenError("token_expired", "iat claim is missing");
        }
        long iat = iatDate.getTime() / 1000L;
        if (iat - skew > nowSec) {
            throw idTokenError("token_expired", "iat is in the future");
        }

        Date nbfDate = claims.getNotBeforeTime();
        if (nbfDate != null) {
            long nbf = nbfDate.getTime() / 1000L;
            if (nbf - skew > nowSec) {
                throw idTokenError("token_expired", "nbf is in the future");
            }
        }

        // Rule 6 — mandatory for oidcExchange, skipped when the caller
        // supplied no expected nonce (oidcRefresh / loginClientCredentials).
        if (nonce != null) {
            String claimNonce = stringClaimOrNull(claims, "nonce");
            if (claimNonce == null || !constantTimeEquals(claimNonce, nonce)) {
                throw idTokenError("nonce_mismatch", "nonce claim is absent or does not match the request nonce");
            }
        }

        return IdTokenClaims.from(claims);
    }

    /**
     * Resolves the effective clock skew: the caller's value clamped into
     * {@code [0, MAX_CLOCK_SKEW_SEC]}, or the maximum when unset.
     *
     * @param clockSkewSec the caller-requested clock skew in seconds, or {@code null}
     * @return the effective clock skew in seconds
     */
    public static int resolveClockSkew(@Nullable Integer clockSkewSec) {
        if (clockSkewSec == null) {
            return MAX_CLOCK_SKEW_SEC;
        }
        return Math.min(Math.max(clockSkewSec, 0), MAX_CLOCK_SKEW_SEC);
    }

    /**
     * Constant-time string equality, used for the {@code nonce} comparison
     * CONTRACT.md &sect;12.4 rule 6 requires.
     *
     * @param a the first string to compare
     * @param b the second string to compare
     * @return {@code true} if {@code a} and {@code b} are equal
     */
    public static boolean constantTimeEquals(String a, String b) {
        byte[] left = a.getBytes(StandardCharsets.UTF_8);
        byte[] right = b.getBytes(StandardCharsets.UTF_8);
        if (left.length != right.length) {
            return false;
        }
        return MessageDigest.isEqual(left, right);
    }

    /**
     * Reads a string claim, returning {@code null} instead of throwing when
     * the claim is absent or not a string.
     *
     * @param claims the claim set to read from
     * @param name   the claim name
     * @return the claim's string value, or {@code null} if absent or mistyped
     */
    static @Nullable String stringClaimOrNull(JWTClaimsSet claims, String name) {
        try {
            return claims.getStringClaim(name);
        } catch (ParseException e) {
            return null;
        }
    }

    private static AuthError idTokenError(String reason, String message) {
        return new AuthError("id_token validation failed (" + reason + "): " + message, reason);
    }
}
