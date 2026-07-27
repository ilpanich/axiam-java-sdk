package io.axiam.sdk.oidc;

import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.4 rules 3&ndash;6 (issuer, audience, time, nonce) —
 * pure claim checks over an already-signature-verified claim set, one test
 * per failure mode using the contract's exact reason codes. Rules 1&ndash;2
 * (signature) are covered separately by {@code JwksVerifierOidcTest}.
 */
class IdTokenValidatorClaimsTest {

    private static final String ISSUER = "https://axiam.example.com";
    private static final String CLIENT_ID = "my-app";
    private static final long NOW = 1_700_000_000L;

    private static JWTClaimsSet.Builder validBuilder() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-1")
                .audience(CLIENT_ID)
                .expirationTime(new Date((NOW + 900) * 1000))
                .issueTime(new Date(NOW * 1000))
                .claim("nonce", "expected-nonce");
    }

    @Test
    void validClaimsPassAndProduceIdTokenClaims() {
        JWTClaimsSet claims = validBuilder().build();

        IdTokenClaims result = IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW);

        assertEquals(ISSUER, result.iss());
        assertEquals("user-1", result.sub());
        assertEquals(List.of(CLIENT_ID), result.aud());
        assertEquals("expected-nonce", result.nonce());
        assertTrue(result.claims().containsKey("sub"));
    }

    @Test
    void invalidIssuerIsRejected() {
        JWTClaimsSet claims = validBuilder().issuer("https://not-axiam.example.com").build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("invalid_issuer", e.reason());
    }

    @Test
    void issuerComparisonIsExactNoTrailingSlashTolerance() {
        JWTClaimsSet claims = validBuilder().issuer(ISSUER + "/").build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("invalid_issuer", e.reason());
    }

    @Test
    void audienceNotContainingClientIdIsRejected() {
        JWTClaimsSet claims = validBuilder().audience("someone-else").build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("invalid_audience", e.reason());
    }

    @Test
    void multipleAudiencesWithoutMatchingAzpIsRejected() {
        JWTClaimsSet claims = validBuilder().audience(List.of(CLIENT_ID, "other-client")).build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("invalid_audience", e.reason());
    }

    @Test
    void multipleAudiencesWithMatchingAzpPasses() {
        JWTClaimsSet claims = validBuilder()
                .audience(List.of(CLIENT_ID, "other-client"))
                .claim("azp", CLIENT_ID)
                .build();

        IdTokenClaims result = IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW);

        assertEquals(CLIENT_ID, result.azp());
    }

    @Test
    void expiredTokenIsRejected() {
        // Well beyond the default 60s skew (rule 5), not merely 10s past exp.
        JWTClaimsSet claims = validBuilder().expirationTime(new Date((NOW - 3600) * 1000)).build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("token_expired", e.reason());
    }

    @Test
    void missingExpClaimIsTreatedAsExpired() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-1")
                .audience(CLIENT_ID)
                .issueTime(new Date(NOW * 1000))
                .claim("nonce", "expected-nonce")
                .build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("token_expired", e.reason());
    }

    @Test
    void missingIatClaimIsTreatedAsExpired() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-1")
                .audience(CLIENT_ID)
                .expirationTime(new Date((NOW + 900) * 1000))
                .claim("nonce", "expected-nonce")
                .build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("token_expired", e.reason());
    }

    @Test
    void futureIatIsTreatedAsExpired() {
        JWTClaimsSet claims = validBuilder().issueTime(new Date((NOW + 3600) * 1000)).build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("token_expired", e.reason());
    }

    @Test
    void futureNbfIsTreatedAsExpired() {
        JWTClaimsSet claims = validBuilder().notBeforeTime(new Date((NOW + 3600) * 1000)).build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("token_expired", e.reason());
    }

    @Test
    void nonceMismatchIsRejected() {
        JWTClaimsSet claims = validBuilder().claim("nonce", "wrong-nonce").build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("nonce_mismatch", e.reason());
    }

    @Test
    void missingNonceClaimIsRejectedWhenExpected() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-1")
                .audience(CLIENT_ID)
                .expirationTime(new Date((NOW + 900) * 1000))
                .issueTime(new Date(NOW * 1000))
                .build();

        AuthError e = assertThrows(AuthError.class,
                () -> IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW));

        assertEquals("nonce_mismatch", e.reason());
    }

    @Test
    void nonceRuleIsSkippedWhenNoExpectedNonceIsSupplied() {
        // oidcRefresh / loginClientCredentials: rule 6 does not apply.
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-1")
                .audience(CLIENT_ID)
                .expirationTime(new Date((NOW + 900) * 1000))
                .issueTime(new Date(NOW * 1000))
                .build();

        IdTokenClaims result = IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, null, null, NOW);

        assertEquals(ISSUER, result.iss());
    }

    @Test
    void clockSkewIsClampedToSixtySecondsMaximum() {
        assertEquals(60, IdTokenValidator.resolveClockSkew(3600));
        assertEquals(0, IdTokenValidator.resolveClockSkew(-10));
        assertEquals(60, IdTokenValidator.resolveClockSkew(null));
        assertEquals(30, IdTokenValidator.resolveClockSkew(30));
    }

    @Test
    void expirationWithinSkewWindowPasses() {
        // exp is 30s in the past, within the default 60s skew.
        JWTClaimsSet claims = validBuilder().expirationTime(new Date((NOW - 30) * 1000)).build();

        IdTokenClaims result = IdTokenValidator.checkClaims(claims, ISSUER, CLIENT_ID, "expected-nonce", null, NOW);

        assertEquals(ISSUER, result.iss());
    }

    @Test
    void constantTimeEqualsRejectsDifferentLengthStrings() {
        assertTrue(!IdTokenValidator.constantTimeEquals("short", "much-longer-string"));
        assertTrue(IdTokenValidator.constantTimeEquals("same", "same"));
    }
}
