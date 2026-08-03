package io.axiam.sdk.internal;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.errors.AuthError;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;10.1 minimum local-verification set — conformance tests
 * for {@link JwksVerifier#verifyAccessToken(String, String)}.
 *
 * <p>Every rule gets a positive case (proving the suite is non-vacuous) plus
 * the required negative cases: expired token; token with <strong>no</strong>
 * {@code exp}; token with a non-numeric {@code exp}; token whose {@code nbf}
 * is in the future; token for a <strong>different tenant</strong>; token with
 * no {@code tenant_id}; and {@code alg: none} plus an HS-signed token bearing
 * an EdDSA key id. Because this SDK now supports issuer/audience
 * configuration, a mismatch case for each is included too.
 *
 * <p>Why this file exists rather than trusting nimbus-jose-jwt: its
 * {@link JWTClaimsSet} accessors are pure getters, so
 * {@code getExpirationTime()} returns {@code null} for a token with no
 * {@code exp} and nothing in the library objects. That is the {@code SEC-080}
 * defect, and it is pinned below.
 */
class JwksVerifierLocalVerificationSetTest {

    private static final String TENANT = "tenant-a";
    private static final String OTHER_TENANT = "tenant-b";
    private static final String KID = "key-1";

    // --- Rule 1: signature, alg pinned to EdDSA BEFORE key lookup ---------

    @Test
    void validTokenIsAccepted() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());

            JWTClaimsSet claims = verifier.verifyAccessToken(signEdDsa(keyPair, validClaims().build()), TENANT);

            assertEquals("user-1", claims.getSubject());
            assertEquals(TENANT, claims.getStringClaim("tenant_id"));
        }
    }

    @Test
    void algNoneIsRejectedWithoutAnyKeyLookup() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        AtomicInteger fetches = new AtomicInteger();
        try (MockWebServer server = startCountingJwksServer(keyPair, fetches)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());

            AuthError e = assertThrows(
                    AuthError.class, () -> verifier.verifyAccessToken(unsignedAlgNoneToken(), TENANT));

            assertTrue(e.getMessage().contains("only EdDSA is accepted"), e.getMessage());
            assertEquals(0, fetches.get(), "alg:none must be rejected without consulting a key");
        }
    }

    @Test
    void hsTokenBearingAnEdDsaKidIsRejectedWithoutAnyKeyLookup() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        AtomicInteger fetches = new AtomicInteger();
        try (MockWebServer server = startCountingJwksServer(keyPair, fetches)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            // HS256 whose kid names the published EdDSA key: the confusion
            // attack that would press the Ed25519 public key into service as
            // an HMAC secret if the token's own alg selected the algorithm.
            String hsToken = signHs256(validClaims().build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(hsToken, TENANT));

            assertTrue(e.getMessage().contains("only EdDSA is accepted"), e.getMessage());
            assertEquals(0, fetches.get(), "HS confusion must be rejected without consulting a key");
        }
    }

    @Test
    void tokenSignedByAForeignKeyIsRejected() throws Exception {
        OctetKeyPair published = generateEd25519KeyPair();
        OctetKeyPair foreign = new OctetKeyPairGenerator(Curve.Ed25519).keyID(KID).generate();
        try (MockWebServer server = startJwksServer(published)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());

            assertThrows(
                    AuthError.class,
                    () -> verifier.verifyAccessToken(signEdDsa(foreign, validClaims().build()), TENANT));
        }
    }

    // --- Rule 2: exp REQUIRED and numeric ---------------------------------

    @Test
    void expiredTokenIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().expirationTime(secondsFromNow(-3600)).build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));

            assertTrue(e.getMessage().contains("expired"), e.getMessage());
        }
    }

    @Test
    void tokenWithNoExpIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            // No expirationTime() at all — a permanent credential (SEC-080).
            String token = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .claim("tenant_id", TENANT)
                            .build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));

            assertTrue(e.getMessage().contains("missing the required exp claim"), e.getMessage());
        }
    }

    /**
     * Pins the library gap this SDK compensates for: nimbus itself parses the
     * SAME no-{@code exp} token happily and reports {@code null} expiry. If a
     * future nimbus starts objecting, this fails loudly rather than leaving
     * dead defensive code behind.
     */
    @Test
    void nimbusAloneReportsNullExpiryForATokenWithNoExp() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        String token = signEdDsa(
                keyPair,
                new JWTClaimsSet.Builder()
                        .subject("user-1")
                        .claim("tenant_id", TENANT)
                        .build());

        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();

        assertEquals(null, claims.getExpirationTime(), "nimbus treats an absent exp as simply null");
    }

    @Test
    void tokenWithANonNumericExpIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());

            for (Object badExp : List.of("not-a-number", "9999999999", Boolean.TRUE)) {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("sub", "user-1");
                payload.put("tenant_id", TENANT);
                payload.put("exp", badExp);
                String token = signEdDsaRawPayload(keyPair, payload);

                assertThrows(
                        AuthError.class,
                        () -> verifier.verifyAccessToken(token, TENANT),
                        "exp=" + badExp + " must be rejected");
            }
        }
    }

    // --- Rule 3: nbf honoured when present --------------------------------

    @Test
    void futureNbfIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().notBeforeTime(secondsFromNow(3600)).build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));

            assertTrue(e.getMessage().contains("not yet valid"), e.getMessage());
        }
    }

    @Test
    void absentNbfIsValid() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().build());

            assertDoesNotThrow(() -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    @Test
    void pastNbfIsValid() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().notBeforeTime(secondsFromNow(-3600)).build());

            assertDoesNotThrow(() -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    // --- Rule 4: tenant_id REQUIRED and asserted --------------------------

    @Test
    void differentTenantIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .claim("tenant_id", OTHER_TENANT)
                            .expirationTime(secondsFromNow(900))
                            .build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));

            assertTrue(e.getMessage().contains("tenant_id does not match"), e.getMessage());
        }
    }

    @Test
    void tokenWithNoTenantIdIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .expirationTime(secondsFromNow(900))
                            .build());

            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    @Test
    void noConfiguredTenantFailsClosed() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().build());

            for (String noTenant : new String[] {null, "", "   "}) {
                AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, noTenant));
                assertTrue(e.getMessage().contains("no configured tenant"), e.getMessage());
            }
        }
    }

    @Test
    void nonStringTenantIdIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("sub", "user-1");
            payload.put("tenant_id", 42);
            payload.put("exp", System.currentTimeMillis() / 1000 + 900);
            String token = signEdDsaRawPayload(keyPair, payload);

            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    // --- Rules 5 & 6: iss / aud, conditional on configuration -------------

    @Test
    void issuerNotConfiguredMeansNoIssuerCheck() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().issuer("https://whoever.example").build());

            assertDoesNotThrow(() -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    @Test
    void configuredIssuerAcceptsAMatchAndRejectsAMismatchOrAbsence() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(
                    server.url("/").toString(),
                    new JwksVerifier.LocalVerificationPolicy(
                            "https://axiam.example", null, JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS));

            String matching = signEdDsa(keyPair, validClaims().issuer("https://axiam.example").build());
            assertDoesNotThrow(() -> verifier.verifyAccessToken(matching, TENANT));

            String mismatched = signEdDsa(keyPair, validClaims().issuer("https://evil.example").build());
            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(mismatched, TENANT));
            assertTrue(e.getMessage().contains("iss does not match"), e.getMessage());

            String absent = signEdDsa(keyPair, validClaims().build());
            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(absent, TENANT));
        }
    }

    @Test
    void audienceNotConfiguredMeansNoAudienceCheck() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, validClaims().audience("some-other-api").build());

            assertDoesNotThrow(() -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    @Test
    void configuredAudienceAcceptsAMatchAndRejectsAMismatchOrAbsence() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(
                    server.url("/").toString(),
                    new JwksVerifier.LocalVerificationPolicy(
                            null,
                            JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE,
                            JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS));

            String matching = signEdDsa(
                    keyPair,
                    validClaims()
                            .audience(List.of(JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE, "other"))
                            .build());
            assertDoesNotThrow(() -> verifier.verifyAccessToken(matching, TENANT));

            String mismatched = signEdDsa(keyPair, validClaims().audience("someone-else").build());
            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(mismatched, TENANT));
            assertTrue(e.getMessage().contains("aud does not contain"), e.getMessage());

            String absent = signEdDsa(keyPair, validClaims().build());
            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(absent, TENANT));
        }
    }

    // --- Rule 7: named, bounded clock skew --------------------------------

    @Test
    void defaultClockSkewIsTheRecommendedSixtySeconds() {
        assertEquals(60L, JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS);
        assertEquals(60L, JwksVerifier.LocalVerificationPolicy.defaults().clockSkewSeconds());
    }

    @Test
    void clockSkewAbsorbsAJustExpiredTokenAndAJustFutureNbf() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());

            String justExpired = signEdDsa(keyPair, validClaims().expirationTime(secondsFromNow(-10)).build());
            assertDoesNotThrow(() -> verifier.verifyAccessToken(justExpired, TENANT));

            String justFutureNbf = signEdDsa(keyPair, validClaims().notBeforeTime(secondsFromNow(10)).build());
            assertDoesNotThrow(() -> verifier.verifyAccessToken(justFutureNbf, TENANT));
        }
    }

    @Test
    void clockSkewCannotBeConfiguredUnbounded() {
        for (long bad : new long[] {-1L, JwksVerifier.MAX_CLOCK_SKEW_SECONDS + 1, 86_400L}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new JwksVerifier.LocalVerificationPolicy(null, null, bad),
                    "skew " + bad + " must be refused");
        }
    }

    @Test
    void clockSkewMayBeTightenedToZero() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(
                    server.url("/").toString(), new JwksVerifier.LocalVerificationPolicy(null, null, 0L));
            String justExpired = signEdDsa(keyPair, validClaims().expirationTime(secondsFromNow(-10)).build());

            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(justExpired, TENANT));
        }
    }

    // --- The signature-only primitive stays available, and stays obvious --

    @Test
    void signatureOnlyPrimitiveIsNamedToAdvertiseItsOmission() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            // No exp, foreign tenant: accepted by the raw primitive, which is
            // exactly why the SDK's own guards never call it.
            String token = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .claim("tenant_id", OTHER_TENANT)
                            .build());

            assertNotNull(verifier.verifySignatureOnlyUnchecked(token).getSubject());
            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    // --- helpers ----------------------------------------------------------

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", TENANT)
                .claim("scope", "users:read")
                .expirationTime(secondsFromNow(900));
    }

    private static Date secondsFromNow(long seconds) {
        return new Date(System.currentTimeMillis() + seconds * 1000L);
    }

    private static OctetKeyPair generateEd25519KeyPair() throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(KID).generate();
    }

    private static String signEdDsa(OctetKeyPair keyPair, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(keyPair));
        return jwt.serialize();
    }

    /**
     * Signs an arbitrary JSON payload — needed for wrong-typed claims that
     * {@link JWTClaimsSet.Builder} would coerce or refuse to hold.
     */
    private static String signEdDsaRawPayload(OctetKeyPair keyPair, Map<String, Object> payload) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        JWSObject jws = new JWSObject(header, new Payload(payload));
        jws.sign(new Ed25519Signer(keyPair));
        return jws.serialize();
    }

    private static String signHs256(JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .keyID(KID)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new MACSigner("some-shared-secret-key-material-32b".getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    /** Hand-assembles an {@code alg: none} token; no signer will emit one. */
    private static String unsignedAlgNoneToken() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString(
                ("{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"" + KID + "\"}").getBytes(StandardCharsets.UTF_8));
        String payload = b64.encodeToString(
                ("{\"sub\":\"user-1\",\"tenant_id\":\"" + TENANT + "\",\"exp\":" + (System.currentTimeMillis() / 1000
                                + 900) + "}")
                        .getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".";
    }

    private static MockWebServer startJwksServer(OctetKeyPair keyPair) throws Exception {
        return startCountingJwksServer(keyPair, new AtomicInteger());
    }

    private static MockWebServer startCountingJwksServer(OctetKeyPair keyPair, AtomicInteger fetches)
            throws Exception {
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                fetches.incrementAndGet();
                String body = new JWKSet(List.of(keyPair.toPublicJWK())).toString();
                return new MockResponse()
                        .setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody(body);
            }
        });
        server.start();
        return server;
    }
}
