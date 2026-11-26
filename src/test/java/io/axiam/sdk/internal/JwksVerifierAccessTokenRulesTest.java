package io.axiam.sdk.internal;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
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

import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;10.1 rules 10&ndash;12 (contract 1.68; N14, N10, D-7): the token must be an
 * <em>access</em> token. Every case uses an otherwise-valid token for the configured tenant,
 * signed by the JWKS key, with no {@code aud}, against a verifier configured with no expected
 * audience &mdash; the configuration under which the Rust SDK admitted MFA-challenge and
 * WebAuthn-state JWTs (N14). Rules 10, 11 and 12 are separate sub-leads and each is pinned on its
 * own.
 *
 * <p>Also holds the C5 pin: an unknown {@code kid} triggers at most one JWKS refetch per cooldown
 * window, not one per token.
 */
class JwksVerifierAccessTokenRulesTest {

    private static final String TENANT = "tenant-a";
    private static final String KID = "key-1";
    private static final String NIL_UUID = "00000000-0000-0000-0000-000000000000";

    // --- Rule 10: typ ------------------------------------------------------

    @Test
    void rule10_typJwtIsRefused() throws Exception {
        assertRefusedWithTyp("JWT");
    }

    @Test
    void rule10_mfaChallengeTypIsRefused() throws Exception {
        assertRefusedWithTyp("axiam-mfa-challenge+jwt");
    }

    @Test
    void rule10_webauthnStateTypIsRefused() throws Exception {
        assertRefusedWithTyp("axiam-webauthn-state+jwt");
    }

    @Test
    void rule10_logoutTokenTypIsRefused() throws Exception {
        assertRefusedWithTyp("logout+jwt");
    }

    @Test
    void rule10_secEventTypIsRefused() throws Exception {
        assertRefusedWithTyp("secevent+jwt");
    }

    @Test
    void rule10_atJwtInAnyCaseAndWithOrWithoutApplicationPrefixIsAccepted() throws Exception {
        for (String typ : new String[] {"at+jwt", "AT+JWT", "application/at+jwt", "Application/AT+JWT"}) {
            OctetKeyPair key = key();
            try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
                JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
                JWTClaimsSet claims = verifier.verifyAccessToken(sign(key, typ, KID, claims().build()), TENANT);
                assertEquals("user-1", claims.getSubject(), typ);
            }
        }
    }

    @Test
    void rule10_noTypIsNotRejectedByThisRule() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            assertEquals("user-1", verifier.verifyAccessToken(sign(key, null, KID, claims().build()), TENANT)
                    .getSubject());
        }
    }

    // --- Rule 11: purpose --------------------------------------------------

    @Test
    void rule11_purposeClaimIsRefusedEvenWithAtJwtTypAndValidKid() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, "at+jwt", KID, claims().claim("purpose", "mfa_challenge").build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
            assertTrue(e.getMessage().contains("purpose"), e.getMessage());
        }
    }

    @Test
    void rule11_webauthnDiscoverableShapeIsRefused() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, "at+jwt", KID, claims().subject(NIL_UUID)
                    .claim("purpose", "webauthn_authenticate_discoverable").build());

            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    @Test
    void rule11_purposeWithNullValueIsRefused() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            // JWTClaimsSet.Builder drops a null claim unless asked to keep it; build the payload by hand.
            String payload = "{\"sub\":\"user-1\",\"tenant_id\":\"" + TENANT + "\",\"purpose\":null,\"exp\":"
                    + (System.currentTimeMillis() / 1000 + 900) + "}";
            String token = signRaw(key, "at+jwt", KID, payload);

            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
        }
    }

    @Test
    void rule11_purposeIsRefusedOnTheSenderConstrainedEntryPointToo() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, null, KID, claims().claim("purpose", "mfa_setup").build());

            assertThrows(AuthError.class, () -> verifier.verifySenderConstrained(token, TENANT, null));
        }
    }

    // --- Rule 12: kid ------------------------------------------------------

    @Test
    void rule12_kidlessTokenIsRefusedAgainstAOneKeyJwks() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, "at+jwt", null, claims().build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
            assertTrue(e.getMessage().contains("kid"), e.getMessage());
        }
    }

    @Test
    void rule12_kidlessTokenWithNoTypIsRefusedToo() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, null, null, claims().build());

            assertThrows(AuthError.class, () -> verifier.verifySenderConstrained(token, TENANT, null));
        }
    }

    @Test
    void rule12_kidlessSignatureOnlyPrimitiveDoesNotFallBackToTheOnlyKeyEither() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, "at+jwt", null, claims().build());

            assertThrows(AuthError.class, () -> verifier.verifySignatureOnlyUnchecked(token));
        }
    }

    // --- Control -----------------------------------------------------------

    @Test
    void normalAccessTokenPasses() throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            JWTClaimsSet claims = verifier.verifyAccessToken(sign(key, "at+jwt", KID, claims().build()), TENANT);
            assertEquals("user-1", claims.getSubject());
        }
    }

    // --- C5: unknown-kid refetch cooldown ----------------------------------

    @Test
    void c5_unknownKidRefetchesAtMostOncePerCooldownWindow() throws Exception {
        OctetKeyPair key = key();
        AtomicInteger fetches = new AtomicInteger();
        try (MockWebServer server = jwksServer(key, fetches)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            // Warm the cache with one genuine token: one fetch.
            verifier.verifyAccessToken(sign(key, "at+jwt", KID, claims().build()), TENANT);
            assertEquals(1, fetches.get());

            // Twenty forged tokens, each with its own random kid, in one burst.
            for (int i = 0; i < 20; i++) {
                String forged = sign(key, "at+jwt", "forged-" + i, claims().build());
                assertThrows(AuthError.class, () -> verifier.verifyAccessToken(forged, TENANT));
            }

            // One re-fetch is allowed for the whole window; never one per token.
            assertTrue(fetches.get() <= 2,
                    "unknown kids must cause at most one refetch per cooldown window, saw " + fetches.get()
                            + " total fetches");
        }
    }

    @Test
    void c5_unknownKidBurstOnAColdCacheAddsNoFetchAfterTheFirstToken() throws Exception {
        OctetKeyPair key = key();
        AtomicInteger fetches = new AtomicInteger();
        try (MockWebServer server = jwksServer(key, fetches)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String first = sign(key, "at+jwt", "forged-first", claims().build());
            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(first, TENANT));
            // The first token loads the cold cache and starts the window: one fetch, not two
            // (JAV-R1-3; this used to allow nimbus's load-then-retry pair).
            int afterFirst = fetches.get();
            assertTrue(afterFirst <= 1, "first unknown-kid token fetched " + afterFirst + " times");

            for (int i = 0; i < 10; i++) {
                String forged = sign(key, "at+jwt", "forged-" + i, claims().build());
                assertThrows(AuthError.class, () -> verifier.verifyAccessToken(forged, TENANT));
            }
            assertEquals(afterFirst, fetches.get(), "no further fetch inside the cooldown window");
        }
    }

    @Test
    void c5_aRotatedKidIsFetchedOnceTheCooldownWindowHasPassed() throws Exception {
        OctetKeyPair oldKey = key();
        OctetKeyPair newKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-2").generate();
        AtomicInteger fetches = new AtomicInteger();
        java.util.concurrent.atomic.AtomicReference<OctetKeyPair> published =
                new java.util.concurrent.atomic.AtomicReference<>(oldKey);
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                fetches.incrementAndGet();
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(List.of(published.get().toPublicJWK())).toString());
            }
        });
        server.start();
        try (server) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            java.util.concurrent.atomic.AtomicLong now = new java.util.concurrent.atomic.AtomicLong(1_000_000_000L);
            verifier.setClockForTesting(now::get);
            verifier.verifyAccessToken(sign(oldKey, "at+jwt", KID, claims().build()), TENANT);

            published.set(newKey);
            String rotated = sign(newKey, "at+jwt", "key-2", claims().build());
            // Inside the window: refused without a fetch.
            int before = fetches.get();
            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(rotated, TENANT));
            assertEquals(before, fetches.get());

            // After the window: one refetch picks the new key up.
            now.addAndGet(JwksVerifier.UNKNOWN_KID_REFETCH_COOLDOWN.toNanos() + 1);
            assertEquals("user-1", verifier.verifyAccessToken(rotated, TENANT).getSubject());
        }
    }

    // --- helpers -----------------------------------------------------------

    private static void assertRefusedWithTyp(String typ) throws Exception {
        OctetKeyPair key = key();
        try (MockWebServer server = jwksServer(key, new AtomicInteger())) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = sign(key, typ, KID, claims().build());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT), typ);
            assertTrue(e.getMessage().contains("typ"), e.getMessage());
        }
    }

    private static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", TENANT)
                .claim("scope", "users:read")
                .expirationTime(new Date(System.currentTimeMillis() + 900_000L));
    }

    private static OctetKeyPair key() throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(KID).generate();
    }

    private static String sign(OctetKeyPair key, String typ, String kid, JWTClaimsSet claims) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.EdDSA);
        if (typ != null) {
            header.type(new JOSEObjectType(typ));
        }
        if (kid != null) {
            header.keyID(kid);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims);
        jwt.sign(new Ed25519Signer(key));
        return jwt.serialize();
    }

    private static String signRaw(OctetKeyPair key, String typ, String kid, String payloadJson) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.EdDSA);
        if (typ != null) {
            header.type(new JOSEObjectType(typ));
        }
        if (kid != null) {
            header.keyID(kid);
        }
        com.nimbusds.jose.JWSObject jws =
                new com.nimbusds.jose.JWSObject(header.build(), new com.nimbusds.jose.Payload(payloadJson));
        jws.sign(new Ed25519Signer(key));
        return jws.serialize();
    }

    private static MockWebServer jwksServer(OctetKeyPair key, AtomicInteger fetches) throws Exception {
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                fetches.incrementAndGet();
                return new MockResponse()
                        .setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(List.of(key.toPublicJWK())).toString());
            }
        });
        server.start();
        return server;
    }
}
