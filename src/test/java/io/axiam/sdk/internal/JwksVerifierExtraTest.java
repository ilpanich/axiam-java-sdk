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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Additional {@link JwksVerifier} failure- and cache-path coverage
 * complementing {@link JwksVerifierTest}: malformed token, unknown-{@code kid}
 * (no matching key even after refetch), a wrong-key signature (key found but
 * signature invalid), a JWKS fetch transport error, and the warm-cache fast
 * path on a repeat verify.
 */
class JwksVerifierExtraTest {

    @Test
    void malformedTokenThrowsAuthErrorWithoutTouchingTheServer() {
        // Parse fails before any JWKS lookup, so no server is needed at all.
        JwksVerifier verifier = new JwksVerifier("http://localhost:1");
        assertThrows(AuthError.class, () -> verifier.verify("this-is-not-a-jwt"));
        assertThrows(AuthError.class, () -> verifier.verify("only.two"));
    }

    @Test
    void unknownKidYieldsNoMatchingKeyError() throws Exception {
        OctetKeyPair signing = generateEd25519KeyPair("kid-token");
        OctetKeyPair servedKey = generateEd25519KeyPair("kid-different");

        try (MockWebServer server = new MockWebServer()) {
            // JWKS only ever contains a DIFFERENT kid — after the forced
            // refetch the sought kid is still absent -> "no matching key".
            server.setDispatcher(new okhttp3.mockwebserver.Dispatcher() {
                @Override
                public MockResponse dispatch(okhttp3.mockwebserver.RecordedRequest request) {
                    return jwksResponse(servedKey.toPublicJWK());
                }
            });
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(signing, claims("tenant-a"));

            AuthError error = assertThrows(AuthError.class, () -> verifier.verify(token));
            org.junit.jupiter.api.Assertions.assertTrue(error.getMessage().contains("no matching EdDSA key"),
                    "expected a no-matching-key error, was: " + error.getMessage());
        }
    }

    @Test
    void keyFoundButSignatureInvalidIsRejected() throws Exception {
        // Same kid on both keys, but the token is signed with keyA while the
        // JWKS serves keyB's public key -> key selected, signature invalid.
        OctetKeyPair keyA = generateEd25519KeyPair("shared-kid");
        OctetKeyPair keyB = generateEd25519KeyPair("shared-kid");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(jwksResponse(keyB.toPublicJWK()));
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyA, claims("tenant-a"));

            AuthError error = assertThrows(AuthError.class, () -> verifier.verify(token));
            org.junit.jupiter.api.Assertions.assertTrue(error.getMessage().contains("invalid token signature"),
                    "expected an invalid-signature error, was: " + error.getMessage());
        }
    }

    @Test
    void jwksFetchTransportErrorSurfacesAsAuthError() throws Exception {
        OctetKeyPair signing = generateEd25519KeyPair("kid-token");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(signing, claims("tenant-a"));

            // A 500 on the JWKS endpoint makes RemoteJWKSet#get raise a
            // KeySourceException, which JwksVerifier maps to AuthError.
            assertThrows(AuthError.class, () -> verifier.verify(token));
        }
    }

    @Test
    void repeatVerifyUsesTheWarmCacheFastPath() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("kid-warm");
        java.util.concurrent.atomic.AtomicInteger fetches = new java.util.concurrent.atomic.AtomicInteger();

        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new okhttp3.mockwebserver.Dispatcher() {
                @Override
                public MockResponse dispatch(okhttp3.mockwebserver.RecordedRequest request) {
                    fetches.incrementAndGet();
                    return jwksResponse(keyPair.toPublicJWK());
                }
            });
            server.start();

            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            String token = signEdDsa(keyPair, claims("tenant-a"));

            JWTClaimsSet first = verifier.verify(token);
            JWTClaimsSet second = verifier.verify(token); // must hit the warm-cache fast path

            assertEquals("tenant-a", first.getStringClaim("tenant_id"));
            assertEquals("tenant-a", second.getStringClaim("tenant_id"));
            assertEquals(1, fetches.get(), "the second verify must be served from the warm cache (no extra fetch)");
        }
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static JWTClaimsSet claims(String tenantId) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", tenantId)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .build();
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

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(java.util.List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
