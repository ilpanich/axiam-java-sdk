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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CONTRACT.md &sect;12.4 rules 1&ndash;2 (algorithm, signature) via
 * {@link JwksVerifier#verifyForOidc(String)} — one test per required failure
 * mode using the exact reason codes, plus a happy path and the
 * unknown-{@code kid} single-forced-refetch-then-fail behavior.
 */
class JwksVerifierOidcTest {

    @Test
    void validEdDsaIdTokenVerifiesAndReturnsClaims() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
            server.start();

            JwksVerifier verifier = JwksVerifier.forJwksUri(server.url("/jwks").toString());
            String token = signEdDsa(keyPair, claims());

            JWTClaimsSet result = verifier.verifyForOidc(token);

            assertEquals("user-1", result.getSubject());
        }
    }

    @Test
    void algNoneIsRejectedAsInvalidAlg() {
        // A hand-built alg:none header — never reaches SignedJWT.parse's own
        // (different) rejection path, since verifyForOidc peeks the raw
        // header first (§12.4 rule 1: alg checked BEFORE any signature work).
        String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"user-1\"}");
        String token = header + "." + payload + ".";

        JwksVerifier verifier = JwksVerifier.forJwksUri("https://example.invalid/jwks");

        AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));
        assertEquals("invalid_alg", e.reason());
    }

    @Test
    void nonEdDsaAlgIsRejectedAsInvalidAlg() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        String header = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"user-1\"}");
        String token = header + "." + payload + ".sig";

        JwksVerifier verifier = JwksVerifier.forJwksUri("https://example.invalid/jwks");

        AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));
        assertEquals("invalid_alg", e.reason());
    }

    @Test
    void missingAlgHeaderIsRejectedAsInvalidAlg() {
        String header = base64Url("{\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"user-1\"}");
        String token = header + "." + payload + ".sig";

        JwksVerifier verifier = JwksVerifier.forJwksUri("https://example.invalid/jwks");

        AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));
        assertEquals("invalid_alg", e.reason());
    }

    @Test
    void unmatchedKidIsRejectedAfterSingleForcedRefetch() throws Exception {
        OctetKeyPair signingKey = generateEd25519KeyPair("kid-signing");
        OctetKeyPair otherKey = generateEd25519KeyPair("kid-other-only-in-jwks");
        AtomicInteger fetchCount = new AtomicInteger(0);

        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    fetchCount.incrementAndGet();
                    return jwksResponse(otherKey.toPublicJWK());
                }
            });
            server.start();

            JwksVerifier verifier = JwksVerifier.forJwksUri(server.url("/jwks").toString());
            String token = signEdDsa(signingKey, claims());

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));

            assertEquals("unknown_kid", e.reason());
            // The initial (cold-cache) fetch plus exactly ONE forced re-fetch
            // on the still-unmatched kid — the "single JWKS re-fetch" §12.4
            // rule 2 requires — then fail; never a second re-fetch/retry loop.
            assertEquals(2, fetchCount.get(),
                    "an unknown kid must trigger the initial fetch plus exactly one forced re-fetch, then fail");
        }
    }

    @Test
    void noKidHeaderAtAllIsRejectedAsUnknownKid() {
        // port-brief-addendum item 12: "no kid header at all" is unknown_kid,
        // not a separate case, and must never reach the JWKS source.
        String header = base64Url("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"user-1\"}");
        String token = header + "." + payload + ".sig";

        JwksVerifier verifier = JwksVerifier.forJwksUri("https://example.invalid/jwks");

        AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));
        assertEquals("unknown_kid", e.reason());
    }

    @Test
    void tamperedSignatureIsRejectedAsInvalidSignature() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
            server.start();

            JwksVerifier verifier = JwksVerifier.forJwksUri(server.url("/jwks").toString());
            String token = signEdDsa(keyPair, claims());
            String tampered = tamperSignature(token);

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(tampered));
            assertEquals("invalid_signature", e.reason());
        }
    }

    @Test
    void malformedTokenIsRejectedAsInvalidAlgFailingClosed() {
        JwksVerifier verifier = JwksVerifier.forJwksUri("https://example.invalid/jwks");

        AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc("not-a-jwt-at-all"));
        assertEquals("invalid_alg", e.reason());
    }

    @Test
    void forJwksUriRejectsAMalformedUri() {
        assertThrows(AuthError.class, () -> JwksVerifier.forJwksUri("::not a url::"));
    }

    /**
     * A validly EdDSA-signed token whose payload is not a JSON object fails
     * at claims-parsing time (after signature verification succeeds),
     * exercising the {@code getJWTClaimsSet()} {@code ParseException} branch
     * distinctly from a bad signature.
     */
    @Test
    void validSignatureOverANonJsonPayloadIsRejectedAsInvalidSignature() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");

        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
            server.start();

            JwksVerifier verifier = JwksVerifier.forJwksUri(server.url("/jwks").toString());
            String token = signEdDsaOverRawPayload(keyPair, "not a json object");

            AuthError e = assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));
            assertEquals("invalid_signature", e.reason());
        }
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static JWTClaimsSet claims() {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
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

    /** Builds a validly EdDSA-signed compact JWS whose payload is arbitrary
     * (non-JSON) text, via the lower-level {@link com.nimbusds.jose.JWSObject}
     * API — {@link SignedJWT}'s own constructor requires a {@link JWTClaimsSet}
     * and so cannot represent this shape. */
    private static String signEdDsaOverRawPayload(OctetKeyPair keyPair, String rawPayload) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(keyPair.getKeyID())
                .build();
        com.nimbusds.jose.JWSObject jwsObject = new com.nimbusds.jose.JWSObject(header, new com.nimbusds.jose.Payload(rawPayload));
        jwsObject.sign(new Ed25519Signer(keyPair));
        return jwsObject.serialize();
    }

    private static String tamperSignature(String token) {
        String[] parts = token.split("\\.", -1);
        // Flip the last signature segment so the byte content differs while
        // remaining valid base64url (swap the first char with the last, or
        // replace with a same-length placeholder if too short).
        String sig = parts[2];
        String tampered = sig.isEmpty() ? "AA" : (sig.charAt(0) == 'A' ? "B" + sig.substring(1) : "A" + sig.substring(1));
        return parts[0] + "." + parts[1] + "." + tampered;
    }

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(java.util.List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
