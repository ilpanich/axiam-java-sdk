package io.axiam.sdk.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.internal.DpopVerifier.DpopRequest;
import io.axiam.sdk.internal.DpopVerifier.InMemoryJtiStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
 *
 * <p>Each check gets a negative test, because §21.7.2's whole premise is that a verifier
 * missing one of them still reports success. A suite that only proved a good proof passes
 * would not distinguish this class from returning the thumbprint unconditionally.
 */
class DpopVerifierTest {

    private static final String METHOD = "POST";
    private static final String URI = "https://rs.example.com/v1/things";
    private static final String TOKEN = "eyJhbGciOiJFZERTQSJ9.e30.sig";

    private static final AtomicInteger JTI_SEQ = new AtomicInteger();

    private InMemoryJtiStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryJtiStore();
    }

    private static OctetKeyPair newKey() throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).generate();
    }

    private static Map<String, Object> claims(Map<String, Object> overrides) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("htm", METHOD);
        c.put("htu", URI);
        c.put("iat", Instant.now().getEpochSecond());
        c.put("jti", "jti-" + JTI_SEQ.incrementAndGet());
        c.put("ath", DpopVerifier.accessTokenHash(TOKEN));
        overrides.forEach(
                (k, v) -> {
                    if (v == null) {
                        c.remove(k);
                    } else {
                        c.put(k, v);
                    }
                });
        return c;
    }

    private static String sign(OctetKeyPair key, JWSHeader header, Map<String, Object> claims)
            throws Exception {
        JWSObject jws = new JWSObject(header, new Payload(claims));
        jws.sign(new Ed25519Signer(key));
        return jws.serialize();
    }

    private static JWSHeader header(JWK publicJwk) {
        return new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
                .jwk(publicJwk)
                .build();
    }

    private static String goodProof(OctetKeyPair key) throws Exception {
        return sign(key, header(key.toPublicJWK()), claims(Map.of()));
    }

    private DpopRequest request() {
        return DpopRequest.of(METHOD, URI, TOKEN);
    }

    /**
     * Splice a new header onto an existing proof, leaving its signature intact. Needed
     * because Nimbus refuses to *emit* a header carrying private key material, which is
     * exactly what check 4 must be tested against.
     */
    private static String spliceHeader(String proof, Map<String, Object> header) {
        String[] parts = proof.split("\\.");
        String encoded =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                com.nimbusds.jose.util.JSONObjectUtils.toJSONString(header)
                                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return encoded + "." + parts[1] + "." + parts[2];
    }

    private static Map<String, Object> jwkMap(OctetKeyPair key) {
        return new HashMap<>(key.toPublicJWK().toJSONObject());
    }

    // ------------------------------------------------------------------------
    // The happy path
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("a well-formed proof verifies and returns its thumbprint")
    void wellFormedProofVerifies() throws Exception {
        OctetKeyPair key = newKey();
        String jkt = DpopVerifier.verifyProof(goodProof(key), request(), store);
        // Returning the thumbprint rather than void is what lets a guard pass a value
        // onward that could only have come from a verified proof.
        assertEquals(key.toPublicJWK().computeThumbprint().toString(), jkt);
        assertEquals(43, jkt.length());
    }

    @Test
    @DisplayName("query and fragment are stripped from both sides of htu")
    void queryStringDoesNotMatter() throws Exception {
        OctetKeyPair key = newKey();
        DpopRequest r =
                new DpopRequest(METHOD, URI + "?page=2#frag", TOKEN, null, DpopVerifier.IAT_LEEWAY, null);
        assertDoesNotThrow(() -> DpopVerifier.verifyProof(goodProof(key), r, store));
    }

    // ------------------------------------------------------------------------
    // One negative test per check
    // ------------------------------------------------------------------------

    /**
     * Without pinning typ, any other JWT signed by the same key — an access token, an ID
     * token — is replayable as a proof.
     */
    @Test
    @DisplayName("check 1: a proof without the dpop+jwt typ is refused")
    void check1WrongTyp() throws Exception {
        OctetKeyPair key = newKey();
        JWSHeader h =
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new com.nimbusds.jose.JOSEObjectType("JWT"))
                        .jwk(key.toPublicJWK())
                        .build();
        String proof = sign(key, h, claims(Map.of()));
        AuthError e =
                assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(proof, request(), store));
        assertTrue(e.getMessage().contains("typ"), e.getMessage());
    }

    @Test
    @DisplayName("check 1: the typ comparison is case-insensitive")
    void check1TypCaseInsensitive() throws Exception {
        OctetKeyPair key = newKey();
        JWSHeader h =
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new com.nimbusds.jose.JOSEObjectType("DPoP+JWT"))
                        .jwk(key.toPublicJWK())
                        .build();
        String proof = sign(key, h, claims(Map.of()));
        assertDoesNotThrow(() -> DpopVerifier.verifyProof(proof, request(), store));
    }

    /**
     * The attack check 2 exists for, run for real.
     *
     * <p>The attacker holds no private key. They take the <i>public</i> key out of a proof
     * they observed, use its raw bytes as an HMAC secret, sign a proof of their own with
     * HS256, and embed the same public jwk. A verifier that reads alg from the header
     * computes HMAC with that public key, gets a match, and reports success — the signature
     * is valid, just not proof of anything.
     */
    @Test
    @DisplayName("check 2: the public-key-as-HMAC-secret forgery is refused")
    void check2HmacForgery() throws Exception {
        OctetKeyPair key = newKey();
        byte[] publicBytes = key.getX().decode();

        JWSHeader h =
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(new com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
                        .jwk(key.toPublicJWK())
                        .build();
        JWSObject jws = new JWSObject(h, new Payload(claims(Map.of())));
        JWSSigner signer = new MACSigner(publicBytes);
        jws.sign(signer);
        String forged = jws.serialize();

        assertThrows(
                AuthError.class, () -> DpopVerifier.verifyProof(forged, request(), store));
    }

    @Test
    @DisplayName("check 2: an unpermitted key type is refused")
    void check2UnpermittedKeyType() throws Exception {
        OctetKeyPair key = newKey();
        String proof = goodProof(key);
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("alg", "EdDSA");
        h.put("typ", "dpop+jwt");
        h.put("jwk", Map.of("kty", "EC", "crv", "P-521", "x", "AA", "y", "AA"));
        String spliced = spliceHeader(proof, h);
        assertThrows(
                AuthError.class, () -> DpopVerifier.verifyProof(spliced, request(), store));
    }

    @Test
    @DisplayName("check 3: no jwk, or a signature by a different key, is refused")
    void check3BadSignature() throws Exception {
        OctetKeyPair key = newKey();

        Map<String, Object> noJwk = new LinkedHashMap<>();
        noJwk.put("alg", "EdDSA");
        noJwk.put("typ", "dpop+jwt");
        String stripped = spliceHeader(goodProof(key), noJwk);
        AuthError e1 =
                assertThrows(
                        AuthError.class, () -> DpopVerifier.verifyProof(stripped, request(), store));
        assertTrue(e1.getMessage().contains("jwk"), e1.getMessage());

        // Signed by a DIFFERENT key than the one it embeds.
        OctetKeyPair other = newKey();
        String forged = sign(other, header(key.toPublicJWK()), claims(Map.of()));
        assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(forged, request(), store));
    }

    /**
     * RFC 9449 §4.3. Checked against the RAW header JSON, because many JWK libraries
     * silently drop these members when parsing into a public-key type — the check would
     * then pass because the library hid the evidence.
     */
    @Test
    @DisplayName("check 4: private key material in the jwk is refused, by whichever layer sees it")
    void check4PrivateKeyMaterial() throws Exception {
        OctetKeyPair key = newKey();
        String proof = goodProof(key);
        for (String member : new String[] {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}) {
            Map<String, Object> leaky = jwkMap(key);
            leaky.put(member, "c2VjcmV0");
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("alg", "EdDSA");
            h.put("typ", "dpop+jwt");
            h.put("jwk", leaky);
            String spliced = spliceHeader(proof, h);
            // The security outcome is what this asserts: refused, every time. WHICH layer
            // refuses it depends on the member — see the next test.
            assertThrows(
                    AuthError.class,
                    () -> DpopVerifier.verifyProof(spliced, request(), store),
                    "member " + member + " was not caught");
        }
    }

    /**
     * Two layers refuse private key material, and this test pins which does what.
     *
     * <p>Nimbus refuses {@code d} at <i>parse</i> time — it knows {@code d} is OKP's private
     * member, and {@code JWSObject.parse} rejects a non-public jwk outright. The other seven
     * members mean nothing to an OKP key, so Nimbus lets them through and this SDK's own
     * raw-JSON check is what catches them.
     *
     * <p>That is exactly why §21.7.2 check 4 demands the check run against the raw header
     * JSON rather than a parsed key object: relying on the library alone would leave the
     * other seven unguarded here, and on a library that silently <i>drops</i> unknown members
     * it would leave all eight unguarded while appearing to pass.
     */
    @Test
    @DisplayName("check 4: the raw-JSON check catches what the JOSE library does not")
    void check4RawJsonCheckIsNotDeadCode() throws Exception {
        OctetKeyPair key = newKey();
        String proof = goodProof(key);
        for (String member : new String[] {"p", "q", "dp", "dq", "qi", "oth", "k"}) {
            Map<String, Object> leaky = jwkMap(key);
            leaky.put(member, "c2VjcmV0");
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("alg", "EdDSA");
            h.put("typ", "dpop+jwt");
            h.put("jwk", leaky);
            String spliced = spliceHeader(proof, h);
            AuthError e =
                    assertThrows(
                            AuthError.class, () -> DpopVerifier.verifyProof(spliced, request(), store));
            assertTrue(
                    e.getMessage().contains("private key material"),
                    "member " + member + " should be caught by this SDK's own check, got: "
                            + e.getMessage());
        }
    }

    @Test
    @DisplayName("check 5: a proof minted for another method is refused")
    void check5WrongMethod() throws Exception {
        OctetKeyPair key = newKey();
        String proof = sign(key, header(key.toPublicJWK()), claims(Map.of("htm", "GET")));
        AuthError e =
                assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(proof, request(), store));
        assertTrue(e.getMessage().contains("htm"), e.getMessage());
    }

    @Test
    @DisplayName("check 6: a proof minted for another URI is refused")
    void check6WrongUri() throws Exception {
        OctetKeyPair key = newKey();
        String proof =
                sign(
                        key,
                        header(key.toPublicJWK()),
                        claims(Map.of("htu", "https://rs.example.com/v1/other")));
        AuthError e =
                assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(proof, request(), store));
        assertTrue(e.getMessage().contains("htu"), e.getMessage());
    }

    /**
     * A normalising comparison is where two unequal URIs become equal. Only query and
     * fragment come off; case, default ports and trailing slashes are left exactly as they
     * are.
     */
    @Test
    @DisplayName("check 6: htu is compared without normalisation")
    void check6NoNormalisation() {
        assertEquals("https://a.example/p", DpopVerifier.canonicalHtu("https://a.example/p?q=1#f"));
        assertNotEquals(
                DpopVerifier.canonicalHtu("https://A.example/P"),
                DpopVerifier.canonicalHtu("https://a.example/p"));
        assertNotEquals(
                DpopVerifier.canonicalHtu("https://a.example:443/p"),
                DpopVerifier.canonicalHtu("https://a.example/p"));
        assertNotEquals(
                DpopVerifier.canonicalHtu("https://a.example/p/"),
                DpopVerifier.canonicalHtu("https://a.example/p"));
    }

    /**
     * Both directions. A proof from the future is as suspect as a stale one: it is how a
     * one-sided skew allowance becomes a long-lived proof.
     */
    @Test
    @DisplayName("check 7: a stale or future proof is refused")
    void check7Freshness() throws Exception {
        OctetKeyPair key = newKey();
        Instant now = Instant.now();
        for (long offset : new long[] {-65, 65}) {
            String proof =
                    sign(
                            key,
                            header(key.toPublicJWK()),
                            claims(Map.of("iat", now.getEpochSecond() + offset)));
            DpopRequest r =
                    new DpopRequest(METHOD, URI, TOKEN, null, DpopVerifier.IAT_LEEWAY, now);
            AuthError e =
                    assertThrows(
                            AuthError.class,
                            () -> DpopVerifier.verifyProof(proof, r, store),
                            "offset " + offset + " was accepted");
            assertTrue(e.getMessage().contains("freshness window"), e.getMessage());
        }
    }

    /**
     * Freshness bounds the window; the jti guard is what makes the window unusable. Without
     * this the same proof works repeatedly for a full minute.
     */
    @Test
    @DisplayName("check 8: a replayed proof is refused")
    void check8Replay() throws Exception {
        OctetKeyPair key = newKey();
        String proof = goodProof(key);
        assertDoesNotThrow(() -> DpopVerifier.verifyProof(proof, request(), store));
        AuthError e =
                assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(proof, request(), store));
        assertTrue(e.getMessage().contains("replay"), e.getMessage());
    }

    /**
     * The jti claim is a mutation, so it runs last. Claiming it earlier would let an
     * attacker burn arbitrary jti values out of the store using proofs that were never going
     * to verify — turning the replay guard into a denial-of-service surface against
     * legitimate proofs.
     */
    @Test
    @DisplayName("check 8: the jti is claimed only after every other check passes")
    void check8JtiClaimedLast() throws Exception {
        OctetKeyPair key = newKey();
        Map<String, Object> overrides = new LinkedHashMap<>();
        overrides.put("htm", "GET");
        overrides.put("jti", "precious");
        String doomed = sign(key, header(key.toPublicJWK()), claims(overrides));

        assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(doomed, request(), store));

        // That jti is still unused, so a genuine proof carrying it still works.
        assertTrue(
                store.claim("precious", Instant.now().plus(Duration.ofMinutes(1))),
                "a failed proof must not burn its jti");
    }

    /**
     * Without ath, a proof captured on one request can be re-aimed at a different token held
     * by the same key.
     */
    @Test
    @DisplayName("check 9: a proof aimed at another token is refused")
    void check9WrongAth() throws Exception {
        OctetKeyPair key = newKey();
        String proof =
                sign(
                        key,
                        header(key.toPublicJWK()),
                        claims(Map.of("ath", DpopVerifier.accessTokenHash("some.other.token"))));
        AuthError e =
                assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(proof, request(), store));
        assertTrue(e.getMessage().contains("ath"), e.getMessage());
    }

    @Test
    @DisplayName("check 9: a proof with no ath at all is refused")
    void check9MissingAth() throws Exception {
        Map<String, Object> overrides = new LinkedHashMap<>();
        overrides.put("ath", null);
        OctetKeyPair key = newKey();
        String proof = sign(key, header(key.toPublicJWK()), claims(overrides));
        AuthError e =
                assertThrows(AuthError.class, () -> DpopVerifier.verifyProof(proof, request(), store));
        assertTrue(e.getMessage().contains("ath"), e.getMessage());
    }

    /**
     * This is the step that ties the proof to the token; the other nine are what make the
     * proof mean anything.
     */
    @Test
    @DisplayName("check 10: a proof by the wrong key is refused")
    void check10WrongKey() throws Exception {
        OctetKeyPair key = newKey();
        OctetKeyPair other = newKey();
        DpopRequest r = request().withExpectedJkt(other.toPublicJWK().computeThumbprint().toString());
        AuthError e =
                assertThrows(
                        AuthError.class, () -> DpopVerifier.verifyProof(goodProof(key), r, store));
        assertTrue(e.getMessage().contains("cnf.jkt"), e.getMessage());
    }

    // ------------------------------------------------------------------------
    // Thumbprint and framing
    // ------------------------------------------------------------------------

    /**
     * The RFC's own worked example. A thumbprint implementation that is self-consistent but
     * wrong agrees with itself on every round trip, so the only useful test is against a
     * published vector.
     */
    @Test
    @DisplayName("the thumbprint matches the RFC 7638 appendix A vector")
    void rfc7638Vector() throws Exception {
        JWK rsa =
                JWK.parse(
                        "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L"
                            + "hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
                            + "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
                            + "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr"
                            + "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF"
                            + "Cur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\"}");
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", DpopVerifier.thumbprintS256(rsa));
    }

    @Test
    @DisplayName("ath is base64url-unpadded SHA-256 over the token as it travelled")
    void athShape() {
        String ath = DpopVerifier.accessTokenHash(TOKEN);
        assertEquals(43, ath.length());
        assertTrue(ath.indexOf('=') < 0);
        assertEquals(ath, DpopVerifier.accessTokenHash(TOKEN));
        assertNotEquals(ath, DpopVerifier.accessTokenHash(TOKEN + "x"));
    }

    /**
     * RFC 9449 §4.2 makes exactly one the rule. Rejecting beats picking the first, which is
     * how a verifier and a downstream parser end up reading different proofs.
     */
    @Test
    @DisplayName("a header carrying two proofs is refused")
    void twoProofsRefused() throws Exception {
        OctetKeyPair key = newKey();
        String proof = goodProof(key);
        AuthError e =
                assertThrows(
                        AuthError.class,
                        () -> DpopVerifier.verifyProof(proof + "," + proof, request(), store));
        assertTrue(e.getMessage().contains("exactly one proof"), e.getMessage());
    }

    @Test
    @DisplayName("malformed proofs are refused as AuthError, not something else")
    void malformedProofs() {
        for (String junk : new String[] {"", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$"}) {
            assertThrows(
                    AuthError.class,
                    () -> DpopVerifier.verifyProof(junk, request(), store),
                    "accepted " + junk);
        }
    }

    /**
     * All three algorithms §21.7.2 check 2 permits, each verified through the key type that
     * implies it. HMAC families are absent from that list on purpose — a symmetric "proof"
     * verifiable with a key the verifier also holds proves possession of nothing — which is
     * what {@link #check2HmacForgery()} exercises from the other side.
     */
    @Test
    @DisplayName("check 2: all three permitted algorithms verify")
    void check2AllPermittedAlgorithms() throws Exception {
        // PS256, from an RSA key.
        com.nimbusds.jose.jwk.RSAKey rsa =
                new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048).generate();
        JWSObject rsaProof =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.PS256)
                                .type(new com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
                                .jwk(rsa.toPublicJWK())
                                .build(),
                        new Payload(claims(Map.of())));
        rsaProof.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsa));
        assertEquals(
                rsa.toPublicJWK().computeThumbprint().toString(),
                DpopVerifier.verifyProof(rsaProof.serialize(), request(), store));

        // ES256, from a P-256 key.
        com.nimbusds.jose.jwk.ECKey ec =
                new com.nimbusds.jose.jwk.gen.ECKeyGenerator(Curve.P_256).generate();
        JWSObject ecProof =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.ES256)
                                .type(new com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
                                .jwk(ec.toPublicJWK())
                                .build(),
                        new Payload(claims(Map.of())));
        ecProof.sign(new com.nimbusds.jose.crypto.ECDSASigner(ec));
        assertEquals(
                ec.toPublicJWK().computeThumbprint().toString(),
                DpopVerifier.verifyProof(ecProof.serialize(), request(), store));

        // EdDSA is the happy path everywhere else in this suite.
        OctetKeyPair okp = newKey();
        assertEquals(
                okp.toPublicJWK().computeThumbprint().toString(),
                DpopVerifier.verifyProof(goodProof(okp), request(), store));
    }

    /**
     * The thumbprint ignores members outside RFC 7638's set — which is exactly what makes it
     * stable across two different encodings of the same key.
     */
    @Test
    @DisplayName("the thumbprint ignores members outside the RFC 7638 set")
    void thumbprintIgnoresDecoration() throws Exception {
        OctetKeyPair key = newKey();
        Map<String, Object> decorated = jwkMap(key);
        decorated.put("kid", "abc");
        decorated.put("use", "sig");
        decorated.put("alg", "EdDSA");
        JWK plain = key.toPublicJWK();
        assertEquals(
                DpopVerifier.thumbprintS256(plain),
                DpopVerifier.thumbprintS256(JWK.parse(decorated)));
    }

    /** The x coordinate round-trips through base64url, as JOSE requires. */
    @Test
    @DisplayName("the proof key round-trips through its base64url encoding")
    void base64UrlRoundTrip() throws Exception {
        OctetKeyPair key = newKey();
        Base64URL x = key.getX();
        assertEquals(x.toString(), Base64URL.encode(x.decode()).toString());
    }
}
