package io.axiam.sdk.spring;

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

import io.axiam.sdk.internal.JwksVerifier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for {@link AxiamAuthenticationFilter} (20-06 acceptance
 * criteria): a matching-tenant valid token authenticates AND a
 * valid-signature wrong-tenant token is rejected (cross-tenant control is
 * enforced, non-vacuous), an expired token is rejected, and a request with
 * no token passes through unauthenticated. Uses a {@link MockFilterChain} +
 * {@link JwksVerifier} backed by a real {@link MockWebServer} (same pattern
 * as {@code JwksVerifierTest}) rather than a full Spring
 * {@code ApplicationContext}.
 */
class AxiamAuthenticationFilterTest {

    private static final String CONFIGURED_TENANT = "tenant-a";

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void matchingTenantValidTokenAuthenticatesAndReachesProtectedEndpoint() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "the protected endpoint (downstream filter chain) must be reached");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertEquals("user-1", auth.getName());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void validSignatureWrongTenantTokenIsRejectedEvenThoughSignatureIsValid() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            // Validly signed by the SAME key/JWKS, but minted for a different tenant —
            // proves the cross-tenant replay defense (T-20-07), not just signature checking.
            String wrongTenantToken = signEdDsa(keyPair, claims("tenant-b", 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + wrongTenantToken);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "the protected endpoint must NOT be reached for a cross-tenant token");
            assertEquals(401, response.getStatus());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
            assertTrue(response.getContentAsString().contains("authentication_failed"));
        }
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            // Well beyond the §10.1 rule 7 clock-skew leeway, so this asserts
            // expiry rather than sitting on the skew boundary.
            String expiredToken = signEdDsa(keyPair, claims(CONFIGURED_TENANT, -3_600_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + expiredToken);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "the protected endpoint must NOT be reached for an expired token");
            assertEquals(401, response.getStatus());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    @Test
    void noTokenPassesThroughUnauthenticated() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);

            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "an unauthenticated request must reach the chain so Spring Security's own"
                    + " access-control rules can 401/403 it");
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    // --- CONTRACT.md §10.1 minimum local-verification set, at the filter ---

    /**
     * The full §10.1 required negative set, asserted through the filter
     * itself rather than only at {@code JwksVerifier}: expired; <b>no</b>
     * {@code exp}; non-numeric {@code exp}; future {@code nbf}; different
     * tenant; no {@code tenant_id}; {@code alg: none}; and an HS-signed token
     * bearing the EdDSA {@code kid}. Each must 401 without reaching the
     * protected endpoint and without populating the SecurityContext.
     */
    @Test
    void filterRejectsTheWholeSection101NegativeSet() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);

            long nowSeconds = System.currentTimeMillis() / 1000L;
            java.util.Map<String, String> negatives = new java.util.LinkedHashMap<>();
            negatives.put("expired", signEdDsa(keyPair, claims(CONFIGURED_TENANT, -3_600_000)));
            negatives.put(
                    "no exp",
                    signEdDsa(
                            keyPair,
                            new JWTClaimsSet.Builder()
                                    .subject("user-1")
                                    .claim("tenant_id", CONFIGURED_TENANT)
                                    .build()));
            negatives.put(
                    "non-numeric exp",
                    signEdDsaRawPayload(keyPair, java.util.Map.of(
                            "sub", "user-1", "tenant_id", CONFIGURED_TENANT, "exp", "not-a-number")));
            negatives.put(
                    "future nbf",
                    signEdDsa(
                            keyPair,
                            new JWTClaimsSet.Builder()
                                    .subject("user-1")
                                    .claim("tenant_id", CONFIGURED_TENANT)
                                    .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                                    .notBeforeTime(new Date(System.currentTimeMillis() + 3_600_000))
                                    .build()));
            negatives.put("different tenant", signEdDsa(keyPair, claims("tenant-b", 900_000)));
            negatives.put(
                    "no tenant_id",
                    signEdDsa(
                            keyPair,
                            new JWTClaimsSet.Builder()
                                    .subject("user-1")
                                    .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                                    .build()));
            negatives.put("alg:none", unsignedAlgNoneToken(nowSeconds + 900));
            negatives.put("HS256 with an EdDSA kid", signHs256WithEdDsaKid(claims(CONFIGURED_TENANT, 900_000)));

            for (var entry : negatives.entrySet()) {
                SecurityContextHolder.clearContext();
                MockHttpServletRequest request = new MockHttpServletRequest();
                request.addHeader("Authorization", "Bearer " + entry.getValue());
                MockHttpServletResponse response = new MockHttpServletResponse();
                RecordingFilterChain chain = new RecordingFilterChain();

                filter.doFilter(request, response, chain);

                assertFalse(chain.invoked, entry.getKey() + " must not reach the protected endpoint");
                assertEquals(401, response.getStatus(), entry.getKey() + " must 401");
                assertNull(SecurityContextHolder.getContext().getAuthentication(), entry.getKey());
                assertFalse(
                        response.getContentAsString().contains(entry.getValue()),
                        entry.getKey() + " must not echo the token");
            }
        }
    }

    /**
     * §10.1 rules 5-6 through the filter: with an expected issuer and
     * audience configured, the matching token authenticates (non-vacuous) and
     * each mismatch 401s.
     */
    @Test
    void filterHonoursConfiguredIssuerAndAudience() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(
                    server.url("/").toString(),
                    new JwksVerifier.LocalVerificationPolicy(
                            "https://axiam.example",
                            JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE,
                            JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS));
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT);

            String matching = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .claim("tenant_id", CONFIGURED_TENANT)
                            .issuer("https://axiam.example")
                            .audience(JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE)
                            .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                            .build());

            MockHttpServletRequest okRequest = new MockHttpServletRequest();
            okRequest.addHeader("Authorization", "Bearer " + matching);
            MockHttpServletResponse okResponse = new MockHttpServletResponse();
            RecordingFilterChain okChain = new RecordingFilterChain();
            filter.doFilter(okRequest, okResponse, okChain);
            assertTrue(okChain.invoked, "a token matching the configured issuer and audience must authenticate");

            String wrongIssuer = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .claim("tenant_id", CONFIGURED_TENANT)
                            .issuer("https://evil.example")
                            .audience(JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE)
                            .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                            .build());
            String wrongAudience = signEdDsa(
                    keyPair,
                    new JWTClaimsSet.Builder()
                            .subject("user-1")
                            .claim("tenant_id", CONFIGURED_TENANT)
                            .issuer("https://axiam.example")
                            .audience("someone-else")
                            .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                            .build());

            for (String bad : new String[] {wrongIssuer, wrongAudience}) {
                SecurityContextHolder.clearContext();
                MockHttpServletRequest request = new MockHttpServletRequest();
                request.addHeader("Authorization", "Bearer " + bad);
                MockHttpServletResponse response = new MockHttpServletResponse();
                RecordingFilterChain chain = new RecordingFilterChain();

                filter.doFilter(request, response, chain);

                assertFalse(chain.invoked, "an iss/aud mismatch must not reach the protected endpoint");
                assertEquals(401, response.getStatus());
            }
        }
    }

    // --- CSRF cookie double-submit (CR: java/spring-disabled-csrf-protection) ---

    @Test
    void cookieAuthenticatedStatePassingPostWithoutCsrfHeaderIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setMethod("POST");
            request.setCookies(new Cookie("axiam_access", token), new Cookie("axiam_csrf", "csrf-abc"));
            // No X-CSRF-Token header attached.
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "a cookie-authenticated state-changing request without a CSRF header must be rejected");
            assertEquals(403, response.getStatus());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
            assertTrue(response.getContentAsString().contains("csrf_validation_failed"));
        }
    }

    @Test
    void cookieAuthenticatedPostWithMatchingCsrfHeaderPassesAuth() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setMethod("POST");
            request.setCookies(new Cookie("axiam_access", token), new Cookie("axiam_csrf", "csrf-abc"));
            request.addHeader("X-CSRF-Token", "csrf-abc");
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "a matching double-submit CSRF token must let the request through");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertEquals("user-1", auth.getName());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void bearerAuthenticatedPostWithoutCsrfHeaderPassesAuth() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setMethod("POST");
            request.addHeader("Authorization", "Bearer " + token);
            // No CSRF cookie/header at all — a Bearer-header request is CSRF-immune
            // by construction (a cross-site attacker cannot set custom headers).
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "Bearer-header auth must never require a CSRF token");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertEquals("user-1", auth.getName());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void cookieAuthenticatedGetWithoutCsrfHeaderPassesAuth() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT, 900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setMethod("GET");
            request.setCookies(new Cookie("axiam_access", token));
            // No CSRF cookie/header — a safe method must not require one.
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "a GET must never require a CSRF token, even when cookie-authenticated");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertEquals("user-1", auth.getName());
            assertEquals(200, response.getStatus());
        }
    }

    private static AxiamAuthenticationFilter filterFor(MockWebServer server, String configuredTenantId) {
        JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
        return new AxiamAuthenticationFilter(verifier, configuredTenantId);
    }

    private static MockWebServer startJwksServer(OctetKeyPair keyPair) throws Exception {
        MockWebServer server = new MockWebServer();
        // Enqueue generously: RemoteJWKSet may re-fetch on cache-miss checks
        // across the four independent test methods sharing this helper.
        for (int i = 0; i < 4; i++) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
        }
        server.start();
        return server;
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static JWTClaimsSet claims(String tenantId, long expiresInMillis) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", tenantId)
                .claim("scope", "users:read users:write")
                .expirationTime(new Date(System.currentTimeMillis() + expiresInMillis))
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

    /**
     * Signs an arbitrary JSON payload — needed for wrong-typed claims that
     * {@link JWTClaimsSet.Builder} would coerce or refuse to hold.
     */
    private static String signEdDsaRawPayload(OctetKeyPair keyPair, java.util.Map<String, Object> payload)
            throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        com.nimbusds.jose.JWSObject jws =
                new com.nimbusds.jose.JWSObject(header, new com.nimbusds.jose.Payload(payload));
        jws.sign(new Ed25519Signer(keyPair));
        return jws.serialize();
    }

    /** An HS256 token whose {@code kid} names the published EdDSA key. */
    private static String signHs256WithEdDsaKid(JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .keyID("key-1")
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new com.nimbusds.jose.crypto.MACSigner(
                "some-shared-secret-key-material-32b".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    /** Hand-assembles an {@code alg: none} token; no signer will emit one. */
    private static String unsignedAlgNoneToken(long expSeconds) {
        java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString(
                "{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"key-1\"}"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payload = b64.encodeToString(
                ("{\"sub\":\"user-1\",\"tenant_id\":\"" + CONFIGURED_TENANT + "\",\"exp\":" + expSeconds + "}")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return header + "." + payload + ".";
    }

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(java.util.List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    /** Records whether the downstream chain (the protected endpoint) was reached. */
    private static final class RecordingFilterChain implements FilterChain {
        private boolean invoked = false;

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
            invoked = true;
        }
    }
}
