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
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The contract 1.51 rule-9 fix, at {@link AxiamAuthenticationFilter} — the SDK's default
 * servlet-container guard — over a REAL {@code X509Certificate}, presented the way a
 * servlet container actually presents one: the standard
 * {@code jakarta.servlet.request.X509Certificate} request attribute, never a header.
 *
 * <p>This is the "own connection" half of CONTRACT.md &sect;10.1 rule 9's table.
 * {@code JwksVerifierLocalVerificationSetTest}/{@code TokenBindingTest} already cover the
 * claims-level decision table exhaustively with synthetic claims; what this file adds is
 * that the FILTER — the entry point a real application wires up — actually reads its
 * evidence from the connection object a servlet container populates, not from
 * something a request could set itself.
 */
class ServletBoundTokenTest {

    private static final String CONFIGURED_TENANT = "tenant-a";

    @TempDir
    Path tempDir;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private static X509Certificate toX509(byte[] pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(pem));
    }

    @Test
    void ownCertificateOnTheConnectionIsAccepted() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        Identity device = TestCerts.selfSignedIdentity(tempDir, "device-under-test");
        X509Certificate deviceCert = toX509(device.certPem());
        String thumbprint = JwksVerifier.certificateThumbprintS256(deviceCert.getEncoded());

        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, boundClaims(thumbprint));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            request.setAttribute("jakarta.servlet.request.X509Certificate",
                    new X509Certificate[] {deviceCert});
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "the connection presented the SAME certificate the "
                    + "token is bound to — it must be accepted");
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void aDifferentCertificateOnTheConnectionIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        Identity device = TestCerts.selfSignedIdentity(tempDir, "device-under-test-2");
        Identity attacker = TestCerts.selfSignedIdentity(tempDir, "not-the-device");
        String deviceThumbprint =
                JwksVerifier.certificateThumbprintS256(toX509(device.certPem()).getEncoded());

        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, boundClaims(deviceThumbprint));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            // The CONNECTION presented a different certificate than the one the token
            // names — the theft scenario rule 9 exists to close.
            request.setAttribute("jakarta.servlet.request.X509Certificate",
                    new X509Certificate[] {toX509(attacker.certPem())});
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked);
            assertEquals(401, response.getStatus());
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    /**
     * The regression this whole fix exists for: a device token, lifted off the device
     * (no certificate on THIS connection at all), must be refused — not accepted the way
     * it was before the contract 1.51 fix.
     */
    @Test
    void aBoundTokenWithNoCertificateOnTheConnectionIsRejected() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        Identity device = TestCerts.selfSignedIdentity(tempDir, "device-under-test-3");
        String thumbprint =
                JwksVerifier.certificateThumbprintS256(toX509(device.certPem()).getEncoded());

        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, boundClaims(thumbprint));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            // No jakarta.servlet.request.X509Certificate attribute at all — an ordinary
            // (non-mTLS) connection, exactly what a stolen device token rides in on.
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "a device token replayed with no certificate on this "
                    + "connection must be refused — the contract 1.51 fix this test exists for");
            assertEquals(401, response.getStatus());
        }
    }

    /** The I4 twin: an ordinary, unbound token is completely unaffected by the fix. */
    @Test
    void anUnboundTokenIsUnaffectedWithOrWithoutACertificateOnTheConnection() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair();
        Identity device = TestCerts.selfSignedIdentity(tempDir, "device-under-test-4");

        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);
            String token = signEdDsa(keyPair, unboundClaims());

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            request.setAttribute("jakarta.servlet.request.X509Certificate",
                    new X509Certificate[] {toX509(device.certPem())});
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked);
            assertEquals(200, response.getStatus());
        }
    }

    // ------------------------------------------------------------------
    // Fixtures (mirrors AxiamAuthenticationFilterTest's, kept file-local so this
    // file's rule-9 focus is not tangled with that file's own scenarios)
    // ------------------------------------------------------------------

    private static AxiamAuthenticationFilter filterFor(MockWebServer server, String configuredTenantId) {
        JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
        return new AxiamAuthenticationFilter(verifier, configuredTenantId);
    }

    private static MockWebServer startJwksServer(OctetKeyPair keyPair) throws Exception {
        MockWebServer server = new MockWebServer();
        for (int i = 0; i < 4; i++) {
            server.enqueue(new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody(new JWKSet(keyPair.toPublicJWK()).toString()));
        }
        server.start();
        return server;
    }

    private static OctetKeyPair generateEd25519KeyPair() throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-1").generate();
    }

    private static JWTClaimsSet unboundClaims() {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", CONFIGURED_TENANT)
                .claim("scope", "users:read")
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .build();
    }

    private static JWTClaimsSet boundClaims(String thumbprint) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", CONFIGURED_TENANT)
                .claim("scope", "users:read")
                .claim("cnf", Map.of("x5t#S256", thumbprint))
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

    private static final class RecordingFilterChain implements jakarta.servlet.FilterChain {
        boolean invoked;

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
            invoked = true;
        }
    }
}
