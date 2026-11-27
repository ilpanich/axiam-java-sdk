package io.axiam.sdk.internal;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.testutil.OidcTestSupport;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JWKS fetch client is built per verifier: it carries the TLS context it was given (CONTRACT.md &sect;6
 * {@code customCa}) and reads the JVM proxy settings at construction, not at class load.
 */
class JwksVerifierTlsTest {

    private static final String TENANT = "tenant-a";

    @TempDir
    Path tempDir;

    private static MockWebServer httpsServer(Identity identity, OctetKeyPair key, int responses) throws Exception {
        return httpsServer(identity, null, key, responses);
    }

    /** An HTTPS JWKS server; with {@code requiredClientCertPem} it demands that exact client certificate. */
    private static MockWebServer httpsServer(Identity identity, byte[] requiredClientCertPem, OctetKeyPair key,
            int responses) throws Exception {
        javax.net.ssl.TrustManager[] trust = null;
        if (requiredClientCertPem != null) {
            java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("client", java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(requiredClientCertPem)));
            javax.net.ssl.TrustManagerFactory tmf =
                    javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            trust = tmf.getTrustManagers();
        }
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(TlsSupport.keyManagers(identity.certPem(), identity.keyPem()), trust, new SecureRandom());
        MockWebServer mock = new MockWebServer();
        mock.useHttps(serverContext.getSocketFactory(), false);
        if (requiredClientCertPem != null) {
            mock.requireClientAuth();
        }
        for (int i = 0; i < responses; i++) {
            mock.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
        }
        mock.start(java.net.InetAddress.getByName("0.0.0.0"), 0); // wildcard: 127.0.0.2 must reach it too
        return mock;
    }

    private static String token(OctetKeyPair key) throws Exception {
        return OidcTestSupport.signEdDsa(key, new JWTClaimsSet.Builder()
                .subject("user-1").claim("tenant_id", TENANT)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000)).build());
    }

    @Test
    void aVerifierGivenACustomCaFetchesTheJwksThroughIt() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-tls");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer mock = httpsServer(server, key, 1)) {
            JwksVerifier verifier = new JwksVerifier("https://127.0.0.1:" + mock.getPort(),
                    JwksVerifier.LocalVerificationPolicy.defaults(), null, server.certPem(), null, null);

            JWTClaimsSet claims = verifier.verifySignatureOnlyUnchecked(token(key));

            assertEquals(TENANT, claims.getStringClaim("tenant_id"));
        }
    }

    @Test
    void aVerifierWithoutTheCaStillFailsClosed() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-tls-neg");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer mock = httpsServer(server, key, 1)) {
            JwksVerifier verifier = new JwksVerifier("https://127.0.0.1:" + mock.getPort());

            assertThrows(AuthError.class, () -> verifier.verifySignatureOnlyUnchecked(token(key)));
        }
    }

    @Test
    void theTlsContextIsPerVerifierNotSharedAcrossThem() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-tls-iso");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer mock = httpsServer(server, key, 2)) {
            String base = "https://127.0.0.1:" + mock.getPort();
            JwksVerifier plain = new JwksVerifier(base);
            JwksVerifier trusting = new JwksVerifier(base, JwksVerifier.LocalVerificationPolicy.defaults(), null,
                    server.certPem(), null, null);

            // The plain one is built (and fails) first: a static client would have frozen its context for both.
            assertThrows(AuthError.class, () -> plain.verifySignatureOnlyUnchecked(token(key)));
            assertEquals(TENANT, trusting.verifySignatureOnlyUnchecked(token(key)).getStringClaim("tenant_id"));
        }
    }

    @Test
    void aTrustedCaDoesNotRelaxHostnameVerification() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-tls-host");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer mock = httpsServer(server, key, 2)) {
            // 127.0.0.2 reaches the same listener, but the certificate names only localhost and 127.0.0.1.
            try (java.net.Socket probe = new java.net.Socket("127.0.0.2", mock.getPort())) {
                assertTrue(probe.isConnected(), "the mismatched name must be reachable, or this proves nothing");
            }
            JwksVerifier mismatched = new JwksVerifier("https://127.0.0.2:" + mock.getPort(),
                    JwksVerifier.LocalVerificationPolicy.defaults(), null, server.certPem(), null, null);
            assertThrows(AuthError.class, () -> mismatched.verifySignatureOnlyUnchecked(token(key)));

            JwksVerifier matching = new JwksVerifier("https://127.0.0.1:" + mock.getPort(),
                    JwksVerifier.LocalVerificationPolicy.defaults(), null, server.certPem(), null, null);
            assertEquals(TENANT, matching.verifySignatureOnlyUnchecked(token(key)).getStringClaim("tenant_id"));
        }
    }

    @Test
    void customCaAddsToTheDefaultTrustStoreRatherThanReplacingIt() throws Exception {
        Identity defaultStoreServer = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-default-store");
        Identity customServer = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-custom-ca");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");

        // A test "default" trust store holding only the first server's certificate.
        java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("default-anchor", java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(defaultStoreServer.certPem())));
        Path storeFile = tempDir.resolve("default-trust.p12");
        try (java.io.OutputStream out = java.nio.file.Files.newOutputStream(storeFile)) {
            ts.store(out, "changeit".toCharArray());
        }
        String[] props = {"javax.net.ssl.trustStore", "javax.net.ssl.trustStoreType", "javax.net.ssl.trustStorePassword"};
        String[] saved = new String[props.length];
        for (int n = 0; n < props.length; n++) {
            saved[n] = System.getProperty(props[n]);
        }
        System.setProperty(props[0], storeFile.toString());
        System.setProperty(props[1], "PKCS12");
        System.setProperty(props[2], "changeit");
        try (MockWebServer viaDefault = httpsServer(defaultStoreServer, key, 1);
                MockWebServer viaCustom = httpsServer(customServer, key, 1)) {
            // customCa names ONLY the second server; the first is trusted by the default store alone.
            JwksVerifier fromDefault = new JwksVerifier("https://127.0.0.1:" + viaDefault.getPort(),
                    JwksVerifier.LocalVerificationPolicy.defaults(), null, customServer.certPem(), null, null);
            JwksVerifier fromCustom = new JwksVerifier("https://127.0.0.1:" + viaCustom.getPort(),
                    JwksVerifier.LocalVerificationPolicy.defaults(), null, customServer.certPem(), null, null);

            assertEquals(TENANT, fromDefault.verifySignatureOnlyUnchecked(token(key)).getStringClaim("tenant_id"));
            assertEquals(TENANT, fromCustom.verifySignatureOnlyUnchecked(token(key)).getStringClaim("tenant_id"));
        } finally {
            for (int n = 0; n < props.length; n++) {
                if (saved[n] == null) {
                    System.clearProperty(props[n]);
                } else {
                    System.setProperty(props[n], saved[n]);
                }
            }
        }
    }

    @Test
    void theClientIdentityIsPresentedOnlyToTheSameOriginJwks() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-tls-mtls");
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-jwks-client");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer mock = httpsServer(server, client.certPem(), key, 3)) {
            String jwksUri = "https://127.0.0.1:" + mock.getPort() + "/oauth2/jwks";
            String sameBase = "https://127.0.0.1:" + mock.getPort();
            String otherBase = "https://axiam.example.invalid";

            JwksVerifier same = JwksVerifier.forJwksUri(jwksUri, sameBase, server.certPem(),
                    client.certPem(), client.keyPem());
            assertEquals(TENANT, same.verifySignatureOnlyUnchecked(token(key)).getStringClaim("tenant_id"));

            // Another origin (§12.3 rule 6): trust only, no identity, so the mutual-TLS listener refuses it.
            JwksVerifier other = JwksVerifier.forJwksUri(jwksUri, otherBase, server.certPem(),
                    client.certPem(), client.keyPem());
            assertThrows(AuthError.class, () -> other.verifySignatureOnlyUnchecked(token(key)));
        }
    }

    @Test
    void sameOriginComparesSchemeHostAndEffectivePort() throws Exception {
        java.net.URL base = URI.create("https://Axiam.Example/").toURL();
        assertTrue(JwksVerifier.sameOrigin(URI.create("https://axiam.example:443/x").toURL(), base));
        org.junit.jupiter.api.Assertions.assertFalse(
                JwksVerifier.sameOrigin(URI.create("https://axiam.example:8443/x").toURL(), base));
        org.junit.jupiter.api.Assertions.assertFalse(
                JwksVerifier.sameOrigin(URI.create("http://axiam.example/x").toURL(), base));
        org.junit.jupiter.api.Assertions.assertFalse(
                JwksVerifier.sameOrigin(URI.create("https://other.example/x").toURL(), base));
    }

    @Test
    void theProxySelectorIsReadWhenTheVerifierIsBuilt() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        new JwksVerifier("http://localhost:1"); // class initialisation happens BEFORE the selector below exists
        AtomicInteger consulted = new AtomicInteger();
        ProxySelector previous = ProxySelector.getDefault();
        ProxySelector.setDefault(new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                consulted.incrementAndGet();
                return List.of(Proxy.NO_PROXY);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            }
        });
        try (MockWebServer mock = new MockWebServer()) {
            mock.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
            mock.start();
            JwksVerifier verifier = new JwksVerifier(mock.url("/").toString());

            verifier.verifySignatureOnlyUnchecked(token(key));

            assertTrue(consulted.get() > 0, "the selector installed before construction must be the one consulted");
        } finally {
            ProxySelector.setDefault(previous);
        }
    }
}
