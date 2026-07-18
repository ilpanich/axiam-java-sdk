package io.axiam.sdk;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;6.1: real end-to-end mutual-TLS coverage for the REST
 * transport. A {@code MockWebServer} is stood up with {@code requireClientAuth()}
 * and a trust store containing only the freshly-generated test client
 * certificate, so the handshake completes ONLY when {@code AxiamClient} presents
 * the matching client identity via {@link AxiamClient.Builder#clientCertificate(byte[], byte[])}.
 * Plus construction-time validation (both-or-neither, malformed PEM).
 *
 * <p>All PKI is generated at test time into the {@code @TempDir} — no key
 * material is ever committed.
 */
class AxiamClientMtlsTest {

    @TempDir
    Path tempDir;

    @Test
    void clientPresentingItsCertificateCompletesTheMutualTlsHandshake() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-mtls-server");
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-mtls-client");
        SSLContext serverContext = serverSslContext(server, client.certPem());

        try (MockWebServer mockServer = new MockWebServer()) {
            mockServer.useHttps(serverContext.getSocketFactory(), false);
            mockServer.requireClientAuth();
            mockServer.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));

            String baseUrl = "https://127.0.0.1:" + mockServer.getPort();
            try (AxiamClient authed = AxiamClient.builder(baseUrl, "acme")
                    .customCa(server.certPem())
                    .clientCertificate(client.certPem(), client.keyPem())
                    .build()) {
                AxiamClient.AccessResult result = authed.checkAccess("read", "documents/1");
                assertTrue(result.allowed(),
                        "the mTLS handshake must succeed and the authz response be returned");
            }
        }
    }

    @Test
    void clientWithoutACertificateFailsTheMutualTlsHandshake() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-mtls-server-2");
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-mtls-client-2");
        SSLContext serverContext = serverSslContext(server, client.certPem());

        try (MockWebServer mockServer = new MockWebServer()) {
            mockServer.useHttps(serverContext.getSocketFactory(), false);
            mockServer.requireClientAuth();
            mockServer.enqueue(new MockResponse().setResponseCode(200).setBody("{\"allowed\":true}"));

            // Trusts the server (customCa) but presents NO client identity — the
            // server's requireClientAuth() rejects the handshake, surfacing as a
            // NetworkError from the SDK.
            try (AxiamClient noCert = AxiamClient.builder(mockServer.url("/").toString(), "acme")
                    .customCa(server.certPem())
                    .build()) {
                assertThrows(NetworkError.class, () -> noCert.checkAccess("read", "documents/1"),
                        "a server requiring client auth must reject a client with no certificate");
            }
        }
    }

    @Test
    void clientCertificateWithoutAKeyIsRejectedAtBuild() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-halfconfig-1");
        AxiamClient.Builder builder = AxiamClient.builder("https://axiam.example.com", "acme")
                .clientCertificate(client.certPem(), null);
        assertThrows(IllegalArgumentException.class, builder::build,
                "supplying a certificate without a private key must fail at build()");
    }

    @Test
    void clientKeyWithoutACertificateIsRejectedAtBuild() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-halfconfig-2");
        AxiamClient.Builder builder = AxiamClient.builder("https://axiam.example.com", "acme")
                .clientCertificate(null, client.keyPem());
        assertThrows(IllegalArgumentException.class, builder::build,
                "supplying a private key without a certificate must fail at build()");
    }

    @Test
    void malformedClientCertificatePemIsRejectedAtBuild() {
        AxiamClient.Builder builder = AxiamClient.builder("https://axiam.example.com", "acme")
                .clientCertificate("not a certificate".getBytes(), "not a key".getBytes());
        assertThrows(NetworkError.class, builder::build,
                "a non-PEM client certificate must surface as a clear error at construction time");
    }

    @Test
    void malformedClientKeyWithAValidCertificateIsRejectedAtBuild() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-badkey");
        AxiamClient.Builder builder = AxiamClient.builder("https://axiam.example.com", "acme")
                .clientCertificate(client.certPem(), "-----BEGIN PRIVATE KEY-----\nnotbase64!!\n-----END PRIVATE KEY-----".getBytes());
        assertThrows(NetworkError.class, builder::build,
                "a malformed private key must surface as a clear error at construction time");
    }

    @Test
    void mtlsClientStillHasNoClientCertGetterAndDoesNotLeakInToString() throws Exception {
        Identity client = TestCerts.selfSignedIdentity(tempDir, "axiam-secrecy");
        try (AxiamClient c = AxiamClient.builder("https://axiam.example.com", "acme")
                .clientCertificate(client.certPem(), client.keyPem())
                .build()) {
            // §7: the private key must never appear in toString()/logs.
            assertFalse(c.toString().contains("PRIVATE KEY"),
                    "toString() must never expose client key material");
        }
    }

    // ------------------------------------------------------------------
    // Test-side server: server identity + a trust store that trusts ONLY the
    // freshly-generated client certificate (its own self-signed anchor).
    // ------------------------------------------------------------------

    private static SSLContext serverSslContext(Identity serverId, byte[] clientCertPem) throws Exception {
        char[] pw = "changeit".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", parsePkcs8(serverId.keyPem()), pw,
                new Certificate[]{parseCert(serverId.certPem())});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, pw);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("client-anchor", parseCert(clientCertPem));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return ctx;
    }

    private static X509Certificate parseCert(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static PrivateKey parsePkcs8(byte[] pem) throws Exception {
        String body = new String(pem, java.nio.charset.StandardCharsets.US_ASCII)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
