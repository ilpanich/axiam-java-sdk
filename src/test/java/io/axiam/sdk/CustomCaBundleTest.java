package io.axiam.sdk;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.TlsSupport;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;6: {@code customCa} is a PEM <em>bundle</em>. The REST transport and the JWKS fetch must
 * trust every certificate in it (a root plus an intermediate, or two roots during a CA rotation) and must give
 * the same answers; neither may weaken verification.
 */
class CustomCaBundleTest {

    @TempDir
    Path tempDir;

    private static byte[] concat(byte[]... parts) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p);
        }
        return out.toByteArray();
    }

    private static X509Certificate parse(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static X509TrustManager restTrustManager(byte[] pem) throws Exception {
        Method m = AxiamClient.class.getDeclaredMethod("buildTrustManager", byte[].class);
        m.setAccessible(true);
        try {
            return (X509TrustManager) m.invoke(null, (Object) pem);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    /** HTTPS server presenting {@code server}'s certificate, answering one authz call "allowed". */
    private static MockWebServer httpsServer(Identity server) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(TlsSupport.keyManagers(server.certPem(), server.keyPem()), null, new SecureRandom());
        MockWebServer mock = new MockWebServer();
        mock.useHttps(ctx.getSocketFactory(), false);
        mock.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
        mock.start(InetAddress.getByName("0.0.0.0"), 0); // wildcard: 127.0.0.2 reaches it too
        return mock;
    }

    // ---- REST, end to end --------------------------------------------------------------------

    @Test
    void restTrustsTheSecondCertificateOfABundle() throws Exception {
        byte[] ca1 = TestCerts.selfSignedCertPem(tempDir, "bundle-ca-1");
        Identity ca2 = TestCerts.selfSignedIdentity(tempDir, "bundle-ca-2");
        try (MockWebServer mock = httpsServer(ca2);
             AxiamClient c = AxiamClient.builder("https://127.0.0.1:" + mock.getPort(), "acme")
                     .customCa(concat(ca1, ca2.certPem())).build()) {
            assertTrue(c.checkAccess("read", "documents/1").allowed(),
                    "a server under CA-2 (second in the bundle) must be trusted over REST");
        }
    }

    @Test
    void restStillRefusesAServerUnderNeitherCa() throws Exception {
        byte[] ca1 = TestCerts.selfSignedCertPem(tempDir, "bundle-ca-1b");
        byte[] ca2 = TestCerts.selfSignedCertPem(tempDir, "bundle-ca-2b");
        Identity stranger = TestCerts.selfSignedIdentity(tempDir, "bundle-stranger");
        try (MockWebServer mock = httpsServer(stranger);
             AxiamClient c = AxiamClient.builder("https://127.0.0.1:" + mock.getPort(), "acme")
                     .customCa(concat(ca1, ca2)).build()) {
            assertThrows(NetworkError.class, () -> c.checkAccess("read", "documents/1"));
        }
    }

    @Test
    void restStillRefusesAHostnameMismatchEvenUnderATrustedCa() throws Exception {
        byte[] ca1 = TestCerts.selfSignedCertPem(tempDir, "bundle-ca-1c");
        Identity ca2 = TestCerts.selfSignedIdentity(tempDir, "bundle-ca-2c"); // SAN: localhost, 127.0.0.1
        try (MockWebServer mock = httpsServer(ca2);
             AxiamClient c = AxiamClient.builder("https://127.0.0.2:" + mock.getPort(), "acme")
                     .customCa(concat(ca1, ca2.certPem())).build()) {
            assertThrows(NetworkError.class, () -> c.checkAccess("read", "documents/1"),
                    "trusted CA but the certificate does not name 127.0.0.2: must still be refused");
        }
    }

    // ---- REST and JWKS agree -----------------------------------------------------------------

    @Test
    void restAndJwksTrustManagersGiveTheSameAnswersOnABundle() throws Exception {
        byte[] ca1 = TestCerts.selfSignedCertPem(tempDir, "bundle-ca-1d");
        byte[] ca2 = TestCerts.selfSignedCertPem(tempDir, "bundle-ca-2d");
        byte[] other = TestCerts.selfSignedCertPem(tempDir, "bundle-other-d");
        byte[] bundle = concat(ca1, ca2);

        for (X509TrustManager tm : new X509TrustManager[] {restTrustManager(bundle), TlsSupport.trustManager(bundle)}) {
            assertDoesNotThrow(() -> tm.checkServerTrusted(new X509Certificate[] {parse(ca1)}, "RSA"));
            assertDoesNotThrow(() -> tm.checkServerTrusted(new X509Certificate[] {parse(ca2)}, "RSA"));
            X509Certificate stranger = parse(other);
            assertThrows(CertificateException.class,
                    () -> tm.checkServerTrusted(new X509Certificate[] {stranger}, "RSA"));
        }
    }

    // ---- refusal never echoes the content -----------------------------------------------------

    @Test
    void emptyOfCertificatesBundleIsRefusedWithoutEchoingIt() throws Exception {
        String secretLooking = "S3CR3T-PAYLOAD-MARKER not a certificate";
        byte[] junk = secretLooking.getBytes(StandardCharsets.UTF_8);
        NetworkError rest = assertThrows(NetworkError.class, () -> restTrustManager(junk));
        NetworkError jwks = assertThrows(NetworkError.class, () -> TlsSupport.trustManager(junk));
        for (NetworkError e : new NetworkError[] {rest, jwks}) {
            assertFalse(String.valueOf(e.getMessage()).contains("S3CR3T"), "got: " + e.getMessage());
            assertTrue(e.getMessage().contains("custom CA"), "got: " + e.getMessage());
        }
    }

    @Test
    void anUnparsableBundleNamesTheParserExceptionClassButNeverItsMessageOrContent() {
        String armoredJunk = "-----BEGIN CERTIFICATE-----\nS3CR3TS3CR3TS3CR3T\n-----END CERTIFICATE-----\n";
        NetworkError e = assertThrows(NetworkError.class,
                () -> TlsSupport.customCaStore(armoredJunk.getBytes(StandardCharsets.UTF_8)));
        assertTrue(e.getMessage().startsWith("invalid custom CA PEM: the bundle could not be parsed ("),
                "got: " + e.getMessage());
        assertTrue(e.getMessage().matches(".*\\(java\\.([a-z]+\\.)+[A-Za-z]+Exception\\)$"),
                "a parser exception class name is appended: " + e.getMessage());
        assertFalse(e.getMessage().contains("S3CR3T"), "got: " + e.getMessage());
    }
}
