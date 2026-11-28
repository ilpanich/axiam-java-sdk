package io.axiam.sdk.grpc;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;

import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import java.net.Socket;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * D-11/&sect;6: {@code AuthClientInterceptor}'s strict-TLS {@code channelBuilder} construction
 * seam plus its private {@code buildTrustManager}/{@code CompositeX509TrustManager} — duplicated
 * (not shared) from {@code AxiamClient}'s own composite trust manager so the {@code grpc}
 * package stays independently buildable (see the class Javadoc). Mirrors {@code
 * AxiamClientTrustManagerTest}'s reflection-based approach for the private members, plus direct
 * calls to the public {@link AuthClientInterceptor#channelBuilder} for the construction-path
 * lines that method alone exercises.
 */
class AuthClientInterceptorTrustManagerTest {

    @TempDir
    Path tempDir;

    @Test
    void channelBuilderWithNoCustomCaBuildsANettyChannelBuilder() {
        NettyChannelBuilder builder = AuthClientInterceptor.channelBuilder("dns:///localhost:1", null);
        assertNotNull(builder);
    }

    @Test
    void channelBuilderWithAValidCustomCaBuildsANettyChannelBuilder() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-1");
        NettyChannelBuilder builder = AuthClientInterceptor.channelBuilder("dns:///localhost:1", pem);
        assertNotNull(builder);
    }

    @Test
    void channelBuilderWithAnInvalidCustomCaThrowsNetworkError() {
        assertThrows(NetworkError.class,
                () -> AuthClientInterceptor.channelBuilder("dns:///localhost:1", "not a certificate".getBytes()));
    }

    @Test
    void nullCustomCaReturnsThePlainSystemTrustManager() throws Exception {
        X509TrustManager tm = invokeBuildTrustManager(null);
        assertNotEquals("CompositeX509TrustManager", tm.getClass().getSimpleName());
    }

    @Test
    void emptyCustomCaReturnsThePlainSystemTrustManager() throws Exception {
        X509TrustManager tm = invokeBuildTrustManager(new byte[0]);
        assertNotEquals("CompositeX509TrustManager", tm.getClass().getSimpleName());
    }

    @Test
    void validCustomCaProducesACompositeTrustManagerThatTrustsTheCustomCert() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-2");
        X509TrustManager tm = invokeBuildTrustManager(pem);
        assertEquals("CompositeX509TrustManager", tm.getClass().getSimpleName());

        X509Certificate cert = parseCert(pem);
        assertDoesNotThrow(() -> tm.checkServerTrusted(new X509Certificate[]{cert}, "RSA"));
    }

    @Test
    void compositeTrustManagerIsAnExtendedTrustManagerForNettyOpenSsl() throws Exception {
        // gRPC >= 1.85 enables HTTPS endpoint identification; Netty's OpenSSL provider then
        // rejects a plain X509TrustManager on JDK 25+ ("unable to setup trustmanager").
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-6");
        assertInstanceOf(X509ExtendedTrustManager.class, invokeBuildTrustManager(pem));
    }

    @Test
    void socketOverloadsDelegateToTheUnderlyingTrustManagers() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-7");
        X509ExtendedTrustManager tm = (X509ExtendedTrustManager) invokeBuildTrustManager(pem);
        X509Certificate[] chain = {parseCert(pem)};

        assertDoesNotThrow(() -> tm.checkServerTrusted(chain, "RSA", (Socket) null));
        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(chain, "RSA", (Socket) null));
    }

    @Test
    void engineOverloadsDelegateToTheUnderlyingTrustManagers() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-8");
        X509ExtendedTrustManager tm = (X509ExtendedTrustManager) invokeBuildTrustManager(pem);
        X509Certificate[] chain = {parseCert(pem)};
        // An engine with no handshake session is rejected by both SunJSSE delegates — the
        // composite must surface that, never fall back to an engine-less (weaker) check.
        SSLEngine engine = SSLContext.getDefault().createSSLEngine("localhost", 443);
        engine.setUseClientMode(true);

        assertThrows(CertificateException.class, () -> tm.checkServerTrusted(chain, "RSA", engine));
        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(chain, "RSA", engine));
    }

    @Test
    void compositeTrustManagerRejectsACertificateTrustedByNeitherStore() throws Exception {
        byte[] customCaPem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-3");
        byte[] unrelatedPem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-unrelated-cert");
        X509TrustManager tm = invokeBuildTrustManager(customCaPem);
        X509Certificate unrelated = parseCert(unrelatedPem);

        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[]{unrelated}, "RSA"));
    }

    @Test
    void everyCertificateOfABundleIsTrustedAndAnUnrelatedOneStillRefused() throws Exception {
        byte[] ca1 = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-bundle-1");
        byte[] ca2 = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-bundle-2");
        byte[] other = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-bundle-other");
        byte[] bundle = new byte[ca1.length + ca2.length];
        System.arraycopy(ca1, 0, bundle, 0, ca1.length);
        System.arraycopy(ca2, 0, bundle, ca1.length, ca2.length);
        X509TrustManager tm = invokeBuildTrustManager(bundle);

        assertDoesNotThrow(() -> tm.checkServerTrusted(new X509Certificate[]{parseCert(ca1)}, "RSA"));
        assertDoesNotThrow(() -> tm.checkServerTrusted(new X509Certificate[]{parseCert(ca2)}, "RSA"),
                "the SECOND certificate of the bundle must be trusted, as on REST and JWKS");
        X509Certificate stranger = parseCert(other);
        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[]{stranger}, "RSA"));
    }

    @Test
    void endpointIdentificationStillAppliesToABundleCertificate() throws Exception {
        byte[] ca1 = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-bundle-eid-1");
        TestCerts.Identity server = TestCerts.selfSignedIdentity(tempDir, "axiam-grpc-bundle-eid-2"); // SAN localhost
        byte[] bundle = new byte[ca1.length + server.certPem().length];
        System.arraycopy(ca1, 0, bundle, 0, ca1.length);
        System.arraycopy(server.certPem(), 0, bundle, ca1.length, server.certPem().length);
        X509TrustManager tm = invokeBuildTrustManager(bundle);

        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(io.axiam.sdk.internal.TlsSupport.keyManagers(server.certPem(), server.keyPem()), null, null);
        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, new javax.net.ssl.TrustManager[]{tm}, null);

        try (javax.net.ssl.SSLServerSocket listener = (javax.net.ssl.SSLServerSocket) serverCtx
                .getServerSocketFactory().createServerSocket(0, 5, java.net.InetAddress.getByName("0.0.0.0"))) {
            Thread acceptor = new Thread(() -> {
                for (int i = 0; i < 2; i++) {
                    try (javax.net.ssl.SSLSocket sock = (javax.net.ssl.SSLSocket) listener.accept()) {
                        sock.startHandshake();
                    } catch (java.io.IOException ignored) {
                        // the client may abort the handshake
                    }
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();

            assertDoesNotThrow(() -> handshake(clientCtx, "127.0.0.1", listener.getLocalPort()));
            assertThrows(javax.net.ssl.SSLHandshakeException.class,
                    () -> handshake(clientCtx, "127.0.0.2", listener.getLocalPort()),
                    "a trusted CA does not excuse a hostname the certificate does not name");
        }
    }

    private static void handshake(SSLContext ctx, String host, int port) throws java.io.IOException {
        try (javax.net.ssl.SSLSocket sock = (javax.net.ssl.SSLSocket) ctx.getSocketFactory().createSocket(host, port)) {
            javax.net.ssl.SSLParameters params = sock.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            sock.setSSLParameters(params);
            sock.startHandshake();
        }
    }

    @Test
    void checkClientTrustedDelegatesOnlyToThePrimarySystemTrustManager() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-4");
        X509TrustManager tm = invokeBuildTrustManager(pem);
        X509Certificate cert = parseCert(pem);

        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(new X509Certificate[]{cert}, "RSA"));
    }

    @Test
    void getAcceptedIssuersCombinesPrimaryAndSecondaryIssuers() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-5");
        X509TrustManager tm = invokeBuildTrustManager(pem);
        X509Certificate customCert = parseCert(pem);

        X509Certificate[] issuers = tm.getAcceptedIssuers();
        assertTrue(issuers.length > 1);
        assertTrue(Arrays.asList(issuers).contains(customCert));
    }

    @Test
    void invalidCustomCaPemThrowsNetworkErrorAtConstructionTime() throws Exception {
        InvocationTargetException wrapped = assertThrows(InvocationTargetException.class,
                () -> buildTrustManagerMethod().invoke(null, (Object) "not a certificate".getBytes()));
        assertInstanceOf(NetworkError.class, wrapped.getCause());
    }

    @Test
    void firstX509ThrowsIllegalStateWhenNoX509TrustManagerIsPresent() throws Exception {
        Method firstX509 = AuthClientInterceptor.class.getDeclaredMethod("firstX509", javax.net.ssl.TrustManager[].class);
        firstX509.setAccessible(true);

        InvocationTargetException wrapped = assertThrows(InvocationTargetException.class,
                () -> firstX509.invoke(null, (Object) new javax.net.ssl.TrustManager[0]));
        assertInstanceOf(IllegalStateException.class, wrapped.getCause());
    }

    private static X509Certificate parseCert(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static Method buildTrustManagerMethod() throws NoSuchMethodException {
        Method m = AuthClientInterceptor.class.getDeclaredMethod("buildTrustManager", byte[].class);
        m.setAccessible(true);
        return m;
    }

    private static X509TrustManager invokeBuildTrustManager(byte[] pem) throws Exception {
        return (X509TrustManager) buildTrustManagerMethod().invoke(null, (Object) pem);
    }
}
