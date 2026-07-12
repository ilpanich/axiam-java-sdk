package io.axiam.sdk.grpc;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;

import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.X509TrustManager;

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
    void compositeTrustManagerRejectsACertificateTrustedByNeitherStore() throws Exception {
        byte[] customCaPem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-test-ca-3");
        byte[] unrelatedPem = TestCerts.selfSignedCertPem(tempDir, "axiam-grpc-unrelated-cert");
        X509TrustManager tm = invokeBuildTrustManager(customCaPem);
        X509Certificate unrelated = parseCert(unrelatedPem);

        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[]{unrelated}, "RSA"));
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
