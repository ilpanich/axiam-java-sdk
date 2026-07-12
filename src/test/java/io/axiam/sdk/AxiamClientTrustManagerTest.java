package io.axiam.sdk;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.TrustManager;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * &sect;6/D-27: {@code AxiamClient}'s private {@code buildTrustManager}/{@code
 * CompositeX509TrustManager} — server certs are accepted if EITHER the system trust store OR
 * the configured custom CA validates the chain, and NEVER via a silent bypass. These are
 * construction-time private static members with no public seam other than {@code
 * Builder#customCa(byte[])}, so this test reaches them via reflection (same pattern {@code
 * AxiamClientBuilderTest} already uses for {@code Builder}'s constructor visibility) rather than
 * standing up a real HTTPS server for every branch.
 */
class AxiamClientTrustManagerTest {

    @TempDir
    Path tempDir;

    @Test
    void nullCustomCaReturnsThePlainSystemTrustManager() throws Exception {
        X509TrustManager tm = invokeBuildTrustManager(null);
        assertNotEquals("CompositeX509TrustManager", tm.getClass().getSimpleName(),
                "no custom CA configured — must be the bare system trust manager, not a composite");
    }

    @Test
    void emptyCustomCaReturnsThePlainSystemTrustManager() throws Exception {
        X509TrustManager tm = invokeBuildTrustManager(new byte[0]);
        assertNotEquals("CompositeX509TrustManager", tm.getClass().getSimpleName());
    }

    @Test
    void validCustomCaProducesACompositeTrustManagerThatTrustsTheCustomCert() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-test-ca-1");
        X509TrustManager tm = invokeBuildTrustManager(pem);
        assertEquals("CompositeX509TrustManager", tm.getClass().getSimpleName());

        X509Certificate cert = parseCert(pem);
        // The system default trust store never contains this throwaway self-signed cert, so the
        // primary (system) trust manager rejects it — the composite must fall through to the
        // secondary (custom CA) trust manager, which trusts it as its own configured anchor.
        assertDoesNotThrow(() -> tm.checkServerTrusted(new X509Certificate[]{cert}, "RSA"));
    }

    @Test
    void compositeTrustManagerRejectsACertificateTrustedByNeitherStore() throws Exception {
        byte[] customCaPem = TestCerts.selfSignedCertPem(tempDir, "axiam-test-ca-2");
        byte[] unrelatedPem = TestCerts.selfSignedCertPem(tempDir, "axiam-unrelated-cert");
        X509TrustManager tm = invokeBuildTrustManager(customCaPem);
        X509Certificate unrelated = parseCert(unrelatedPem);

        assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(new X509Certificate[]{unrelated}, "RSA"),
                "neither the system store nor an unrelated custom CA should trust this cert — "
                        + "the composite must never silently bypass on a first-manager failure");
    }

    @Test
    void checkClientTrustedDelegatesOnlyToThePrimarySystemTrustManager() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-test-ca-3");
        X509TrustManager tm = invokeBuildTrustManager(pem);
        X509Certificate cert = parseCert(pem);

        // checkClientTrusted only ever delegates to `primary` (the system store) — this
        // self-signed test cert is never in it, so this must fail even though
        // checkServerTrusted for the SAME cert succeeds via the secondary/custom-CA fallback.
        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(new X509Certificate[]{cert}, "RSA"));
    }

    @Test
    void getAcceptedIssuersCombinesPrimaryAndSecondaryIssuers() throws Exception {
        byte[] pem = TestCerts.selfSignedCertPem(tempDir, "axiam-test-ca-4");
        X509TrustManager tm = invokeBuildTrustManager(pem);
        X509Certificate customCert = parseCert(pem);

        X509Certificate[] issuers = tm.getAcceptedIssuers();
        assertTrue(issuers.length > 1, "must combine the system store's issuers with the custom CA's");
        assertTrue(Arrays.asList(issuers).contains(customCert),
                "the custom CA cert itself must be among the combined accepted issuers");
    }

    @Test
    void invalidCustomCaPemThrowsNetworkErrorAtConstructionTime() throws Exception {
        InvocationTargetException wrapped = assertThrows(InvocationTargetException.class,
                () -> buildTrustManagerMethod().invoke(null, (Object) "not a certificate".getBytes()));
        assertInstanceOf(NetworkError.class, wrapped.getCause(),
                "&sect;6: a non-PEM/invalid custom CA MUST surface as NetworkError at construction time");
    }

    @Test
    void firstX509ThrowsIllegalStateWhenNoX509TrustManagerIsPresent() throws Exception {
        Method firstX509 = AxiamClient.class.getDeclaredMethod("firstX509", TrustManager[].class);
        firstX509.setAccessible(true);

        InvocationTargetException wrapped = assertThrows(InvocationTargetException.class,
                () -> firstX509.invoke(null, (Object) new TrustManager[0]));
        assertInstanceOf(IllegalStateException.class, wrapped.getCause());
    }

    private static X509Certificate parseCert(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static Method buildTrustManagerMethod() throws NoSuchMethodException {
        Method m = AxiamClient.class.getDeclaredMethod("buildTrustManager", byte[].class);
        m.setAccessible(true);
        return m;
    }

    private static X509TrustManager invokeBuildTrustManager(byte[] pem) throws Exception {
        return (X509TrustManager) buildTrustManagerMethod().invoke(null, (Object) pem);
    }
}
