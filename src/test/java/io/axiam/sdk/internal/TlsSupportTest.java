package io.axiam.sdk.internal;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link TlsSupport} — the PEM-to-{@link SSLContext} plumbing behind the &sect;8b broker
 * connection.
 *
 * <p>The theme throughout: malformed or half-supplied material must fail at <em>construction</em>,
 * not at the first handshake. A TLS misconfiguration that surfaces as a connection error at 3am
 * looks exactly like a broker outage, and the operator debugging it has no reason to suspect their
 * own certificate mount.
 */
class TlsSupportTest {

    // ------------------------------------------------------------------
    // Server verification
    // ------------------------------------------------------------------

    @Test
    void noCustomCaYieldsTheSystemTrustManager() {
        X509TrustManager tm = TlsSupport.trustManager(null);
        assertNotNull(tm);
        assertTrue(
                tm.getAcceptedIssuers().length > 0,
                "the platform trust store should carry public roots");
    }

    @Test
    void anEmptyCustomCaIsTreatedAsAbsentRatherThanAsAnError() {
        assertNotNull(TlsSupport.trustManager(new byte[0]));
    }

    /**
     * The custom CA is <em>added</em> to the system roots, not substituted for them: an operator
     * who trusts their broker's private CA does not thereby stop trusting everything else. The
     * composite's accepted-issuer list is the observable form of that.
     */
    @Test
    void aCustomCaIsAddedToTheSystemRootsRatherThanReplacingThem(@TempDir Path tempDir)
            throws Exception {
        int systemIssuers = TlsSupport.trustManager(null).getAcceptedIssuers().length;
        byte[] caPem = TestCerts.selfSignedCertPem(tempDir, "tls-support-ca");

        X509TrustManager composite = TlsSupport.trustManager(caPem);
        assertEquals(
                systemIssuers + 1,
                composite.getAcceptedIssuers().length,
                "the composite must expose the system issuers PLUS the custom CA");
    }

    /**
     * Both delegates verify, so a chain neither of them accepts is still rejected. This is the
     * assertion that separates "widened the trust set" from "stopped verifying".
     */
    @Test
    void aCompositeStillRejectsAChainNeitherDelegateTrusts(@TempDir Path tempDir)
            throws Exception {
        byte[] caPem = TestCerts.selfSignedCertPem(tempDir, "tls-support-ca-reject");
        X509TrustManager composite = TlsSupport.trustManager(caPem);

        // A different self-signed certificate, chaining to neither the system
        // roots nor the CA above.
        byte[] strangerPem = TestCerts.selfSignedCertPem(tempDir, "tls-support-stranger");
        X509Certificate stranger = (X509Certificate)
                java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(strangerPem));

        assertThrows(
                CertificateException.class,
                () -> composite.checkServerTrusted(new X509Certificate[] {stranger}, "RSA"));
        assertThrows(
                CertificateException.class,
                () -> composite.checkClientTrusted(new X509Certificate[] {stranger}, "RSA"));
    }

    @Test
    void aMalformedCustomCaFailsAtConstruction() {
        NetworkError err = assertThrows(
                NetworkError.class,
                () -> TlsSupport.trustManager("not a certificate".getBytes(StandardCharsets.UTF_8)));
        assertTrue(err.getMessage().contains("CA"), "got: " + err.getMessage());
    }

    // ------------------------------------------------------------------
    // Client identity (mutual TLS)
    // ------------------------------------------------------------------

    @Test
    void noClientIdentityYieldsNoKeyManagers() {
        assertNull(TlsSupport.keyManagers(null, null));
    }

    @Test
    void aCompleteClientIdentityIsAccepted(@TempDir Path tempDir) throws Exception {
        TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "tls-support-client");
        KeyManager[] kms = TlsSupport.keyManagers(id.certPem(), id.keyPem());
        assertNotNull(kms);
        assertTrue(kms.length > 0);
    }

    /**
     * Half an identity cannot authenticate, and connecting anyway would silently downgrade mutual
     * TLS to ordinary TLS — the caller would believe they were presenting a certificate and would
     * not be. Both directions are refused.
     */
    @Test
    void halfAClientIdentityIsRefusedInBothDirections(@TempDir Path tempDir) throws Exception {
        TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "tls-support-half");

        NetworkError certOnly = assertThrows(
                NetworkError.class, () -> TlsSupport.keyManagers(id.certPem(), null));
        assertTrue(certOnly.getMessage().contains("BOTH"), "got: " + certOnly.getMessage());

        assertThrows(NetworkError.class, () -> TlsSupport.keyManagers(null, id.keyPem()));
    }

    @Test
    void aMalformedClientCertificateFailsAtConstruction(@TempDir Path tempDir) throws Exception {
        TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "tls-support-badcert");
        assertThrows(
                NetworkError.class,
                () -> TlsSupport.keyManagers(
                        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"
                                .getBytes(StandardCharsets.UTF_8),
                        id.keyPem()));
    }

    @Test
    void aMalformedPrivateKeyFailsAtConstruction(@TempDir Path tempDir) throws Exception {
        TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "tls-support-badkey");

        // Not base64 at all.
        assertThrows(
                NetworkError.class,
                () -> TlsSupport.keyManagers(
                        id.certPem(),
                        "-----BEGIN PRIVATE KEY-----\n!!!not base64!!!\n-----END PRIVATE KEY-----\n"
                                .getBytes(StandardCharsets.UTF_8)));

        // Valid base64, but not a PKCS#8 key of any algorithm we accept.
        assertThrows(
                NetworkError.class,
                () -> TlsSupport.keyManagers(
                        id.certPem(),
                        "-----BEGIN PRIVATE KEY-----\nZm9vYmFy\n-----END PRIVATE KEY-----\n"
                                .getBytes(StandardCharsets.UTF_8)));
    }

    // ------------------------------------------------------------------
    // Context assembly
    // ------------------------------------------------------------------

    @Test
    void anSslContextIsBuiltWithAndWithoutAClientIdentity(@TempDir Path tempDir) throws Exception {
        X509TrustManager tm = TlsSupport.trustManager(null);

        SSLContext serverOnly = TlsSupport.sslContext(tm, null);
        assertNotNull(serverOnly.getSocketFactory());

        TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "tls-support-ctx");
        SSLContext mutual = TlsSupport.sslContext(tm, TlsSupport.keyManagers(id.certPem(), id.keyPem()));
        assertNotNull(mutual.getSocketFactory());
    }
}
