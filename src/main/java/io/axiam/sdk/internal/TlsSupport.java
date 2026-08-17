package io.axiam.sdk.internal;

import io.axiam.sdk.errors.NetworkError;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.jspecify.annotations.Nullable;

/**
 * PEM-to-{@link SSLContext} plumbing shared by transports that need TLS
 * material of their own.
 *
 * <p>Built for the AMQP broker connection ({@code ReactorConnections},
 * CONTRACT.md &sect;8b), which needs the same three inputs the REST and gRPC
 * transports already take: an optional custom CA for server verification, and
 * an optional client certificate/key pair for mutual TLS.
 *
 * <h2>On the duplication this does not yet remove</h2>
 *
 * <p>Equivalent private copies of this logic already live in
 * {@code AxiamClient} (&sect;6, REST) and {@code grpc.AuthClientInterceptor}
 * (gRPC), each with its own nested {@code CompositeX509TrustManager}. Adding a
 * third copy inside the reactor package would have been the smaller diff and
 * the worse outcome: three independent implementations of server-certificate
 * verification drift, and the drift is invisible until the day one of them
 * stops verifying something.
 *
 * <p>This class is therefore the beginning of one implementation rather than a
 * fourth. It is deliberately scoped to the new caller — folding the two
 * existing transports into it changes established &sect;6/&sect;6.1 behaviour
 * and belongs in its own change, not in a &sect;8b fix.
 *
 * <h2>There is no bypass, by construction</h2>
 *
 * <p>Nothing here accepts a "skip verification" argument, and there is no code
 * path that builds a permissive {@link X509TrustManager}. &sect;6 and &sect;8b
 * rule 4 both forbid surfacing one. The absence is the feature.
 */
public final class TlsSupport {

    private TlsSupport() {
    }

    /**
     * Builds a trust manager over the system trust store, plus {@code customCaPem} when supplied.
     *
     * <p>The custom CA is <strong>added</strong> to the system roots rather than replacing them,
     * via a composite that accepts a chain either side validates. That matches the REST and gRPC
     * transports' existing behaviour, so an operator who supplies one CA bundle gets the same
     * trust semantics on every transport this SDK speaks.
     *
     * @param customCaPem PEM CA certificate to trust in addition to the system roots, or null
     * @return a trust manager that verifies; never a permissive one
     * @throws NetworkError when the PEM is absent, malformed, or contains no certificate
     */
    public static X509TrustManager trustManager(byte @Nullable [] customCaPem) {
        try {
            TrustManagerFactory systemTmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            systemTmf.init((KeyStore) null);
            X509TrustManager systemTm = firstX509(systemTmf.getTrustManagers());

            if (customCaPem == null || customCaPem.length == 0) {
                return systemTm;
            }

            KeyStore customStore = KeyStore.getInstance(KeyStore.getDefaultType());
            customStore.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(customCaPem));
            if (certs.isEmpty()) {
                throw new NetworkError("custom CA PEM contained no certificates");
            }
            int i = 0;
            for (Certificate cert : certs) {
                customStore.setCertificateEntry("custom-ca-" + i++, (X509Certificate) cert);
            }

            TrustManagerFactory customTmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            customTmf.init(customStore);
            return new CompositeX509TrustManager(systemTm, firstX509(customTmf.getTrustManagers()));
        } catch (GeneralSecurityException | IOException e) {
            // A non-PEM / invalid custom CA MUST fail clearly at construction,
            // not at the first handshake.
            throw new NetworkError("invalid custom CA PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Builds the client-identity key managers for mutual TLS, or null when no identity is
     * configured.
     *
     * <p>The certificate and key are all-or-nothing: half an identity cannot authenticate, and
     * proceeding without the mutual half would silently downgrade mTLS to ordinary TLS.
     *
     * @param certPem PEM client certificate chain, or null
     * @param keyPem  PEM PKCS#8 private key, or null
     * @return the key managers, or null when neither is configured
     * @throws NetworkError when exactly one of the two is supplied, or either is malformed
     */
    public static KeyManager @Nullable [] keyManagers(
            byte @Nullable [] certPem, byte @Nullable [] keyPem) {
        if (certPem == null && keyPem == null) {
            return null;
        }
        if (certPem == null || keyPem == null) {
            throw new NetworkError(
                    "mutual TLS requires BOTH a client certificate and its private key — half a "
                            + "client identity cannot authenticate, and connecting anyway would "
                            + "silently drop the mutual half of mutual TLS. Supply both or neither.");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(certPem));
            if (certs.isEmpty()) {
                throw new NetworkError("client certificate PEM contained no certificates");
            }
            Certificate[] chain = certs.toArray(new Certificate[0]);
            PrivateKey privateKey = parsePkcs8PrivateKey(keyPem);

            // Random, throwaway password for the in-memory store — never
            // persisted, never exposed, and zeroed below.
            byte[] pwBytes = new byte[32];
            new SecureRandom().nextBytes(pwBytes);
            char[] password = Base64.getEncoder().encodeToString(pwBytes).toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("client", privateKey, password, chain);

            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);
            Arrays.fill(password, '\0');
            return kmf.getKeyManagers();
        } catch (GeneralSecurityException | IOException e) {
            throw new NetworkError(
                    "invalid client certificate/key PEM: " + e.getMessage(), e);
        }
    }

    /**
     * Builds a verifying {@link SSLContext} from a trust manager and optional key managers.
     *
     * <p>A client certificate never relaxes server verification: the trust manager passed in is
     * used unchanged whether or not an identity is present.
     *
     * @param trustManager server verification, from {@link #trustManager(byte[])}
     * @param keyManagers  client identity, or null for none
     * @return an initialized TLS context
     * @throws NetworkError when the context cannot be initialized
     */
    public static SSLContext sslContext(
            X509TrustManager trustManager, KeyManager @Nullable [] keyManagers) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(keyManagers, new TrustManager[] {trustManager}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new NetworkError("failed to initialize TLS context: " + e.getMessage(), e);
        }
    }

    private static X509TrustManager firstX509(TrustManager[] tms) {
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException(
                "no X509TrustManager found in the default TrustManagerFactory");
    }

    /**
     * Parses a PEM PKCS#8 private key, detecting the algorithm by trying RSA, then EC, then
     * Ed25519 — the three AXIAM issues certificates for.
     */
    private static PrivateKey parsePkcs8PrivateKey(byte[] keyPem) throws GeneralSecurityException {
        String pem = new String(keyPem, StandardCharsets.UTF_8);
        // The algorithm prefix is OPTIONAL — a PKCS#8 key's header is a bare
        // `-----BEGIN PRIVATE KEY-----`, which is the common case and the one a
        // `(?:RSA |EC )` group written without `?` silently fails to strip,
        // leaving the header in the body and reporting it as "not valid base64".
        String base64 = pem.replaceAll("-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "")
                .replaceAll("-----END (?:RSA |EC )?PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        if (base64.isEmpty()) {
            throw new java.security.spec.InvalidKeySpecException(
                    "no PEM private key body found (expected -----BEGIN PRIVATE KEY----- PKCS#8)");
        }
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new java.security.spec.InvalidKeySpecException(
                    "private key PEM is not valid base64", e);
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        GeneralSecurityException last = null;
        for (String algorithm : new String[] {"RSA", "EC", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw new java.security.spec.InvalidKeySpecException(
                "private key is not a PKCS#8 RSA, EC or Ed25519 key", last);
    }

    /**
     * Accepts a server chain that <em>either</em> the system roots or the supplied custom CA
     * validates.
     *
     * <p>Both delegates verify. This composite widens which issuers are acceptable; it never
     * makes acceptance unconditional, and a chain both delegates reject is rejected.
     */
    private static final class CompositeX509TrustManager implements X509TrustManager {
        private final X509TrustManager primary;
        private final X509TrustManager secondary;

        CompositeX509TrustManager(X509TrustManager primary, X509TrustManager secondary) {
            this.primary = primary;
            this.secondary = secondary;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            try {
                primary.checkClientTrusted(chain, authType);
            } catch (java.security.cert.CertificateException e) {
                secondary.checkClientTrusted(chain, authType);
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            try {
                primary.checkServerTrusted(chain, authType);
            } catch (java.security.cert.CertificateException e) {
                secondary.checkServerTrusted(chain, authType);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] a = primary.getAcceptedIssuers();
            X509Certificate[] b = secondary.getAcceptedIssuers();
            X509Certificate[] all = Arrays.copyOf(a, a.length + b.length);
            System.arraycopy(b, 0, all, a.length, b.length);
            return all;
        }
    }
}
