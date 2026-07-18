package io.axiam.sdk.testutil;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Base64;

/**
 * Test-only helper: shells out to the JDK's own {@code keytool} (always present under
 * {@code java.home}, no extra test dependency needed) to mint throwaway self-signed X.509
 * certificates (PEM-encoded) for TLS trust-manager tests. Never referenced by production code.
 *
 * <p>All key material it produces is generated freshly at test time and lives only in the
 * JUnit {@code @TempDir} — nothing is ever committed to the repository.
 */
public final class TestCerts {

    private TestCerts() {
    }

    /**
     * A throwaway client/server identity: the PEM-encoded certificate and its matching
     * PEM-encoded PKCS#8 private key, exactly the shape
     * {@code AxiamClient.Builder#clientCertificate(byte[], byte[])} accepts.
     *
     * @param certPem the PEM-encoded self-signed X.509 certificate
     * @param keyPem  the PEM-encoded PKCS#8 private key matching {@code certPem}
     */
    public record Identity(byte[] certPem, byte[] keyPem) {
    }

    /**
     * Generates a fresh RSA self-signed identity (certificate + PKCS#8 private key) with the
     * given {@code CN} and a {@code DNS:localhost,IP:127.0.0.1} SAN (so it passes strict
     * hostname verification against a loopback {@code MockWebServer}).
     *
     * @param tempDir a JUnit {@code @TempDir}-provided scratch directory
     * @param cn      the certificate's Common Name (also used to derive unique file names)
     * @return the freshly generated {@link Identity}
     * @throws IOException          if keytool invocation or file I/O fails
     * @throws InterruptedException if the keytool subprocess is interrupted
     * @throws GeneralSecurityException if the generated keystore cannot be read back
     */
    public static Identity selfSignedIdentity(Path tempDir, String cn)
            throws IOException, InterruptedException, GeneralSecurityException {
        String safeName = cn.replaceAll("[^a-zA-Z0-9]", "");
        Path keystore = tempDir.resolve(safeName + "-id.p12");
        String keytool = System.getProperty("java.home") + "/bin/keytool";

        run(keytool, "-genkeypair", "-alias", "cert", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", "changeit", "-keypass", "changeit",
                "-dname", "CN=" + cn, "-ext", "san=dns:localhost,ip:127.0.0.1");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            ks.load(in, "changeit".toCharArray());
        }
        PrivateKey key = (PrivateKey) ks.getKey("cert", "changeit".toCharArray());
        Certificate cert = ks.getCertificate("cert");
        // PrivateKey#getEncoded() returns the PKCS#8 DER encoding; wrap it as a
        // `-----BEGIN PRIVATE KEY-----` PEM block (the shape clientCertificate parses).
        byte[] certPem = pem("CERTIFICATE", cert.getEncoded());
        byte[] keyPem = pem("PRIVATE KEY", key.getEncoded());
        return new Identity(certPem, keyPem);
    }

    private static byte[] pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return ("-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n")
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    /**
     * Generates a fresh self-signed certificate with the given {@code CN} and returns its
     * PEM encoding, exactly the shape {@code AxiamClient.Builder#customCa(byte[])} and
     * {@code AuthClientInterceptor#channelBuilder} accept.
     *
     * @param tempDir a JUnit {@code @TempDir}-provided scratch directory
     * @param cn      the certificate's Common Name (also used to derive unique file names)
     * @return the PEM-encoded self-signed certificate bytes
     */
    public static byte[] selfSignedCertPem(Path tempDir, String cn) throws IOException, InterruptedException {
        String safeName = cn.replaceAll("[^a-zA-Z0-9]", "");
        Path keystore = tempDir.resolve(safeName + ".p12");
        Path certOut = tempDir.resolve(safeName + ".pem");
        String keytool = System.getProperty("java.home") + "/bin/keytool";

        run(keytool, "-genkeypair", "-alias", "cert", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", "changeit", "-keypass", "changeit",
                "-dname", "CN=" + cn);
        run(keytool, "-exportcert", "-alias", "cert", "-keystore", keystore.toString(),
                "-storepass", "changeit", "-rfc", "-file", certOut.toString());
        return Files.readAllBytes(certOut);
    }

    private static void run(String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes());
        int exit = p.waitFor();
        if (exit != 0) {
            throw new IOException("keytool command failed (exit " + exit + "): " + output);
        }
    }
}
