package io.axiam.sdk.testutil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Test-only helper: shells out to the JDK's own {@code keytool} (always present under
 * {@code java.home}, no extra test dependency needed) to mint throwaway self-signed X.509
 * certificates (PEM-encoded) for TLS trust-manager tests. Never referenced by production code.
 */
public final class TestCerts {

    private TestCerts() {
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
