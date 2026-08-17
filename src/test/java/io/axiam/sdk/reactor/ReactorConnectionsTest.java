package io.axiam.sdk.reactor;

import com.rabbitmq.client.ConnectionFactory;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.TestCerts;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;8b for the Java reactor transport.
 *
 * <p>&sect;22.2 closes with "Reactors connect across a trust boundary: {@code amqps://}, a
 * supplied CA bundle, no verification-skip switch, no plaintext fallback." Until
 * {@link ReactorConnections} existed, this SDK stated that in a javadoc sentence on
 * {@link ReactorServeOptions#builder} and enforced none of it — a caller who built a
 * {@code ConnectionFactory} from an {@code amqp://} URI got a working reactor and no warning.
 * These tests are the enforcement.
 */
class ReactorConnectionsTest {

    private static final String AMQPS = "amqps://reactor:secret@broker.internal:5671/%2f";

    // ------------------------------------------------------------------
    // Rules 1 and 5 — amqps:// only, no plaintext fallback
    // ------------------------------------------------------------------

    @Test
    void plaintextAmqpIsRefused() {
        NetworkError err = assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory("amqp://broker.internal:5672", null));
        assertTrue(
                err.getMessage().contains("amqps://"),
                "the error must name the scheme to use, got: " + err.getMessage());
    }

    /**
     * Loopback earns no exception here. &sect;8b rules 1 and 5 carry no host carve-out, and the
     * AXIAM server is TLS-only with no plaintext listener for one to reach.
     */
    @Test
    void plaintextIsRefusedOnLoopbackToo() {
        assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory("amqp://localhost:5672", null));
        assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory("amqp://127.0.0.1:5672", null));
    }

    @Test
    void everyOtherSchemeIsRefused() {
        for (String uri : new String[] {"https://broker.internal", "amqpsomething://broker:5671",
                "broker.internal:5671", "//broker.internal:5671"}) {
            assertThrows(
                    NetworkError.class,
                    () -> ReactorConnections.connectionFactory(uri, null),
                    "expected " + uri + " to be refused");
        }
    }

    /**
     * A URI that will not parse is refused rather than passed through. A security check must fail
     * closed on an input it cannot read — the opposite mistake (skip the check when parsing fails)
     * is one the Rust SDK actually shipped.
     */
    @Test
    void anUnparseableUriIsRefusedRatherThanWavedThrough() {
        assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory("amqps://broker with spaces:5671", null));
        assertThrows(
                NetworkError.class, () -> ReactorConnections.connectionFactory("", null));
    }

    @Test
    void amqpsIsAcceptedCaseInsensitively() {
        // An operator who wrote AMQPS:// meant TLS.
        ReactorConnections.requireAmqps("AMQPS://broker.internal:5671");
        ReactorConnections.requireAmqps(AMQPS);
    }

    // ------------------------------------------------------------------
    // Rule 2 — a custom CA bundle, the reason rule 2 is a MUST
    // ------------------------------------------------------------------

    @Test
    void anAmqpsUriWithoutACaBundleUsesTheSystemTrustStore() {
        ConnectionFactory factory = ReactorConnections.connectionFactory(AMQPS, null);
        assertNotNull(factory, "a publicly-issued broker certificate needs no bundle");
    }

    @Test
    void aPrivateCaBundleIsAccepted(@TempDir Path tempDir) {
        ConnectionFactory factory =
                ReactorConnections.connectionFactory(AMQPS, selfSignedCaPem(tempDir));
        assertNotNull(factory);
    }

    @Test
    void aMalformedCaBundleFailsAtConstructionNotAtHandshake() {
        NetworkError err = assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory(
                        AMQPS, "not a certificate".getBytes(StandardCharsets.UTF_8)));
        assertTrue(
                err.getMessage().toLowerCase().contains("ca"),
                "the error must point at the CA material, got: " + err.getMessage());
    }

    // ------------------------------------------------------------------
    // Rule 3 — a client identity is all-or-nothing
    // ------------------------------------------------------------------

    @Test
    void halfAClientIdentityIsRefused(@TempDir Path tempDir) {
        byte[] certPem = selfSignedCaPem(tempDir);
        NetworkError certOnly = assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory(AMQPS, null, certPem, null));
        assertTrue(
                certOnly.getMessage().contains("BOTH"),
                "got: " + certOnly.getMessage());

        assertThrows(
                NetworkError.class,
                () -> ReactorConnections.connectionFactory(
                        AMQPS, null, null, Sensitive.of("-----BEGIN PRIVATE KEY-----")),
                "…and so must the mirror case");
    }

    // ------------------------------------------------------------------
    // Rule 4 — the absence is the feature
    // ------------------------------------------------------------------

    /**
     * A tripwire on the API surface: no method here may offer a way to weaken verification. Adding
     * one would fail this test, which is the point — a verification-skip switch appears in a dev
     * compose file, works, and travels unchanged into production.
     */
    @Test
    void thereIsNoVerificationSkipEntryPoint() {
        for (java.lang.reflect.Method m : ReactorConnections.class.getDeclaredMethods()) {
            String name = m.getName().toLowerCase();
            for (String forbidden : new String[] {"insecure", "skipverif", "trustall", "nover"}) {
                assertTrue(
                        !name.contains(forbidden),
                        "ReactorConnections must not grow a " + forbidden + "-shaped method");
            }
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /**
     * A real self-signed certificate, generated per test run by the same
     * {@link TestCerts} helper the &sect;6.1 mTLS tests use. Generated rather than pasted so this
     * test carries no expiry date, and shared with those tests so one certificate story covers
     * every transport.
     *
     * <p>Nothing here is used for a live handshake — these tests build factories, they never dial
     * a broker.
     */
    private static byte[] selfSignedCaPem(Path tempDir) {
        try {
            return TestCerts.selfSignedCertPem(tempDir, "test-broker-ca");
        } catch (Exception e) {
            throw new IllegalStateException("could not build a test certificate", e);
        }
    }
}
