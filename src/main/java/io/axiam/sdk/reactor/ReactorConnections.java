package io.axiam.sdk.reactor;

import com.rabbitmq.client.ConnectionFactory;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.TlsSupport;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import org.jspecify.annotations.Nullable;

/**
 * Broker connections for a reactor, with CONTRACT.md &sect;8b enforced rather than described.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>{@link ReactorServeOptions} takes an already-open {@code Channel}, and the caller owns its
 * lifecycle. That is a reasonable division — but until now the &sect;8b requirement travelling
 * with it was a sentence of javadoc: "its connection MUST have been opened over {@code amqps://}
 * with a trusted CA". A javadoc MUST is a note to whoever reads the javadoc. Someone who builds a
 * {@code ConnectionFactory} from an {@code amqp://} URI and hands over the channel gets a working
 * reactor, no warning, and signed-but-readable token decisions on the wire.
 *
 * <p>This class is the enforcing alternative. Build the factory here and &sect;8b holds by
 * construction: the URI is checked, hostname verification is on, and there is no argument anywhere
 * that turns either off. The Kotlin SDK's {@code reactorConnectionFactory} is the same helper
 * against the same RabbitMQ client, and this is deliberately its twin — two SDKs on one client
 * library should not disagree about what a reactor is allowed to connect to.
 *
 * <p>{@code ReactorServeOptions} still accepts any channel: enforcing at construction cannot
 * retroactively constrain a channel someone else opened, and refusing to serve on a channel whose
 * provenance cannot be inspected would break every legitimate custom setup to catch a mistake this
 * class already prevents.
 *
 * <h2>The layering, once</h2>
 *
 * <p>HMAC signing (&sect;8/&sect;22.2) gives authenticity and replay protection across broker
 * hops, which TLS cannot, because TLS terminates at the broker and the broker re-sends. TLS gives
 * confidentiality, which HMAC cannot. A reactor's reply is an instruction to allow, deny or
 * rewrite a token: it needs both, and neither substitutes for the other.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * ConnectionFactory factory = ReactorConnections.connectionFactory(
 *         "amqps://reactor:secret@broker.internal:5671/%2f",
 *         Files.readAllBytes(Path.of("/etc/axiam/broker-ca.pem")),  // §8b rule 2
 *         null, null);                                             // no mTLS
 *
 * try (Connection connection = factory.newConnection();
 *      Channel channel = connection.createChannel()) {
 *     new ReactorServer(ReactorServeOptions.builder(channel, tenantId, signingKey)
 *             .reactorId(reactorId)
 *             .handler(handlers)
 *             .build()).serve();
 * }
 * }</pre>
 */
public final class ReactorConnections {

    private ReactorConnections() {
    }

    /**
     * Builds a {@link ConnectionFactory} for {@code uri}, refusing anything but {@code amqps://}.
     *
     * <p>Automatic recovery is enabled, matching the reconnect posture the &sect;22.10 runtime
     * helper is specified to maintain.
     *
     * @param uri           the broker URI. MUST be {@code amqps://} (&sect;8b rules 1 and 5);
     *                      every other scheme is refused here rather than downgraded, because a
     *                      fallback that works is a fallback that gets used
     * @param customCaPem   PEM CA bundle for a privately-issued broker certificate
     *                      (&sect;8b rule 2 — the common in-cluster case), or null to verify
     *                      against the system trust store only
     * @param clientCertPem PEM client certificate chain for mutual TLS (&sect;8b rule 3), or null
     * @param clientKeyPem  PEM PKCS#8 private key matching {@code clientCertPem}, wrapped in
     *                      {@link Sensitive} because it is a credential (&sect;7), or null.
     *                      All-or-nothing with {@code clientCertPem}
     * @return a factory that verifies the broker, with hostname verification on
     * @throws NetworkError when the URI is not {@code amqps://}, is unparseable, or the TLS
     *                      material is malformed or half-supplied
     */
    public static ConnectionFactory connectionFactory(
            String uri,
            byte @Nullable [] customCaPem,
            byte @Nullable [] clientCertPem,
            @Nullable Sensitive clientKeyPem) {

        requireAmqps(uri);

        X509TrustManager trustManager = TlsSupport.trustManager(customCaPem);
        KeyManager[] keyManagers =
                TlsSupport.keyManagers(
                        clientCertPem,
                        clientKeyPem == null
                                ? null
                                : clientKeyPem.expose().getBytes(StandardCharsets.UTF_8));
        SSLContext sslContext = TlsSupport.sslContext(trustManager, keyManagers);

        ConnectionFactory factory = new ConnectionFactory();
        try {
            factory.setUri(uri);
        } catch (URISyntaxException | java.security.NoSuchAlgorithmException
                | java.security.KeyManagementException e) {
            throw new NetworkError("reactor broker URI is not usable: " + e.getMessage(), e);
        }
        factory.useSslProtocol(sslContext);
        // Verify the broker's hostname against its certificate. The RabbitMQ
        // client leaves this OFF by default, which is why it is set explicitly:
        // a certificate that verifies but names a different host is exactly the
        // attack TLS is here to stop. There is deliberately no switch anywhere
        // in this SDK to turn it back off (§8b rule 4).
        factory.enableHostnameVerification();
        factory.setAutomaticRecoveryEnabled(true);
        return factory;
    }

    /**
     * Convenience overload for the common case: a private broker CA and no client certificate.
     *
     * @param uri         the broker URI, which MUST be {@code amqps://}
     * @param customCaPem PEM CA bundle, or null for the system trust store
     * @return a factory that verifies the broker
     * @throws NetworkError when the URI is not {@code amqps://} or the CA PEM is malformed
     */
    public static ConnectionFactory connectionFactory(String uri, byte @Nullable [] customCaPem) {
        return connectionFactory(uri, customCaPem, null, null);
    }

    /**
     * Rejects any URI that is not {@code amqps://} (&sect;8b rules 1 and 5).
     *
     * <p>Unlike a scheme check written against a parsed URL and skipped when parsing fails, an
     * unparseable URI is an error here. A security check must fail closed on an input it cannot
     * read.
     *
     * @param uri the broker URI to check
     * @throws NetworkError when the scheme is anything but {@code amqps}
     */
    public static void requireAmqps(String uri) {
        String scheme;
        try {
            scheme = new URI(uri.trim()).getScheme();
        } catch (URISyntaxException | NullPointerException e) {
            throw new NetworkError(
                    "reactor broker URI is not a valid URI: " + uri
                            + " (CONTRACT.md §8b requires an amqps:// URL)");
        }
        if (scheme == null || !scheme.toLowerCase(Locale.ROOT).equals("amqps")) {
            throw new NetworkError(
                    "a reactor MUST connect over amqps:// (CONTRACT.md §8b rules 1 and 5) — got '"
                            + (scheme == null ? "no scheme" : scheme)
                            + "'. A reactor's reply is an instruction to allow, deny or rewrite a "
                            + "token; HMAC signing gives it authenticity, not confidentiality. "
                            + "There is no plaintext fallback and no verification-skip switch — "
                            + "supply a private broker CA if the certificate is not publicly issued.");
        }
    }
}
