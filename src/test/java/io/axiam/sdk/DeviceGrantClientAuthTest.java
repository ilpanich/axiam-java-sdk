package io.axiam.sdk;

import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.DeviceAuthorization;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;14.1 and &sect;14.2 as amended by contract 1.62 (&sect;14.6, item (m) and
 * (t) of &sect;34.6): the device grant authenticates its client.
 *
 * <p>A client <em>configured with a credential</em> sends it at {@code device_authorize}
 * <em>and</em> at every {@code device_poll}, by the rules of its other token requests: a client
 * secret as {@code client_secret} in the form body (never {@code Authorization: Basic}, for a
 * {@code client_secret_post} <em>or</em> a {@code client_secret_basic} registration), or the
 * mTLS certificate on the connection. A public client sends none and is not refused. The poll
 * names its client on every poll. A {@code 401 invalid_client} is an {@link OAuthProtocolError},
 * one request, no retry, and never the &sect;9 refresh guard.
 *
 * <p>This SDK has no {@code private_key_jwt} assertion and generates no DPoP proof (it ships the
 * &sect;21.7 verifier only), so those two rows of &sect;14.6 do not apply to it.
 */
class DeviceGrantClientAuthTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String DEVICE_CODE = "device-code-value";
    private static final String CLIENT_ID = "my-device";
    private static final String SECRET = "s3cr3t-value";

    @TempDir
    Path tempDir;

    private static AxiamClient publicClient(String base) {
        return AxiamClient.builder(base, TENANT_ID).oidcClientId(CLIENT_ID).build();
    }

    private static AxiamClient confidentialClient(String base) {
        return AxiamClient.builder(base, TENANT_ID).oidcClientId(CLIENT_ID)
                .oidcClientSecret(SECRET).build();
    }

    private static Map<String, String> form(RecordedRequest request) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        for (String pair : request.getBody().readUtf8().split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            out.put(java.net.URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq),
                            java.nio.charset.StandardCharsets.UTF_8),
                    eq < 0 ? "" : java.net.URLDecoder.decode(pair.substring(eq + 1),
                            java.nio.charset.StandardCharsets.UTF_8));
        }
        return out;
    }

    // -- a confidential client sends its secret at BOTH endpoints, in the body ----------------

    @Test
    void aSecretIsSentInTheBodyAtDeviceAuthorizeAndEveryPollAndNoAuthorizationHeader() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = confidentialClient(base)) {
                OidcTokenSet tokens = client.deviceLogin(null, null, null, a -> { });
                assertEquals("device-access-token", tokens.accessToken().expose());
            }

            server.takeRequest(); // discovery
            RecordedRequest authorize = server.takeRequest();
            assertEquals("/oauth2/device_authorization", authorize.getRequestUrl().encodedPath());
            Map<String, String> authorizeForm = form(authorize);
            assertEquals(SECRET, authorizeForm.get("client_secret"),
                    "§14.1 rule 2: device_authorize sends the configured secret in the form body");
            assertEquals(CLIENT_ID, authorizeForm.get("client_id"));
            assertNull(authorize.getHeader("Authorization"),
                    "§12.1 rule 3 stands: no Authorization: Basic at device_authorize");

            for (int poll = 1; poll <= 2; poll++) {
                RecordedRequest request = server.takeRequest();
                assertEquals("/oauth2/token", request.getRequestUrl().encodedPath());
                Map<String, String> pollForm = form(request);
                assertEquals("urn:ietf:params:oauth:grant-type:device_code", pollForm.get("grant_type"));
                assertEquals(DEVICE_CODE, pollForm.get("device_code"));
                assertEquals(CLIENT_ID, pollForm.get("client_id"),
                        "§14.1 rule 3: the poll names its client, on every poll (poll " + poll + ")");
                assertEquals(SECRET, pollForm.get("client_secret"),
                        "§14.1 rule 2: every device_poll sends the configured secret (poll " + poll + ")");
                assertNull(request.getHeader("Authorization"),
                        "§12.1 rule 3 stands: no Authorization: Basic at the poll (poll " + poll + ")");
            }
            assertEquals(4, server.getRequestCount());
        }
    }

    @Test
    void theSecretFormIsTheSameForAClientRegisteredClientSecretBasic() throws Exception {
        // The registration is the server's: this SDK has one way to send a secret and it is the
        // form body (maintainer, 2026-10-16; §34.6 item t). A discovery document that advertises
        // ONLY client_secret_basic changes nothing about what is sent.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            String discovery = OidcTestSupport.discoveryResponse(base).getBody().readUtf8()
                    .replace("\"client_secret_post\"", "\"client_secret_basic\"");
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody(discovery));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = confidentialClient(base)) {
                client.deviceLogin(null, null, null, a -> { });
            }
            server.takeRequest();
            RecordedRequest authorize = server.takeRequest();
            RecordedRequest poll = server.takeRequest();
            for (RecordedRequest request : new RecordedRequest[] {authorize, poll}) {
                assertNull(request.getHeader("Authorization"), request.getPath());
                String body = request.getBody().readUtf8();
                assertTrue(body.contains("client_secret=" + SECRET), body);
            }
        }
    }

    @Test
    void theSecretNeverAppearsInTheDeviceAuthorizationOrTheErrorRendering() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(401, "invalid_client"));
            server.start();

            try (AxiamClient client = confidentialClient(base)) {
                DeviceAuthorization authorization = client.deviceAuthorize();
                assertFalse(authorization.toString().contains(SECRET));
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.devicePoll(authorization.deviceCode(), null, null));
                assertFalse(String.valueOf(error.getMessage()).contains(SECRET));
                assertFalse(client.toString().contains(SECRET), "§14.5: the credential is Sensitive");
            }
        }
    }

    // -- a public client sends none and is not refused -----------------------------------------

    @Test
    void aPublicClientSendsNoCredentialAtEitherEndpointAndIsNotRefused() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = publicClient(base)) {
                OidcTokenSet tokens = client.deviceLogin(null, null, null, a -> { });
                assertNotNull(tokens.accessToken());
            }

            server.takeRequest(); // discovery
            RecordedRequest authorize = server.takeRequest();
            String authorizeBody = authorize.getBody().readUtf8();
            assertTrue(authorizeBody.contains("client_id=" + CLIENT_ID), authorizeBody);
            assertFalse(authorizeBody.contains("client_secret"), "a public client sends no credential");
            assertFalse(authorizeBody.contains("client_assertion"), authorizeBody);
            assertNull(authorize.getHeader("Authorization"));
            for (int poll = 1; poll <= 2; poll++) {
                RecordedRequest request = server.takeRequest();
                String body = request.getBody().readUtf8();
                assertTrue(body.contains("client_id=" + CLIENT_ID),
                        "§14.1 rule 3: the poll names its client even when it is public: " + body);
                assertFalse(body.contains("client_secret"), body);
                assertFalse(body.contains("client_assertion"), body);
                assertNull(request.getHeader("Authorization"));
            }
        }
    }

    // -- 401 invalid_client --------------------------------------------------------------------

    @Test
    void invalidClientAtDeviceAuthorizeIsOneRequestNoRetryAndNoRefresh() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.oauthError(401, "invalid_client"));
            server.start();

            try (AxiamClient client = confidentialClient(base)) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class, client::deviceAuthorize);
                assertEquals("invalid_client", error.error());
            }
            assertEquals(2, server.getRequestCount(),
                    "discovery plus exactly one device_authorization request: no retry, no refresh");
            server.takeRequest();
            assertEquals("/oauth2/device_authorization", server.takeRequest().getRequestUrl().encodedPath());
        }
    }

    @Test
    void invalidClientAtThePollIsTerminalOneRequestNoRetryAndNoRefresh() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(401, "invalid_client"));
            // Were it retried or treated as non-terminal, this would be served and succeed.
            server.enqueue(OidcTestSupport.tokenResponse("must-not-be-reached", null, null));
            server.start();

            try (AxiamClient client = confidentialClient(base)) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.deviceLogin(null, null, null, a -> { }));
                assertEquals("invalid_client", error.error(),
                        "§14.2 rule 5: a OAuthProtocolError, not an AuthError, and terminal");
            }
            assertEquals(3, server.getRequestCount(),
                    "discovery, device_authorization and exactly one poll: never retried, never refreshed");
        }
    }

    @Test
    void aSingleDevicePollThatMeetsInvalidClientRaisesItWithoutTouchingTheSession() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.oauthError(401, "invalid_client"));
            server.start();
            try (AxiamClient client = publicClient(base)) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.devicePoll(Sensitive.of(DEVICE_CODE), null, null));
                assertEquals("invalid_client", error.error());
            }
            assertEquals(2, server.getRequestCount());
        }
    }

    // -- an mTLS client authenticates with its certificate -------------------------------------

    @Test
    void anMtlsClientPresentsItsCertificateAtBothEndpointsAndSendsNoSecret() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "device-grant-server");
        Identity device = TestCerts.selfSignedIdentity(tempDir, "device-grant-client");
        SSLContext serverContext = serverSslContext(server, device.certPem());

        try (MockWebServer mock = new MockWebServer()) {
            mock.useHttps(serverContext.getSocketFactory(), false);
            mock.requireClientAuth();
            String base = "https://127.0.0.1:" + mock.getPort();
            mock.enqueue(OidcTestSupport.discoveryResponse(base));
            mock.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            mock.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            mock.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId(CLIENT_ID)
                    .customCa(server.certPem())
                    .clientCertificate(device.certPem(), device.keyPem())
                    .build()) {
                // requireClientAuth(): the handshake of EVERY request succeeds only if the
                // certificate is presented, so completing both calls proves it at both endpoints.
                OidcTokenSet tokens = client.deviceLogin(null, null, null, a -> { });
                assertEquals("device-access-token", tokens.accessToken().expose());
            }

            mock.takeRequest(); // discovery
            for (String path : new String[] {"/oauth2/device_authorization", "/oauth2/token"}) {
                RecordedRequest request = mock.takeRequest();
                assertEquals(path, request.getRequestUrl().encodedPath());
                String body = request.getBody().readUtf8();
                assertFalse(body.contains("client_secret"), "an mTLS client holds no secret: " + body);
                assertTrue(body.contains("client_id=" + CLIENT_ID),
                        "tls_client_auth sends client_id only: " + body);
                assertNull(request.getHeader("Authorization"));
                assertFalse(request.getHandshake().peerCertificates().isEmpty(),
                        "the client certificate was presented on " + path);
            }
        }
    }

    // -- helpers (as AxiamClientMtlsTest) ------------------------------------------------------

    private static SSLContext serverSslContext(Identity serverId, byte[] clientCertPem) throws Exception {
        char[] pw = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", parsePkcs8(serverId.keyPem()), pw,
                new Certificate[] {parseCert(serverId.certPem())});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, pw);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("client-anchor", parseCert(clientCertPem));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return ctx;
    }

    private static X509Certificate parseCert(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static PrivateKey parsePkcs8(byte[] pem) throws Exception {
        String body = new String(pem, java.nio.charset.StandardCharsets.US_ASCII)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
