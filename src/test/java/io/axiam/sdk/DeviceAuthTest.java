package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code authenticateDevice()} — CONTRACT.md &sect;6.1 rules 6-10 (contract 1.51).
 *
 * <p>The cookie-withholding assertions read the {@code Cookie} request header
 * {@code MockWebServer} actually recorded on the wire — the real transport
 * boundary, past {@code AuthInterceptor}'s cookie-jar swap — rather than a mock
 * that could pass even with the withholding removed (the lesson the axiam-typescript-sdk
 * port's {@code deviceAuth.test.ts} needed a second pass to learn: its HTTP mock
 * intercepted above the layer where the cookie jar attaches cookies).
 */
class DeviceAuthTest {

    private static final String TENANT_ID = "acme";

    @TempDir
    Path tempDir;

    private AxiamClient.Builder builderWithCert(String base) throws Exception {
        Identity id = TestCerts.selfSignedIdentity(tempDir, "device-under-test");
        return AxiamClient.builder(base, TENANT_ID).clientCertificate(id.certPem(), id.keyPem());
    }

    /** Rule 7: reachable only on a client configured with a certificate — ZERO wire calls. */
    @Test
    void unreachableWithoutACertificate() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient noCert = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                AuthError e = assertThrows(AuthError.class, noCert::authenticateDevice);
                assertTrue(e.getMessage().contains("requires a client certificate"), e.getMessage());
            }
            assertEquals(0, server.getRequestCount(),
                    "authenticateDevice() without a certificate must make ZERO wire calls");
        }
    }

    /** Rule 6: one call, no body, three fields back — and the token is adopted. */
    @Test
    void oneCallNoBodyAdoptsTheToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"device-token-abc\",\"token_type\":\"Bearer\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                DeviceToken token = client.authenticateDevice();

                assertEquals("device-token-abc", token.accessToken().expose());
                assertEquals("Bearer", token.tokenType());
                assertEquals(900L, token.expiresIn());

                RecordedRequest request = server.takeRequest();
                assertEquals("POST", request.getMethod());
                assertEquals("/api/v1/auth/device", request.getPath());
                assertEquals(0L, request.getBodySize(), "rule 6: no request body");
            }
        }
    }

    /**
     * The mutation this test is meant to catch: dropping the explicit empty {@code Cookie}
     * header would let a stale {@code axiam_access} cookie silently outrank the device token,
     * because the server reads the cookie before the {@code Authorization} header.
     */
    @Test
    void deviceTokenWithholdsAStaleCookie() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // 1) An ordinary login that leaves a stale axiam_access cookie in the jar.
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .addHeader("Set-Cookie",
                            "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/; HttpOnly")
                    .setBody("{\"mfa_required\":false,\"user\":{\"id\":\"11111111-1111-4111-8111-"
                            + "111111111111\",\"email\":\"a@b.test\",\"username\":\"a\"}}"));
            // 2) The device login itself.
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"device-token-xyz\",\"token_type\":\"Bearer\","
                            + "\"expires_in\":900}"));
            // 3) A subsequent authenticated call, whose wire Cookie header is the assertion.
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                client.login("a@b.test", "password");
                server.takeRequest(); // consume the login request

                client.authenticateDevice();
                RecordedRequest deviceRequest = server.takeRequest();
                assertNull(deviceRequest.getHeader("Cookie"),
                        "the device login call itself must carry no stale cookie");

                client.checkAccess("read", "documents/1");
                RecordedRequest laterRequest = server.takeRequest();
                assertNull(laterRequest.getHeader("Cookie"),
                        "a LATER call on the adopted device token must still withhold the stale "
                                + "axiam_access cookie — the server reads it BEFORE Authorization");
                assertEquals("Bearer device-token-xyz", laterRequest.getHeader("Authorization"));
            }
        }
    }

    /**
     * CONTRACT 1.52 N4.1 (C-12): "The device POST carries nothing of a prior
     * session: no Cookie, no Authorization." A client that already holds a
     * bearer/cookie session from a prior {@code login()} must not let that
     * session's access token ride along as {@code Authorization: Bearer} on
     * the device login call itself — the device call authenticates by mTLS
     * alone.
     */
    @Test
    void deviceLoginItselfWithholdsAPriorBearerToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .addHeader("Set-Cookie",
                            "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/; HttpOnly")
                    .setBody("{\"mfa_required\":false,\"user\":{\"id\":\"11111111-1111-4111-8111-"
                            + "111111111111\",\"email\":\"a@b.test\",\"username\":\"a\"}}"));
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"device-token-after-login\",\"token_type\":\"Bearer\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                client.login("a@b.test", "password");
                server.takeRequest(); // consume the login request

                client.authenticateDevice();
                RecordedRequest deviceRequest = server.takeRequest();
                assertNull(deviceRequest.getHeader("Authorization"),
                        "the device login call must not carry a prior session's bearer token");
                assertNull(deviceRequest.getHeader("Cookie"),
                        "the device login call itself must carry no stale cookie");
            }
        }
    }

    /**
     * CONTRACT 1.52 N4.2 (C-12): "A refused or malformed device login changes
     * no client state." A &sect;17 decision memo entry recorded before a
     * refused {@code authenticateDevice()} call must still answer from cache
     * afterward — it must not have been silently dropped as a side effect of
     * the refused call.
     */
    @Test
    void aRefusedDeviceLoginChangesNoClientState() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"authentication_failed\",\"message\":\"unknown certificate\"}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString())
                    .decisionMemoTtl(Duration.ofSeconds(30))
                    .build()) {
                client.checkAccess("read", "documents/1");
                assertEquals(1, server.getRequestCount(), "the memo-populating call");

                assertThrows(AuthError.class, client::authenticateDevice);
                assertEquals(2, server.getRequestCount(), "the refused device login");

                client.checkAccess("read", "documents/1");
                assertEquals(2, server.getRequestCount(),
                        "the memo entry recorded before the refused device login must still answer "
                                + "from cache — a refused device login changes NO client state (N4.2)");
            }
        }
    }

    /**
     * CONTRACT 1.52 N4.4 (C-12): {@code refresh()} "never refreshed" is about
     * the automatic guard, but calling {@code refresh()} explicitly must still
     * never drop an adopted &sect;6.1 device token as a side effect — the
     * credential a later request presents is the assertion, not whatever
     * {@code refresh()} itself does or throws.
     */
    @Test
    void refreshNeverDropsTheAdoptedDeviceCredential() throws Exception {
        String deviceToken = OidcTestTokens.unsignedAccessToken();
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"" + deviceToken + "\",\"token_type\":\"Bearer\","
                            + "\"expires_in\":900}"));
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .addHeader("Set-Cookie",
                            "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/; HttpOnly")
                    .setBody("{\"expires_in\":900}"));
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                DeviceToken adopted = client.authenticateDevice();
                assertEquals(deviceToken, adopted.accessToken().expose());

                try {
                    client.refresh();
                } catch (RuntimeException ignored) {
                    // Whether this explicit refresh() call itself succeeds is not this
                    // test's concern — only that it does not corrupt session state.
                }

                client.checkAccess("read", "documents/1");
                RecordedRequest last = null;
                for (int i = 0; i < server.getRequestCount(); i++) {
                    last = server.takeRequest();
                }
                assertEquals("Bearer " + deviceToken, last.getHeader("Authorization"),
                        "refresh() must never drop the adopted device credential (N4.4)");
                assertNull(last.getHeader("Cookie"),
                        "the device credential's stale-cookie withholding must still apply after refresh()");
            }
        }
    }

    /** Rule 6/8: a 401 on the login itself is AuthError, verbatim, no refresh attempt. */
    @Test
    void a401OnTheLoginItselfIsAuthErrorWithNoRefreshAttempt() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"authentication_failed\","
                            + "\"message\":\"unknown certificate\"}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                assertThrows(AuthError.class, client::authenticateDevice);
            }
            assertEquals(1, server.getRequestCount(),
                    "no refresh attempt: exactly one request, the login itself");
        }
    }

    /** Rule 6/8: a LATER 401 on the adopted device token is surfaced with no refresh attempt. */
    @Test
    void aLater401OnTheDeviceTokenIsSurfacedWithNoRefreshAttempt() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"device-token-revoked\",\"token_type\":\"Bearer\","
                            + "\"expires_in\":900}"));
            server.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"authentication_failed\",\"message\":\"token revoked\"}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                client.authenticateDevice();
                server.takeRequest();

                assertThrows(AuthError.class,
                        () -> client.checkAccess("read", "documents/1"));
            }
            // The device login + the one failed call — no third (refresh) request.
            assertEquals(2, server.getRequestCount(),
                    "no refresh attempt on a later 401: exactly two requests total");
        }
    }

    /** The {@code CompletableFuture} twin adopts the token exactly as the sync call does. */
    @Test
    void authenticateDeviceAsyncAdoptsTheToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"access_token\":\"async-token\",\"token_type\":\"Bearer\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = builderWithCert(server.url("/").toString()).build()) {
                DeviceToken token = client.authenticateDeviceAsync().get();
                assertEquals("async-token", token.accessToken().expose());
            }
            RecordedRequest request = server.takeRequest();
            assertTrue(request.getPath().endsWith("/api/v1/auth/device"));
        }
    }
}
