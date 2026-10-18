package io.axiam.sdk;

import io.axiam.sdk.testutil.OidcTestSupport;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * CONTRACT.md &sect;12.1 rule 3 (last paragraph), &sect;6.1 rule 11 and &sect;14.6 (contract 1.62,
 * C162-05): a session's or an adopted credential is never attached to a request to
 * {@code /oauth2/*}. Adopt a credential (a device login) and, in a second run, sign in; then run
 * {@code deviceAuthorize}, {@code devicePoll} and a token request ({@code oidcRefresh},
 * {@code loginClientCredentials}) and assert on the wire that none carries an
 * {@code Authorization} header. The control is the same client's next management request, which
 * carries the credential, so the assertions cannot pass for want of one. The one thing that is
 * not excluded is a credential the caller hands to a single call (the RFC 7592
 * {@code registration_access_token}, &sect;28.12).
 */
class OauthNoSessionCredentialTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String CLIENT_ID = "my-device";
    private static final String SECRET = "s3cr3t-value";

    @TempDir
    Path tempDir;

    private final String sessionAccess = OidcTestTokens.unsignedAccessToken();
    private final List<RecordedRequest> seen = new ArrayList<>();

    /** Routes by path, so the order in which the client reaches the endpoints does not matter. */
    private MockWebServer server() throws Exception {
        MockWebServer server = new MockWebServer();
        String base = server.url("/").toString();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                synchronized (seen) {
                    seen.add(request);
                }
                String path = request.getRequestUrl().encodedPath();
                return switch (path) {
                    case "/.well-known/openid-configuration" -> OidcTestSupport.discoveryResponse(base);
                    case "/api/v1/auth/login" -> new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .addHeader("Set-Cookie", "axiam_access=" + sessionAccess
                                    + "; Path=/; HttpOnly")
                            .setBody("{\"mfa_required\":false,\"user\":{\"id\":\"11111111-1111-4111-8111-"
                                    + "111111111111\",\"email\":\"a@b.test\",\"username\":\"a\"}}");
                    case "/api/v1/auth/device" -> new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody("{\"access_token\":\"device-token-xyz\",\"token_type\":\"Bearer\","
                                    + "\"expires_in\":900}");
                    case "/oauth2/device_authorization" -> OidcTestSupport.deviceAuthorizationResponse(base, 60, 1);
                    case "/oauth2/token" -> OidcTestSupport.tokenResponse("minted-access", "minted-refresh", null);
                    case "/oauth2/register/c1" -> new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody("{\"client_id\":\"c1\"}");
                    default -> new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}");
                };
            }
        });
        server.start();
        return server;
    }

    private AxiamClient.Builder builder(String base) throws Exception {
        Identity id = TestCerts.selfSignedIdentity(tempDir, "device-under-test");
        return AxiamClient.builder(base, TENANT_ID).clientCertificate(id.certPem(), id.keyPem())
                .oidcClientId(CLIENT_ID).oidcClientSecret(SECRET);
    }

    private List<RecordedRequest> to(String path) {
        synchronized (seen) {
            return seen.stream().filter(r -> r.getRequestUrl().encodedPath().equals(path)).toList();
        }
    }

    private void runTheFourOauth2Calls(AxiamClient client) {
        var authorization = client.deviceAuthorize();
        client.devicePoll(authorization.deviceCode(), null, null);
        client.oidcRefresh("some-refresh-token");
        client.loginClientCredentials();
    }

    private void assertNoAuthorizationOnOauth2() {
        List<RecordedRequest> deviceAuthorize = to("/oauth2/device_authorization");
        List<RecordedRequest> tokens = to("/oauth2/token");
        assertEquals(1, deviceAuthorize.size());
        assertEquals(3, tokens.size(), "device_poll, the refresh and the client-credentials grant");
        for (RecordedRequest r : deviceAuthorize) {
            assertNull(r.getHeader("Authorization"), "device_authorize carries no Authorization header");
        }
        for (RecordedRequest r : tokens) {
            assertNull(r.getHeader("Authorization"), "a token request carries no Authorization header");
        }
    }

    @Test
    void anAdoptedDeviceCredentialIsNotAttachedToAnyOauth2Request() throws Exception {
        try (MockWebServer server = server();
                AxiamClient client = builder(server.url("/").toString()).build()) {
            client.authenticateDevice();
            runTheFourOauth2Calls(client);
            assertNoAuthorizationOnOauth2();

            // Control: the adopted credential is on the next non-/oauth2 request.
            client.checkAccess("read", "documents/1");
            RecordedRequest control = seen.get(seen.size() - 1);
            assertEquals("Bearer device-token-xyz", control.getHeader("Authorization"));
        }
    }

    @Test
    void aSessionCredentialIsNotAttachedToAnyOauth2Request() throws Exception {
        try (MockWebServer server = server();
                AxiamClient client = builder(server.url("/").toString()).build()) {
            client.login("a@b.test", "password");
            runTheFourOauth2Calls(client);
            assertNoAuthorizationOnOauth2();

            // Control: the session is on the next non-/oauth2 request.
            client.checkAccess("read", "documents/1");
            RecordedRequest control = seen.get(seen.size() - 1);
            assertNotNull(control.getHeader("Authorization"), "the session bearer rides the control call");
            assertEquals("Bearer " + sessionAccess, control.getHeader("Authorization"));
        }
    }

    @Test
    void theRegistrationCallStillCarriesItsExplicitToken() throws Exception {
        String registrationToken = UUID.randomUUID().toString().replace("-", "");
        try (MockWebServer server = server();
                AxiamClient client = builder(server.url("/").toString()).build()) {
            client.login("a@b.test", "password");
            client.readClientRegistration(server.url("/oauth2/register/c1?tenant_id=" + TENANT_ID).toString(),
                    Sensitive.of(registrationToken));
            RecordedRequest registration = to("/oauth2/register/c1").get(0);
            assertEquals("Bearer " + registrationToken, registration.getHeader("Authorization"),
                    "§28.12: the caller's explicit registration_access_token is that call's own credential");
        }
    }
}
