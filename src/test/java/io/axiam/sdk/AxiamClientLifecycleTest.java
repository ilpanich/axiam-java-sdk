package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code verifyMfa}/{@code refresh}/{@code logout} success and error paths, the async
 * {@code CompletableFuture} twins, the {@code org_id}-configured login body branch, and {@code
 * buildUser}'s two "login succeeded but the session is unusable" guards (CONTRACT.md &sect;1).
 * {@link io.axiam.sdk.rest.AuthFlowTest} already covers the MFA-challenge and orgSlug-login
 * paths; this class covers what remains.
 */
class AxiamClientLifecycleTest {

    @Test
    void loginWithOrgIdPutsOrgIdInTheRequestBodyInsteadOfOrgSlug() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgId(java.util.UUID.fromString("44444444-4444-4444-4444-444444444444"))
                    .build()) {
                client.login("alice@example.com", "correct horse battery staple");

                RecordedRequest recorded = server.takeRequest();
                String body = recorded.getBody().readUtf8();
                assertTrue(body.contains("\"org_id\":\"44444444-4444-4444-4444-444444444444\""));
                assertFalse(body.contains("org_slug"));
            }
        }
    }

    @Test
    void loginAsyncResolvesTheSameOutcomeAsLogin() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                LoginResult result = client.loginAsync("alice@example.com", "correct horse battery staple").get();
                assertFalse(result.mfaRequired());
                assertNotNull(result.user());
            }
        }
    }

    @Test
    void loginNonSuccessNonChallengeStatusThrowsMappedError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(403).setBody("forbidden"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(AuthzError.class, () -> client.login("alice@example.com", "wrong"));
            }
        }
    }

    @Test
    void verifyMfaSuccessReturnsEstablishedSession() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(900) + "; Path=/; HttpOnly")
                    .addHeader("Set-Cookie", "axiam_refresh=fake-refresh; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\","
                            + "\"email\":\"alice@example.com\"},\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                LoginResult result = client.verifyMfa(Sensitive.of("chal-abc"), "123456");
                assertFalse(result.mfaRequired());
                assertNotNull(result.user());

                RecordedRequest recorded = server.takeRequest();
                assertEquals("/api/v1/auth/mfa/verify", recorded.getPath());
                String body = recorded.getBody().readUtf8();
                assertTrue(body.contains("\"challenge_token\":\"chal-abc\""));
                assertTrue(body.contains("\"totp_code\":\"123456\""));
            }
        }
    }

    @Test
    void verifyMfaAsyncResolvesTheSameOutcome() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(900) + "; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\","
                            + "\"email\":\"alice@example.com\"},\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                LoginResult result = client.verifyMfaAsync(Sensitive.of("chal-abc"), "123456").get();
                assertFalse(result.mfaRequired());
            }
        }
    }

    @Test
    void verifyMfaFailureThrowsMappedError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(401).setBody("invalid code"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(AuthError.class, () -> client.verifyMfa(Sensitive.of("chal-abc"), "000000"));
            }
        }
    }

    @Test
    void refreshWithNoAccessTokenThrowsAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(AuthError.class, client::refresh, "refresh() before any login() must fail fast");
            }
        }
    }

    @Test
    void refreshAsyncCompletesAfterASuccessfulLogin() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(900) + "; Path=/; HttpOnly")
                    .addHeader("Set-Cookie", "axiam_refresh=new-refresh; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                client.login("alice@example.com", "correct horse battery staple");
                client.refreshAsync().get();
            }
        }
    }

    @Test
    void logoutWithNoActiveSessionThrowsAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(AuthError.class, client::logout);
            }
        }
    }

    @Test
    void logoutWithAnAccessTokenMissingJtiThrowsAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // 200 login success, but the returned access token has NO "jti" claim.
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessTokenWithoutJti(900) + "; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\","
                            + "\"email\":\"alice@example.com\"},\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                client.login("alice@example.com", "correct horse battery staple");
                assertThrows(AuthError.class, client::logout);
            }
        }
    }

    @Test
    void logoutSuccessClearsSessionAndLogoutAsyncCompletes() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.enqueue(new MockResponse().setResponseCode(204));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                client.login("alice@example.com", "correct horse battery staple");
                client.logoutAsync().get();

                RecordedRequest logoutRequest = server.takeRequest(); // login
                logoutRequest = server.takeRequest(); // logout
                assertEquals("/api/v1/auth/logout", logoutRequest.getPath());
                String body = logoutRequest.getBody().readUtf8();
                assertTrue(body.contains("\"session_id\":\"22222222-2222-2222-2222-222222222222\""));
            }
        }
    }

    @Test
    void logoutServerErrorThrowsMappedError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginSuccessResponse());
            server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                client.login("alice@example.com", "correct horse battery staple");
                assertThrows(RuntimeException.class, client::logout);
            }
        }
    }

    @Test
    void loginSucceedsButNoAccessTokenCookieIsSetThrowsAuthErrorFromBuildUser() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // 200 with a body but NO Set-Cookie header at all.
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\","
                            + "\"email\":\"alice@example.com\"},\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                AuthError error = assertThrows(AuthError.class,
                        () -> client.login("alice@example.com", "correct horse battery staple"));
                assertTrue(error.getMessage().contains("no access token was set"));
            }
        }
    }

    @Test
    void loginSucceedsButAccessTokenCookieIsUndecodableThrowsAuthErrorFromBuildUser() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // 200 with an axiam_access cookie value that is not a 3-part JWT at all.
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=not-a-jwt; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\","
                            + "\"email\":\"alice@example.com\"},\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                            + "\"expires_in\":900}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                AuthError error = assertThrows(AuthError.class,
                        () -> client.login("alice@example.com", "correct horse battery staple"));
                assertTrue(error.getMessage().contains("failed to decode access token claims"));
            }
        }
    }

    private static MockResponse loginSuccessResponse() {
        return new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(900) + "; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_refresh=fake-refresh-token; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\",\"email\":\"alice@example.com\"},"
                        + "\"session_id\":\"22222222-2222-2222-2222-222222222222\",\"expires_in\":900}");
    }

    private static String fakeAccessToken(long expiresInSeconds) {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"33333333-3333-3333-3333-333333333333\","
                + "\"org_id\":\"44444444-4444-4444-4444-444444444444\","
                + "\"jti\":\"22222222-2222-2222-2222-222222222222\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + expiresInSeconds) + "}");
        return header + "." + payload + ".fake-signature";
    }

    /** A well-formed, decodable access token whose payload deliberately omits "jti". */
    private static String fakeAccessTokenWithoutJti(long expiresInSeconds) {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"33333333-3333-3333-3333-333333333333\","
                + "\"org_id\":\"44444444-4444-4444-4444-444444444444\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + expiresInSeconds) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
