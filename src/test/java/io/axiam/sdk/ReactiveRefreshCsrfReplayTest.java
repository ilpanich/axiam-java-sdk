package io.axiam.sdk;

import io.axiam.sdk.management.models.CreateUserRequest;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;9 rule 1 and &sect;3 (non-browser rule 2), C164-26: after a reactive refresh
 * (a {@code 401} on a write) the replay carries the <em>rotated</em> CSRF token, not the one the
 * request first went out with. The replay is built by OkHttp's authenticator below the
 * application interceptors, so the header has to be set there.
 */
class ReactiveRefreshCsrfReplayTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";

    @Test
    void theReplayAfterARefreshCarriesTheRotatedCsrfToken() throws Exception {
        List<RecordedRequest> writes = new ArrayList<>();
        AtomicInteger usersCalls = new AtomicInteger();
        String loginAccess = OidcTestTokens.unsignedAccessToken();
        String refreshedAccess = OidcTestTokens.unsignedAccessToken();
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    String path = request.getRequestUrl().encodedPath();
                    return switch (path) {
                        case "/api/v1/auth/login" -> new MockResponse().setResponseCode(200)
                                .setHeader("Content-Type", "application/json")
                                .addHeader("Set-Cookie", "axiam_access=" + loginAccess + "; Path=/; HttpOnly")
                                .addHeader("Set-Cookie", "axiam_refresh=r1; Path=/; HttpOnly")
                                .addHeader("Set-Cookie", "axiam_csrf=CSRF-OLD; Path=/")
                                .setHeader("X-CSRF-Token", "CSRF-OLD")
                                .setBody("{\"mfa_required\":false,\"user\":{\"id\":\"11111111-1111-4111-8111-"
                                        + "111111111111\",\"email\":\"a@b.test\",\"username\":\"a\"}}");
                        case "/api/v1/auth/refresh" -> new MockResponse().setResponseCode(200)
                                .setHeader("Content-Type", "application/json")
                                .addHeader("Set-Cookie", "axiam_access=" + refreshedAccess + "; Path=/; HttpOnly")
                                .addHeader("Set-Cookie", "axiam_refresh=r2; Path=/; HttpOnly")
                                .addHeader("Set-Cookie", "axiam_csrf=CSRF-NEW; Path=/")
                                .setHeader("X-CSRF-Token", "CSRF-NEW")
                                .setBody("{\"expires_in\":900}");
                        case "/api/v1/users" -> {
                            synchronized (writes) {
                                writes.add(request);
                            }
                            yield usersCalls.getAndIncrement() == 0
                                    ? new MockResponse().setResponseCode(401)
                                            .setHeader("Content-Type", "application/json")
                                            .setBody("{\"message\":\"expired\"}")
                                    : new MockResponse().setResponseCode(200)
                                            .setHeader("Content-Type", "application/json").setBody("{}");
                        }
                        default -> new MockResponse().setResponseCode(200)
                                .setHeader("Content-Type", "application/json").setBody("{}");
                    };
                }
            });
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                client.login("a@b.test", "password");
                try {
                    client.management().users().create(new CreateUserRequest(
                            "a@b.test", null, null, Sensitive.of("hunter2hunter2"), "bob"));
                } catch (RuntimeException ignored) {
                    // the mock's body is not a user; the replayed request is what is asserted
                }
            }

            assertEquals(2, writes.size(), "the 401 write and its replay");
            assertEquals("CSRF-OLD", writes.get(0).getHeader("X-CSRF-Token"));
            RecordedRequest replay = writes.get(1);
            assertEquals("CSRF-NEW", replay.getHeader("X-CSRF-Token"),
                    "the replay carries the token the refresh rotated to");
            assertTrue(replay.getHeader("Cookie").contains("axiam_csrf=CSRF-NEW"), replay.getHeader("Cookie"));
            assertEquals("Bearer " + refreshedAccess, replay.getHeader("Authorization"));
        }
    }
}
