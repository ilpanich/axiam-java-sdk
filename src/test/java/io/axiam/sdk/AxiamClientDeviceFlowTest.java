package io.axiam.sdk;

import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.DeviceAuthorization;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Device Authorization Grant — CONTRACT.md &sect;14.
 *
 * <p>Fixtures use a 1-second interval so the wire assertions — which answers
 * loop, which terminate, how many requests actually go out, and the &sect;14.3
 * rule 2 ordering guarantee — run in about as long as they take to describe.
 * The interval <em>arithmetic</em> is asserted through those same paths:
 * {@code slow_down} is proven non-terminal, and the {@code expires_in}
 * deadline is proven authoritative by counting the requests that never left.
 */
class AxiamClientDeviceFlowTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String DEVICE_CODE = "device-code-value";
    private static final String USER_CODE = "WDJB-MJHT";

    private static AxiamClient deviceClient(String base) {
        // Built WITHOUT a client secret: §14.1 says a device that cannot show
        // a browser cannot hold one, and the SDK must not refuse such a client.
        return AxiamClient.builder(base, TENANT_ID).oidcClientId("my-device").build();
    }

    // -----------------------------------------------------------------------
    // deviceAuthorize
    // -----------------------------------------------------------------------

    @Test
    void deviceAuthorizeIsUnauthenticatedAndFormEncoded() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 1));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                DeviceAuthorization authorization = client.deviceAuthorize("openid profile", null, null);

                server.takeRequest(); // discovery
                RecordedRequest request = server.takeRequest();
                String body = request.getBody().readUtf8();

                assertTrue(request.getHeader("Content-Type").startsWith("application/x-www-form-urlencoded"));
                assertFalse(body.contains("client_secret"),
                        "§14.1: deviceAuthorize MUST NOT send client_secret");
                assertTrue(body.contains("scope=openid+profile"));
                assertFalse(body.contains("tenant_id"),
                        "§12.1 note 2: tenant_id is a query parameter, never a body field");
                assertEquals(TENANT_ID, request.getRequestUrl().queryParameter("tenant_id"));

                assertEquals(USER_CODE, authorization.userCode());
                assertEquals(1, authorization.interval());
                assertNotNull(authorization.verificationUriComplete());
            }
        }
    }

    @Test
    void absentIntervalDefaultsToFiveSecondsNotFaster() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 600, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                DeviceAuthorization authorization = client.deviceAuthorize();
                assertEquals(AxiamClient.DEFAULT_DEVICE_POLL_INTERVAL_SECONDS, authorization.interval(),
                        "§14.2 rule 2: an absent interval defaults to 5 s; an SDK MUST NOT "
                                + "hard-code a faster floor");
            }
        }
    }

    @Test
    void deviceAuthorizeErrorsWhenServerAdvertisesNoEndpoint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponseWithoutOptionalEndpoints(base));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                io.axiam.sdk.errors.AuthError error = assertThrows(io.axiam.sdk.errors.AuthError.class,
                        client::deviceAuthorize);
                assertTrue(error.getMessage().contains("device_authorization_endpoint"),
                        "the error should name the missing endpoint rather than guessing a URL");
                // Only discovery went out — no URL was synthesised and tried.
                assertEquals(1, server.getRequestCount());
            }
        }
    }

    @Test
    void deviceCodeIsRedactedAndUserCodeIsNot() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 1));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                DeviceAuthorization authorization = client.deviceAuthorize();

                assertFalse(authorization.deviceCode().toString().contains(DEVICE_CODE),
                        "§14.5: device_code is a bearer credential and must never render");
                assertFalse(authorization.toString().contains(DEVICE_CODE));
                assertEquals(DEVICE_CODE, authorization.deviceCode().expose());
                // §14.5: userCode is NOT wrapped — it exists to be read aloud,
                // and wrapping it would defeat the one thing it is for.
                assertEquals(USER_CODE, authorization.userCode());
                assertTrue(authorization.toString().contains(USER_CODE));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §14.2 polling
    // -----------------------------------------------------------------------

    @Test
    void authorizationPendingLoopsRatherThanRaising() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", "device-refresh-token", null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = client.deviceLogin(null, null, null, a -> { });

                assertEquals("device-access-token", tokens.accessToken().expose());
                // discovery + device_authorization + three polls
                assertEquals(5, server.getRequestCount());
            }
        }
    }

    @Test
    void slowDownIsNotTerminal() throws Exception {
        // The interval increase itself is not wall-clock-asserted; what matters
        // here is that slow_down is not mistaken for a terminal answer. An SDK
        // that let it fall through would abort a grant the user is still
        // approving.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "slow_down"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = client.deviceLogin(null, null, null, a -> { });
                assertEquals("device-access-token", tokens.accessToken().expose());
                assertEquals(4, server.getRequestCount());
            }
        }
    }

    /** A recorded sleeper (§14.6: "a fake clock or a recorded sleep, not a wall-clock sleep"). */
    private static final class RecordedClock implements io.axiam.sdk.oidc.CibaClock {
        private java.time.Instant now = java.time.Instant.parse("2026-10-23T00:00:00Z");
        final List<Long> sleeps = new java.util.ArrayList<>();

        @Override
        public java.time.Instant now() {
            return now;
        }

        @Override
        public void sleep(java.time.Duration duration) {
            sleeps.add(duration.toSeconds());
            advance(duration);
        }

        /** Time that passes outside a sleep: a callback, or a request in flight. */
        synchronized void advance(java.time.Duration duration) {
            now = now.plus(duration);
        }
    }

    /** The body AXIAM's token endpoint sends on a rate limit: no {@code error_description}. */
    private static okhttp3.mockwebserver.MockResponse serverRateLimit(String retryAfter) {
        okhttp3.mockwebserver.MockResponse r = new okhttp3.mockwebserver.MockResponse()
                .setResponseCode(429).setHeader("Content-Type", "application/json")
                .setBody("{\"error\":\"rate_limit_exceeded\"}");
        return retryAfter == null ? r : r.setHeader("Retry-After", retryAfter);
    }

    private OidcTokenSet runDeviceLogin(MockWebServer server, RecordedClock clock) {
        try (AxiamClient client = deviceClient(server.url("/").toString())) {
            return client.deviceLogin(null, null, null, a -> { }, clock);
        }
    }

    @Test
    void rateLimitedPollIsWaitedOutAndLeavesTheIntervalUnchanged() throws Exception {
        // §14.6 (contract 1.64): a mock answers one poll with 429 and Retry-After; the loop
        // waits, polls again and completes; the interval is unchanged. Interval 1, Retry-After 2:
        // the waits are 1 (before poll 1, answered 429), 2 (the Retry-After, counted as one
        // interval, not on top of it), 1 (poll 2 answers pending: the interval is unchanged).
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(serverRateLimit("2"));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            RecordedClock clock = new RecordedClock();
            OidcTokenSet tokens = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                    () -> runDeviceLogin(server, clock));

            assertEquals("device-access-token", tokens.accessToken().expose());
            assertEquals(List.of(1L, 2L, 1L), clock.sleeps,
                    "Retry-After is a minimum that replaces one interval; it is neither added to "
                            + "it nor kept for the polls after it");
            assertEquals(5, server.getRequestCount()); // discovery + authorization + three polls
        }
    }

    @Test
    void rateLimitedPollWithoutRetryAfterWaitsTheInterval() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 3));
            server.enqueue(serverRateLimit(null));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            RecordedClock clock = new RecordedClock();
            assertTimeoutPreemptively(java.time.Duration.ofSeconds(10), () -> runDeviceLogin(server, clock));
            assertEquals(List.of(3L, 3L), clock.sleeps);
        }
    }

    @Test
    void anyRateLimitIsTheWaitWhateverItsBodyNames() throws Exception {
        // §14.2 rule 9 (contract 1.64, amended): the status decides, not the body. A 429 that
        // says slow_down (a server before 1.1.2, or an intermediary) does not raise the interval,
        // and a bodiless 429 honours Retry-After as a floor.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(429)
                    .setHeader("Content-Type", "application/json").setHeader("Retry-After", "1")
                    .setBody("{\"error\":\"slow_down\"}"));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(429)
                    .setHeader("Retry-After", "4"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            RecordedClock clock = new RecordedClock();
            assertTimeoutPreemptively(java.time.Duration.ofSeconds(10), () -> runDeviceLogin(server, clock));
            assertEquals(List.of(1L, 1L, 1L, 4L), clock.sleeps);
        }
    }

    @Test
    void aSingleDevicePollOnA429RaisesRateLimitExceededWithItsRetryAfter() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(serverRateLimit("7"));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OAuthProtocolError e = assertThrows(OAuthProtocolError.class,
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null));
                assertEquals("rate_limit_exceeded", e.error());
                assertEquals(7, e.retryAfterSeconds());
                assertNull(e.errorDescription());
            }
        }
    }

    @Test
    void rateLimitedPollRetryAfterIsCappedAtTheDeadline() throws Exception {
        // §14.2 rule 9: Retry-After is a minimum, capped at the expires_in deadline of rule 4.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 5, 1));
            server.enqueue(serverRateLimit("3600"));
            server.start();

            RecordedClock clock = new RecordedClock();
            OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                    () -> assertThrows(OAuthProtocolError.class, () -> runDeviceLogin(server, clock)));
            assertEquals("expired_token", error.error());
            assertEquals(3, server.getRequestCount(), "no poll is sent past the deadline");
            assertEquals(List.of(1L), clock.sleeps, "the capped wait is not served");
        }
    }

    @Test
    void aServerErrorWithAnOauthBodyMidPollIsATransportFailureNotTerminal() throws Exception {
        // §14.2 rule 6 (contract 1.64, amended): the status is read before the body, and AXIAM's
        // own 500 is {"error":"server_error"}, which rule 5 would otherwise dispatch.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(500)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"server_error\",\"error_description\":\"internal\"}"));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            RecordedClock clock = new RecordedClock();
            OidcTokenSet tokens = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                    () -> runDeviceLogin(server, clock));
            assertEquals("device-access-token", tokens.accessToken().expose());
            assertEquals(5, server.getRequestCount());
        }
    }

    @Test
    void aHugeRetryAfterIsCappedAtTheDeadlineNotAnOverflow() throws Exception {
        // C164-30: Retry-After is clamped, so the deadline check (the typed expired_token) is
        // reached instead of an Instant overflow.
        for (String huge : List.of("99999999999999999", "9223372036854775807")) {
            try (MockWebServer server = new MockWebServer()) {
                String base = server.url("/").toString();
                server.enqueue(OidcTestSupport.discoveryResponse(base));
                server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
                server.enqueue(serverRateLimit(huge));
                server.start();

                RecordedClock clock = new RecordedClock();
                OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                        () -> assertThrows(OAuthProtocolError.class, () -> runDeviceLogin(server, clock)));
                assertEquals("expired_token", error.error());
                assertEquals(List.of(1L), clock.sleeps);
                assertEquals(3, server.getRequestCount());
            }
        }
    }

    @Test
    void timeSpentInTheUserCodeCallbackCountsAgainstTheDeadline() throws Exception {
        // C164-29 (C164-05): the deadline is a clock instant, not a budget of sleeps. A callback
        // that takes 25 s of a 30 s grant leaves no room for a 5 s interval: nothing is polled.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 5));
            server.start();

            RecordedClock clock = new RecordedClock();
            try (AxiamClient client = deviceClient(base)) {
                // A preemptive timeout: a loop that took the deadline after the callback would poll
                // an empty mock queue at the read timeout and hang rather than fail (C164-41).
                OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                        () -> assertThrows(OAuthProtocolError.class,
                                () -> client.deviceLogin(null, null, null,
                                        a -> clock.advance(java.time.Duration.ofSeconds(25)), clock)));
                assertEquals("expired_token", error.error());
            }
            assertEquals(List.of(), clock.sleeps);
            assertEquals(2, server.getRequestCount(), "no poll after the deadline");
        }
    }

    @Test
    void timeSpentInAPollCountsAgainstTheDeadline() throws Exception {
        // C164-29: each poll takes 4 s of a 12 s grant at interval 2. Sleeps alone would allow six
        // polls; on the clock the third wait (t = 12) is at the deadline, so exactly two go out.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            RecordedClock clock = new RecordedClock();
            server.setDispatcher(new okhttp3.mockwebserver.Dispatcher() {
                @Override
                public okhttp3.mockwebserver.MockResponse dispatch(RecordedRequest request) {
                    String path = request.getRequestUrl().encodedPath();
                    if (path.endsWith("openid-configuration")) {
                        return OidcTestSupport.discoveryResponse(base);
                    }
                    if (path.endsWith("device_authorization")) {
                        return OidcTestSupport.deviceAuthorizationResponse(base, 12, 2);
                    }
                    clock.advance(java.time.Duration.ofSeconds(4));
                    return OidcTestSupport.oauthError(400, "authorization_pending");
                }
            });
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                        () -> assertThrows(OAuthProtocolError.class,
                                () -> client.deviceLogin(null, null, null, a -> { }, clock)));
                assertEquals("expired_token", error.error());
            }
            assertEquals(List.of(2L, 2L), clock.sleeps);
            assertEquals(4, server.getRequestCount(), "discovery, authorization and two polls");
        }
    }

    @Test
    void aSinglePollIsRetriedWithinTheAttemptOnA5xxButNeverOnA429() throws Exception {
        // C164-25, §14.2 rule 6 / §16.2: 500 server_error and 503 are retried within the poll
        // (at most three attempts); a 429 is the loop's rule-9 wait and is sent once.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(500)
                    .setHeader("Content-Type", "application/json").setBody("{\"error\":\"server_error\"}"));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(503));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.enqueue(serverRateLimit("1"));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null);
                assertEquals("device-access-token", tokens.accessToken().expose());
                assertEquals(4, server.getRequestCount(), "discovery and three attempts");

                OAuthProtocolError limited = assertThrows(OAuthProtocolError.class,
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null));
                assertEquals("rate_limit_exceeded", limited.error());
                assertEquals(5, server.getRequestCount(), "a 429 is not retried within the poll");
            }
        }
    }

    private static okhttp3.mockwebserver.MockResponse serverError500() {
        return new okhttp3.mockwebserver.MockResponse().setResponseCode(500)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"error\":\"server_error\",\"error_description\":\"internal\"}");
    }

    private static okhttp3.mockwebserver.MockResponse disconnect() {
        return new okhttp3.mockwebserver.MockResponse()
                .setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AFTER_REQUEST);
    }

    @Test
    void twoServerErrorsThenTokensIsOneAttemptOfThreeRequests() throws Exception {
        // C164-38, §14.6 (W7.1c): two 500s then 200 within one poll -> three requests, the tokens.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(serverError500());
            server.enqueue(serverError500());
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null);
                assertEquals("device-access-token", tokens.accessToken().expose());
                assertEquals(4, server.getRequestCount(), "discovery and three attempts");
            }
        }
    }

    @Test
    void theAttemptCapIsThreeInTotal() throws Exception {
        // C164-38: a third 500 exhausts the cap (§16.1: three attempts in total), so exactly three
        // requests are sent and the NetworkError surfaces. A cap of 5 sends five and fails this.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            for (int i = 0; i < 6; i++) {
                server.enqueue(serverError500());
            }
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                assertThrows(io.axiam.sdk.errors.NetworkError.class,
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null));
                assertEquals(4, server.getRequestCount(), "discovery and exactly three attempts");
            }
        }
    }

    @Test
    void twoTransportFailuresThenTokensIsThreeRequests() throws Exception {
        // C164-38 / C164-39: connection dropped twice, then 200 -> three requests and the tokens.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(disconnect());
            server.enqueue(disconnect());
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = assertTimeoutPreemptively(java.time.Duration.ofSeconds(20),
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null));
                assertEquals("device-access-token", tokens.accessToken().expose());
                assertEquals(4, server.getRequestCount(), "discovery and three attempts");
            }
        }
    }

    @Test
    void threeTransportFailuresExhaustTheCapWithoutASilentOkHttpReplay() throws Exception {
        // C164-39: OkHttp's own replay of a POST on a dropped pooled connection is off for the
        // poll, so the §16 runner alone counts: three drops -> NetworkError after exactly three
        // requests (with the replay on, the fourth would succeed).
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(disconnect());
            server.enqueue(disconnect());
            server.enqueue(disconnect());
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                assertTimeoutPreemptively(java.time.Duration.ofSeconds(20), () -> assertThrows(
                        io.axiam.sdk.errors.NetworkError.class,
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null)));
                assertEquals(4, server.getRequestCount(), "discovery and exactly three attempts");
            }
        }
    }

    @Test
    void withRetryDisabledATransportFailureIsSentOnce() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(disconnect());
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("my-device")
                    .retryDisabled().build()) {
                assertTimeoutPreemptively(java.time.Duration.ofSeconds(20), () -> assertThrows(
                        io.axiam.sdk.errors.NetworkError.class,
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null)));
                assertEquals(2, server.getRequestCount());
            }
        }
    }

    @Test
    void theInPollRetryNeverSendsAtOrAfterTheDeadline() throws Exception {
        // C164-36, §14.2 rule 4: expires_in 30, interval 5, every poll 503 + Retry-After: 120 (the
        // floor is clamped at 5 s). Polls go out at 5, 10, 15 (one attempt of three), then 20 and 25;
        // the retry due at t = 30 is exactly the deadline, which is not before it, so it is not sent
        // (C164-45: this pins the strict boundary): no request at or after t = 30 on the clock, and
        // the loop ends with expired_token.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            RecordedClock clock = new RecordedClock();
            java.time.Instant start = clock.now();
            List<Long> requestSeconds = new java.util.concurrent.CopyOnWriteArrayList<>();
            server.setDispatcher(new okhttp3.mockwebserver.Dispatcher() {
                @Override
                public okhttp3.mockwebserver.MockResponse dispatch(RecordedRequest request) {
                    String path = request.getRequestUrl().encodedPath();
                    if (path.endsWith("openid-configuration")) {
                        return OidcTestSupport.discoveryResponse(base);
                    }
                    if (path.endsWith("device_authorization")) {
                        return OidcTestSupport.deviceAuthorizationResponse(base, 30, 5);
                    }
                    requestSeconds.add(java.time.Duration.between(start, clock.now()).toSeconds());
                    return new okhttp3.mockwebserver.MockResponse().setResponseCode(503)
                            .setHeader("Retry-After", "120");
                }
            });
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                        () -> assertThrows(OAuthProtocolError.class,
                                () -> client.deviceLogin(null, null, null, a -> { }, clock)));
                assertEquals("expired_token", error.error());
            }
            assertEquals(List.of(5L, 10L, 15L, 20L, 25L), requestSeconds, "nothing at or after t = 30 s");
            assertEquals(List.of(5L, 5L, 5L, 5L, 5L), clock.sleeps, "loop wait, two in-poll waits, loop wait, one in-poll wait");
        }
    }

    @Test
    void aPollSentJustBeforeTheDeadlineAnswered5xxIsNotRetried() throws Exception {
        // C164-36 (2): the poll goes out at deadline - 0.1 s and is answered 500; its retry, even at
        // the floor of 1 s, would be past the deadline, so none is sent.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 12, 2));
            server.enqueue(serverError500().setHeader("Retry-After", "1"));
            server.start();

            RecordedClock clock = new RecordedClock();
            try (AxiamClient client = deviceClient(base)) {
                OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                        () -> assertThrows(OAuthProtocolError.class,
                                () -> client.deviceLogin(null, null, null,
                                        a -> clock.advance(java.time.Duration.ofMillis(9_900)), clock)));
                assertEquals("expired_token", error.error());
            }
            assertEquals(3, server.getRequestCount(), "discovery, authorization and the one poll");
            assertEquals(List.of(2L), clock.sleeps, "no retry wait was served");
        }
    }

    /** A jitter source pinned to {@code value} in [0, 1): the in-attempt backoff is {@code value * 200} ms. */
    private static java.util.Random jitter(double value) {
        return new java.util.Random() {
            @Override
            public double nextDouble() {
                return value;
            }
        };
    }

    private void pollJustBeforeTheDeadlineWithJitter(double jitterValue, boolean retrySent) throws Exception {
        // C164-45: a bare 500 (no Retry-After) to a poll at deadline - 100 ms. The retry's wait is the
        // jittered backoff alone, pinned here: a deadline check that adds only the Retry-After floor
        // and not the jitter would send the retry whatever the jitter.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 12, 2));
            server.enqueue(serverError500());
            if (retrySent) {
                server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            }
            server.start();

            RecordedClock clock = new RecordedClock();
            try (AxiamClient client = deviceClient(base)) {
                client.setPollJitterForTesting(jitter(jitterValue));
                java.util.function.Supplier<OidcTokenSet> login = () -> client.deviceLogin(null, null, null,
                        a -> clock.advance(java.time.Duration.ofMillis(9_900)), clock);
                if (retrySent) {
                    assertEquals("device-access-token", assertTimeoutPreemptively(
                            java.time.Duration.ofSeconds(10), login::get).accessToken().expose());
                    assertEquals(4, server.getRequestCount(), "discovery, authorization, the poll and its retry");
                    assertEquals(List.of(2L, 0L), clock.sleeps, "the zero-jitter retry fits before the deadline");
                } else {
                    OAuthProtocolError error = assertTimeoutPreemptively(java.time.Duration.ofSeconds(10),
                            () -> assertThrows(OAuthProtocolError.class, login::get));
                    assertEquals("expired_token", error.error());
                    assertEquals(3, server.getRequestCount(), "discovery, authorization and the one poll");
                    assertEquals(List.of(2L), clock.sleeps, "no retry wait was served");
                }
            }
        }
    }

    @Test
    void aBare500JustBeforeTheDeadlineIsNotRetriedWhenTheMaximumJitterWouldPassIt() throws Exception {
        pollJustBeforeTheDeadlineWithJitter(0.999999, false); // 199 ms wait: 11.9 s + 199 ms > 12 s
    }

    @Test
    void aRetryDueExactlyAtTheDeadlineIsNotSent() throws Exception {
        pollJustBeforeTheDeadlineWithJitter(0.5, false); // 100 ms wait: 11.9 s + 100 ms == the deadline
    }

    @Test
    void aRetryThatFitsBeforeTheDeadlineIsStillSent() throws Exception {
        pollJustBeforeTheDeadlineWithJitter(0.0, true); // no wait: the check is not "never retry"
    }

    @Test
    void theCibaPollHasNoSilentOkHttpReplayEither() throws Exception {
        // C164-39: the same shape on the CIBA poll: three drops -> an error after exactly three
        // token requests, not a fourth that succeeds.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(disconnect());
            server.enqueue(disconnect());
            server.enqueue(disconnect());
            server.enqueue(OidcTestSupport.tokenResponse("ciba-access-token", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("my-ciba")
                    .oidcClientSecret("s3cr3t-value").build()) {
                assertTimeoutPreemptively(java.time.Duration.ofSeconds(20), () -> assertThrows(
                        RuntimeException.class,
                        () -> client.cibaPoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null)));
                assertEquals(4, server.getRequestCount(), "discovery and exactly three attempts");
            }
        }
    }

    @Test
    void withRetryDisabledASinglePollIsSentOnce() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(500)
                    .setHeader("Content-Type", "application/json").setBody("{\"error\":\"server_error\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("my-device")
                    .retryDisabled().build()) {
                assertThrows(io.axiam.sdk.errors.NetworkError.class,
                        () -> client.devicePoll(io.axiam.sdk.Sensitive.of(DEVICE_CODE), null, null));
                assertEquals(2, server.getRequestCount());
            }
        }
    }

    @Test
    void accessDeniedAndExpiredTokenStayDistinct() throws Exception {
        // §14.2 rule 3: "a human said no" and "nobody answered" are the only
        // two pieces of information the device can act on.
        for (String code : List.of("access_denied", "expired_token", "invalid_grant")) {
            try (MockWebServer server = new MockWebServer()) {
                String base = server.url("/").toString();
                server.enqueue(OidcTestSupport.discoveryResponse(base));
                server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 1));
                server.enqueue(OidcTestSupport.oauthError(400, code));
                server.start();

                try (AxiamClient client = deviceClient(base)) {
                    OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                            () -> client.deviceLogin(null, null, null, a -> { }));
                    assertEquals(code, error.error());
                    assertEquals(3, server.getRequestCount(),
                            "a terminal answer must stop the loop at once");
                }
            }
        }
    }

    @Test
    void pollingStopsAtExpiresIn() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            // 2-second grant, 1-second interval: one poll at t=1, then the t=2
            // tick is the deadline and must not be sent.
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 2, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.deviceLogin(null, null, null, a -> { }));

                assertEquals("expired_token", error.error(),
                        "§14.2 rule 4: reported under the same code the server would have used, "
                                + "so a caller's branch does not care which side noticed first");
                assertEquals(3, server.getRequestCount(),
                        "no poll may be sent past the deadline, even while the server was "
                                + "still answering authorization_pending");
            }
        }
    }

    @Test
    void serverErrorMidPollIsRetriedNotTerminal() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 60, 1));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(500));
            server.enqueue(new okhttp3.mockwebserver.MockResponse().setResponseCode(503));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = assertDoesNotThrow(
                        () -> client.deviceLogin(null, null, null, a -> { }),
                        "§14.2 rule 6: a server restart must not lose an approved grant");
                assertEquals("device-access-token", tokens.accessToken().expose());
                assertEquals(6, server.getRequestCount());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §14.3 deviceLogin
    // -----------------------------------------------------------------------

    @Test
    void deviceLoginSurfacesUserCodeBeforeFirstPoll() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 1));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            List<String> order = new ArrayList<>();
            AtomicReference<String> seen = new AtomicReference<>();

            try (AxiamClient client = deviceClient(base)) {
                client.deviceLogin(null, null, null, a -> {
                    // The request count at callback time is the ordering proof:
                    // discovery + device_authorization have happened, no poll has.
                    order.add("userCode@" + server.getRequestCount());
                    seen.set(a.userCode());
                });
            }

            assertEquals(List.of("userCode@2"), order,
                    "§14.3 rule 2: the caller must have had the chance to display the code "
                            + "BEFORE polling begins");
            assertEquals(USER_CODE, seen.get());
        }
    }

    @Test
    void successfulDeviceLoginReturnsTheTokenSet() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.deviceAuthorizationResponse(base, 30, 1));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", "device-refresh-token", null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OidcTokenSet tokens = client.deviceLogin(null, null, null, a -> { });

                // §14.6 as amended by the contract 1.7 errata: assert the
                // RETURNED token set. This SDK does not adopt — §14.3 rule 4
                // defers to the §12.1 loginClientCredentials MAY, and Java's
                // settled posture there is to leave the tokens with the caller.
                assertEquals("device-access-token", tokens.accessToken().expose());
                assertEquals("Bearer", tokens.tokenType());
                assertNotNull(tokens.refreshToken());
            }
        }
    }

    // -----------------------------------------------------------------------
    // devicePoll standalone
    // -----------------------------------------------------------------------

    @Test
    void devicePollSurfacesPendingForHandRolledLoops() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.oauthError(400, "authorization_pending"));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.devicePoll(Sensitive.of(DEVICE_CODE), null, null));
                assertEquals("authorization_pending", error.error(),
                        "a hand-rolled loop must see exactly what deviceLogin sees");
            }
        }
    }

    @Test
    void devicePollSendsTheDeviceCodeGrant() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("device-access-token", null, null));
            server.start();

            try (AxiamClient client = deviceClient(base)) {
                client.devicePoll(Sensitive.of(DEVICE_CODE), null, null);

                server.takeRequest();
                String body = server.takeRequest().getBody().readUtf8();
                assertTrue(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
                assertTrue(body.contains("device_code=" + DEVICE_CODE));
            }
        }
    }
}
