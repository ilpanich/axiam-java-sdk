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
import static org.junit.jupiter.api.Assertions.assertThrows;
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
