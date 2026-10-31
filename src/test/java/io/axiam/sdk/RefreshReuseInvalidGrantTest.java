package io.axiam.sdk;

import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * CONTRACT.md &sect;9, the contract 1.65 paragraph "A replayed refresh token ends the session":
 * against a mocked {@code 400 invalid_grant} on {@code oidcRefresh}, a burst of N (&ge; 5)
 * concurrent callers makes exactly one wire call, every waiter receives that one
 * {@link OAuthProtocolError}, and the spent token is never presented again.
 */
class RefreshReuseInvalidGrantTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";

    @Test
    void invalidGrantOnOidcRefreshIsOneWireCallSharedByEveryWaiter() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            // Held back so all waiters are inside the single flight before it settles.
            server.enqueue(OidcTestSupport.oauthError(400, "invalid_grant").setBodyDelay(750, TimeUnit.MILLISECONDS));
            server.start();

            int threads = 8;
            List<Throwable> outcomes = new ArrayList<>();
            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("my-app").build()) {
                client.oidcDiscover();
                ExecutorService pool = Executors.newFixedThreadPool(threads);
                CountDownLatch start = new CountDownLatch(1);
                try {
                    List<Future<OidcTokenSet>> futures = new ArrayList<>();
                    for (int i = 0; i < threads; i++) {
                        futures.add(pool.submit(() -> {
                            start.await();
                            return client.oidcRefresh("spent-refresh-token");
                        }));
                    }
                    start.countDown();
                    for (Future<OidcTokenSet> f : futures) {
                        try {
                            f.get(10, TimeUnit.SECONDS);
                            throw new AssertionError("a refresh answered invalid_grant must not succeed");
                        } catch (ExecutionException e) {
                            outcomes.add(e.getCause());
                        }
                    }
                } finally {
                    pool.shutdown();
                    pool.awaitTermination(5, TimeUnit.SECONDS);
                }

                assertEquals(threads, outcomes.size());
                OAuthProtocolError first = assertInstanceOf(OAuthProtocolError.class, outcomes.get(0));
                assertEquals("invalid_grant", first.error());
                for (Throwable t : outcomes) {
                    assertSame(first, t, "every waiter receives that one call's outcome");
                }
                assertEquals(2, server.getRequestCount(), "discovery plus exactly one token request");

                // A later call made with no new token from the caller makes no request with the spent
                // token again: the SDK holds no refresh token of its own to present, and the cached
                // discovery document costs no request.
                client.oidcDiscover();
                assertEquals(2, server.getRequestCount());
            }
            server.takeRequest();
            RecordedRequest token = server.takeRequest();
            assertEquals("/oauth2/token", token.getRequestUrl().encodedPath());
            assertEquals(1, token.getBody().readUtf8().split("spent-refresh-token", -1).length - 1,
                    "the spent token was presented once");
        }
    }
}
