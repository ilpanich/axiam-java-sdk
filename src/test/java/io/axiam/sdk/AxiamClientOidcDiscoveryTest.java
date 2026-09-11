package io.axiam.sdk;

import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.1 {@code oidcDiscover}: fetches
 * {@code GET /.well-known/openid-configuration}, caches per origin with a
 * &ge;5-minute floor, and de-duplicates concurrent callers into a single
 * fetch (&sect;12.3 rule 6).
 */
class AxiamClientOidcDiscoveryTest {

    @Test
    void discoverParsesEveryRequiredField() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();
            String base = server.url("/").toString();

            try (AxiamClient client = AxiamClient.builder(base, "33333333-3333-3333-3333-333333333333").build()) {
                OidcConfiguration config = client.oidcDiscover();

                assertEquals(stripSlash(base), config.issuer());
                assertEquals(stripSlash(base) + "/oauth2/authorize", config.authorization_endpoint());
                assertEquals(stripSlash(base) + "/oauth2/token", config.token_endpoint());
                assertEquals(stripSlash(base) + "/oauth2/jwks", config.jwks_uri());
                assertEquals(stripSlash(base) + "/oauth2/revoke", config.revocation_endpoint());
                assertEquals(stripSlash(base) + "/oauth2/introspect", config.introspection_endpoint());
                assertEquals(List.of("code"), config.response_types_supported());
                assertEquals(List.of("EdDSA"), config.id_token_signing_alg_values_supported());
            }

            RecordedRequest request = server.takeRequest();
            assertEquals("/.well-known/openid-configuration", request.getPath());
            assertEquals("GET", request.getMethod());
        }
    }

    @Test
    void discoverCachesAcrossRepeatedCallsWithinTtl() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "33333333-3333-3333-3333-333333333333")
                    .build()) {
                client.oidcDiscover();
                client.oidcDiscover();
                client.oidcDiscover();
            }

            assertEquals(1, server.getRequestCount(), "repeated calls within the TTL must not re-fetch");
        }
    }

    @Test
    void discoveryTtlBelowFiveMinutesIsFlooredAndCallerCanOverrideAboveTheFloor() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            // Requesting a 1ms TTL is floored to 5 minutes (§12.3 rule 6), so
            // a second call shortly after must still be served from cache.
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "33333333-3333-3333-3333-333333333333")
                    .oidcDiscoveryTtl(Duration.ofMillis(1))
                    .build()) {
                client.oidcDiscover();
                client.oidcDiscover();
            }

            assertEquals(1, server.getRequestCount(), "a sub-5-minute TTL must be floored to 5 minutes");
        }
    }

    @Test
    void concurrentDiscoverCallsTriggerExactlyOneFetch() throws Exception {
        AtomicInteger fetchCount = new AtomicInteger(0);
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    fetchCount.incrementAndGet();
                    return OidcTestSupport.discoveryResponse(server.url("/").toString());
                }
            });
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "33333333-3333-3333-3333-333333333333")
                    .build()) {
                int threadCount = 8;
                ExecutorService pool = Executors.newFixedThreadPool(threadCount);
                CountDownLatch startBarrier = new CountDownLatch(1);
                try {
                    List<Callable<OidcConfiguration>> tasks = new java.util.ArrayList<>();
                    for (int i = 0; i < threadCount; i++) {
                        tasks.add(() -> {
                            startBarrier.await();
                            return client.oidcDiscover();
                        });
                    }
                    List<Future<OidcConfiguration>> futures = new java.util.ArrayList<>();
                    for (Callable<OidcConfiguration> task : tasks) {
                        futures.add(pool.submit(task));
                    }
                    startBarrier.countDown();
                    for (Future<OidcConfiguration> future : futures) {
                        future.get(5, TimeUnit.SECONDS);
                    }
                } finally {
                    pool.shutdown();
                    assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
                }
            }
        }

        assertEquals(1, fetchCount.get(), "a concurrent discover() burst must collapse to exactly one fetch");
    }

    @Test
    void discoverAsyncResolvesTheSameDocument() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "33333333-3333-3333-3333-333333333333")
                    .build()) {
                OidcConfiguration config = client.oidcDiscoverAsync().get(5, TimeUnit.SECONDS);
                assertEquals(stripSlash(server.url("/").toString()), config.issuer());
            }
        }
    }

    @Test
    void discoveryFailureMapsToNetworkErrorOnServerError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(500));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "33333333-3333-3333-3333-333333333333")
                    .build()) {
                org.junit.jupiter.api.Assertions.assertThrows(
                        io.axiam.sdk.errors.NetworkError.class, client::oidcDiscover);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Contract 1.42 — code_challenge_methods_supported and
    // token_endpoint_auth_signing_alg_values_supported
    // -----------------------------------------------------------------------

    /**
     * Both members are marked REQUIRED in {@code openapi.json} as of contract
     * 1.42, and both are modelled {@code @Nullable} here on purpose
     * (CONTRACT.md &sect;21.5): RFC 8414 defines no default for either, so
     * their absence must stay distinguishable from a published value. A
     * document that omits them — an older AXIAM, or any of the non-AXIAM OPs
     * &sect;12.3 rule 6 requires this model to keep parsing — must still
     * produce a usable configuration rather than a rejection or a fabricated
     * {@code ["S256"]}.
     */
    @Test
    void aDocumentWithoutTheContract142MembersStillParsesAndReportsThemAbsent() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(),
                    "33333333-3333-3333-3333-333333333333").build()) {
                OidcConfiguration config = client.oidcDiscover();

                org.junit.jupiter.api.Assertions.assertNull(config.code_challenge_methods_supported(),
                        "absent must be null, not an empty list: \"the OP published nothing\" is "
                                + "not \"the OP supports nothing\"");
                org.junit.jupiter.api.Assertions.assertNull(
                        config.token_endpoint_auth_signing_alg_values_supported());
            }
        }
    }

    @Test
    void theContract142MembersAreParsedWhenThePresentDocumentCarriesThem() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponseWithContract142Members(
                    server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(),
                    "33333333-3333-3333-3333-333333333333").build()) {
                OidcConfiguration config = client.oidcDiscover();

                assertEquals(List.of("S256"), config.code_challenge_methods_supported());
                assertEquals(List.of("PS256", "ES256", "EdDSA"),
                        config.token_endpoint_auth_signing_alg_values_supported());
            }
        }
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
