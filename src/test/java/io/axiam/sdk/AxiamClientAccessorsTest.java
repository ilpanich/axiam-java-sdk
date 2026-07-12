package io.axiam.sdk;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.Cache;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@code Builder}'s remaining fluent setters ({@code orgId}, {@code customCa}, the three
 * timeouts) and {@code AxiamClient}'s package-internal accessors (the gRPC construction seam,
 * 20-08) plus {@code close()} — none of these have any conditional logic of their own, so a
 * single build-then-assert per member is sufficient (D-09 for {@code close()}).
 */
class AxiamClientAccessorsTest {

    @Test
    void builderSettersAreAllAppliedToTheBuiltClient() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgId(java.util.UUID.fromString("44444444-4444-4444-4444-444444444444"))
                    .connectTimeout(Duration.ofSeconds(5))
                    .readTimeout(Duration.ofSeconds(15))
                    .writeTimeout(Duration.ofSeconds(20))
                    .build()) {
                assertEquals(5, client.okHttpClient().connectTimeoutMillis() / 1000);
                assertEquals(15, client.okHttpClient().readTimeoutMillis() / 1000);
                assertEquals(20, client.okHttpClient().writeTimeoutMillis() / 1000);
                assertNull(client.customCa(), "customCa() must be null when Builder#customCa was never called");
            }
        }
    }

    @Test
    void orgIdAndOrgSlugAreMutuallyExclusiveLastCallWins() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            // orgSlug(...) then orgId(...) — orgId must win (clears orgSlug).
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .orgId(java.util.UUID.fromString("44444444-4444-4444-4444-444444444444"))
                    .build()) {
                assertNull(client.session().configuredOrgSlug());
                assertNotNull(client.session().configuredOrgId());
            }
        }
    }

    @Test
    void customCaBuilderSetterIsReflectedByTheAccessor() throws Exception {
        byte[] pem = io.axiam.sdk.testutil.TestCerts.selfSignedCertPem(tempDir, "axiam-accessor-test-ca");
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .customCa(pem)
                    .build()) {
                assertEquals(new String(pem), new String(client.customCa()));
            }
        }
    }

    @Test
    void packageInternalAccessorsExposeTheSharedGuardAndSession() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                assertNotNull(client.refreshGuard(), "refreshGuard() must expose the ONE shared RefreshGuard (D-07/D-08)");
                assertEquals("acme", client.tenantId());
                assertEquals(server.url("/").toString().replaceAll("/$", ""), client.baseUrl());
                assertNotNull(client.session(), "session() must expose the ONE shared SessionState (gRPC seam, 20-08)");
                assertEquals("acme", client.session().tenantId());

                RefreshGuard guard = client.refreshGuard();
                SessionState session = client.session();
                assertNotNull(guard);
                assertNotNull(session);
            }
        }
    }

    @Test
    void closeShutsDownTheHttpClientAndClosesAnAttachedCacheWithoutThrowing() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            OkHttpClient overrideWithCache = new OkHttpClient.Builder()
                    .cache(new Cache(tempDir.resolve("http-cache").toFile(), 1024 * 1024))
                    .build();

            AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .httpClient(overrideWithCache)
                    .build();

            // D-09: close() must tear down the dispatcher, evict the connection pool, and close
            // an attached OkHttp Cache (best-effort; a failed cache close is swallowed) without
            // throwing.
            client.close();

            assertEquals(0, client.okHttpClient().connectionPool().connectionCount());
        }
    }

    @TempDir
    Path tempDir;
}
