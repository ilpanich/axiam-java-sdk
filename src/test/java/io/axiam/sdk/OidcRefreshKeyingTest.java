package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;9 (per-refresh-token single-flight): {@code oidcRefresh} callers presenting the same
 * refresh token and the same effective tenant form one burst and share one wire call; a caller with a
 * different token, or a different tenant, never joins it and never receives its outcome.
 *
 * <p>{@code SingleFlight} publishes a flight's outcome to the flight's own holder and only then vacates its key;
 * the window between the two is held open with its after-publish test hook. Inside it, a same-token caller
 * joins the published flight and a different-token caller gets its own wire call.
 */
class OidcRefreshKeyingTest {

    private static final String DEFAULT_TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    private static final UUID OTHER_TENANT = UUID.fromString("ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee");

    /** Records every token call (token, tenant) and holds calls for tokens starting with "hold-" on a gate. */
    private static final class Rig implements AutoCloseable {
        final MockWebServer server = new MockWebServer();
        final List<String> calls = new CopyOnWriteArrayList<>();
        final CountDownLatch gate = new CountDownLatch(1);
        final CountDownLatch firstArrived = new CountDownLatch(1);
        String base;

        Rig() throws Exception {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest r) throws InterruptedException {
                    if (!r.getPath().startsWith("/oauth2/token")) {
                        return OidcTestSupport.discoveryResponse(base);
                    }
                    String body = r.getBody().readUtf8();
                    String token = body.replaceAll(".*refresh_token=([^&]*).*", "$1");
                    String tenant = HttpUrl.get(r.getRequestUrl().toString()).queryParameter("tenant_id");
                    calls.add(token + "@" + tenant);
                    if (token.startsWith("fail-")) {
                        return OidcTestSupport.oauthError(400, "invalid_grant");
                    }
                    if (token.startsWith("hold-")) {
                        firstArrived.countDown();
                        gate.await(10, TimeUnit.SECONDS);
                    }
                    return OidcTestSupport.tokenResponse("access-for-" + token + "-at-" + tenant, "next-" + token, null);
                }
            });
            server.start();
            base = server.url("/").toString();
        }

        AxiamClient client() {
            return AxiamClient.builder(base, DEFAULT_TENANT).oidcClientId("my-app").build();
        }

        @Override
        public void close() throws Exception {
            gate.countDown();
            server.shutdown();
        }
    }

    /** A dedicated pool: the common pool is sized by core count and would starve on parked callers. */
    private static final java.util.concurrent.ExecutorService POOL =
            java.util.concurrent.Executors.newCachedThreadPool();

    private static <T> CompletableFuture<T> async(java.util.function.Supplier<T> s) {
        return CompletableFuture.supplyAsync(s, POOL);
    }

    private static String access(OidcTokenSet s) {
        return s.accessToken().expose();
    }

    /** Waits until {@code n} callers are inside the client's refresh slots, so a joiner has really joined. */
    private static void awaitUsers(AxiamClient c, int n) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (c.oidcRefreshUsers() < n) {
            assertTrue(System.nanoTime() < deadline, "callers never reached the slots");
            Thread.sleep(5);
        }
    }

    private static <T> T get(CompletableFuture<T> f) throws Exception {
        return f.get(10, TimeUnit.SECONDS);
    }

    @Test
    void aDifferentTokenDuringALiveFlightGetsItsOwnWireCallAndResult() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            CompletableFuture<OidcTokenSet> a1 = async(() -> c.oidcRefresh("hold-A"));
            assertTrue(rig.firstArrived.await(10, TimeUnit.SECONDS));
            CompletableFuture<OidcTokenSet> a2 = async(() -> c.oidcRefresh("hold-A"));
            awaitUsers(c, 2); // the second caller of A is inside A's flight before B is issued
            CompletableFuture<OidcTokenSet> b = async(() -> c.oidcRefresh("B"));

            // B must complete on its own while A is still held on the wire.
            assertEquals("access-for-B-at-" + DEFAULT_TENANT, access(get(b)));
            rig.gate.countDown();
            assertEquals("access-for-hold-A-at-" + DEFAULT_TENANT, access(get(a1)));
            assertEquals("access-for-hold-A-at-" + DEFAULT_TENANT, access(get(a2)), "a second caller of A shares A's call");
            assertEquals(2, rig.calls.size(), "A once, B once: " + rig.calls);
        }
    }

    /** Runs {@code inWindow} once, on A's thread, between A's publish and A's vacate. */
    private static void holdPublishWindow(AxiamClient c, ThrowingRunnable inWindow) {
        java.util.concurrent.atomic.AtomicBoolean fired = new java.util.concurrent.atomic.AtomicBoolean();
        c.oidcRefreshFlight().setTestHooks(() -> {
            if (fired.compareAndSet(false, true)) {
                assertEquals(1, c.oidcRefreshSlotCount(), "A's published flight still holds its key");
                try {
                    inWindow.run();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
        }, null);
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    @Test
    void aDifferentTokenInsideAsPublishBeforeVacateWindowGetsItsOwnCall() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            java.util.concurrent.atomic.AtomicReference<String> b = new java.util.concurrent.atomic.AtomicReference<>();
            holdPublishWindow(c, () -> b.set(access(get(async(() -> c.oidcRefresh("B"))))));
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, access(c.oidcRefresh("A")));
            assertEquals("access-for-B-at-" + DEFAULT_TENANT, b.get(), "B got its own result");
            assertEquals(List.of("A@" + DEFAULT_TENANT, "B@" + DEFAULT_TENANT), rig.calls, "B had its own wire call");
        }
    }

    @Test
    void theSameTokenInsideAsPublishBeforeVacateWindowJoinsAsFlight() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            java.util.concurrent.atomic.AtomicReference<String> sync = new java.util.concurrent.atomic.AtomicReference<>();
            java.util.concurrent.atomic.AtomicReference<String> viaAsync = new java.util.concurrent.atomic.AtomicReference<>();
            holdPublishWindow(c, () -> {
                sync.set(access(get(async(() -> c.oidcRefresh("A")))));
                viaAsync.set(access(get(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("A")))));
            });
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, access(c.oidcRefresh("A")));
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, sync.get());
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, viaAsync.get());
            assertEquals(1, rig.calls.size(), "callers in the window join the published flight: " + rig.calls);
        }
    }

    @Test
    void theSameTokenAfterFullVacateIsAFreshWireCall() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, access(c.oidcRefresh("A")));
            assertEquals("access-for-B-at-" + DEFAULT_TENANT, access(c.oidcRefresh("B")));
            assertEquals(2, rig.calls.size());
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, access(c.oidcRefresh("A")));
            assertEquals("access-for-A-at-" + DEFAULT_TENANT, access(get(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("A")))));
            assertEquals(4, rig.calls.size());
        }
    }

    @Test
    void sameTokenAndEffectiveTenantShareOneCallWhetherOmittedExplicitOrUpperCase() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            UUID dflt = UUID.fromString(DEFAULT_TENANT);
            // The UUID a caller passes is a UUID object; the upper-case spelling arrives as the same UUID.
            UUID upper = UUID.fromString(DEFAULT_TENANT.toUpperCase());
            CompletableFuture<OidcTokenSet> omitted = async(() -> c.oidcRefresh("hold-T"));
            assertTrue(rig.firstArrived.await(10, TimeUnit.SECONDS));
            CompletableFuture<OidcTokenSet> explicit = async(
                    () -> c.oidcRefresh(io.axiam.sdk.Sensitive.of("hold-T"), null, dflt, null));
            CompletableFuture<OidcTokenSet> viaUpper = async(
                    () -> c.oidcRefresh(io.axiam.sdk.Sensitive.of("hold-T"), null, upper, null));
            CompletableFuture<OidcTokenSet> otherScope = async(
                    () -> c.oidcRefresh(io.axiam.sdk.Sensitive.of("hold-T"), "other:scope", null, null));
            awaitUsers(c, 4);
            rig.gate.countDown();
            String expected = "access-for-hold-T-at-" + DEFAULT_TENANT;
            assertEquals(expected, access(get(omitted)));
            assertEquals(expected, access(get(explicit)));
            assertEquals(expected, access(get(viaUpper)));
            assertEquals(expected, access(get(otherScope)), "a different scope joins the one flight");
            assertEquals(1, rig.calls.size(), "one wire call for one token + one effective tenant: " + rig.calls);
        }
    }

    @Test
    void sameTokenInADifferentTenantIsASeparateFlightWithItsOwnTenantAndResult() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            CompletableFuture<OidcTokenSet> first = async(() -> c.oidcRefresh("hold-T"));
            assertTrue(rig.firstArrived.await(10, TimeUnit.SECONDS));
            CompletableFuture<OidcTokenSet> second = async(
                    () -> c.oidcRefresh(io.axiam.sdk.Sensitive.of("hold-T"), null, OTHER_TENANT, null));
            awaitCalls(rig, 2); // the second tenant's call is on the wire while the first is still held
            assertFalse(first.isDone(), "the first tenant's call is still held");
            rig.gate.countDown();
            assertEquals("access-for-hold-T-at-" + DEFAULT_TENANT, access(get(first)));
            assertEquals("access-for-hold-T-at-" + OTHER_TENANT, access(get(second)));
            assertEquals(2, rig.calls.size());
            assertTrue(rig.calls.contains("hold-T@" + DEFAULT_TENANT), rig.calls.toString());
            assertTrue(rig.calls.contains("hold-T@" + OTHER_TENANT), rig.calls.toString());
        }
    }

    @Test
    void anUnresolvableTenantFailsImmediatelyWithNoSlotAndNoRequest() throws Exception {
        try (Rig rig = new Rig();
             AxiamClient c = AxiamClient.builder(rig.base, "acme-slug").oidcClientId("my-app").build()) {
            AuthError e = assertThrows(AuthError.class, () -> c.oidcRefresh("raw-secret-unresolvable"));
            assertNoRawToken(e, "raw-secret-unresolvable");
            CompletableFuture<OidcTokenSet> async = c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("raw-secret-unresolvable"));
            java.util.concurrent.ExecutionException ae =
                    assertThrows(java.util.concurrent.ExecutionException.class, () -> get(async));
            assertTrue(ae.getCause() instanceof AuthError, "async twin fails the same way: " + ae.getCause());
            assertNoRawToken(ae.getCause(), "raw-secret-unresolvable");
            assertEquals(0, rig.server.getRequestCount(), "no discovery fetch and no token call");
            assertTrue(c.oidcRefreshSlotCount() == 0, "no slot left behind");
        }
    }

    @Test
    void slotsAreRemovedOnceVacatedAndHoldNoRawToken() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            c.oidcRefresh("raw-secret-token-1");
            c.oidcRefresh("raw-secret-token-2");
            assertEquals(0, c.oidcRefreshSlotCount());
            CompletableFuture<OidcTokenSet> held = async(() -> c.oidcRefresh("hold-S"));
            assertTrue(rig.firstArrived.await(10, TimeUnit.SECONDS));
            assertEquals(1, c.oidcRefreshSlotCount());
            for (String key : c.oidcRefreshSlotKeys()) {
                assertFalse(key.contains("hold-S"), "the registry must never key on the raw token");
                assertEquals(64, key.length(), "a SHA-256 hex digest");
            }
            rig.gate.countDown();
            get(held);
            assertEquals(0, c.oidcRefreshSlotCount());
        }
    }

    @Test
    void twentyConcurrentDistinctTokenRefreshesAllCompleteAndRunConcurrently() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            java.util.List<CompletableFuture<OidcTokenSet>> futures = new java.util.ArrayList<>();
            java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(20);
            try {
                for (int i = 0; i < 20; i++) {
                    String token = i == 0 ? "hold-0" : "tok-" + i;
                    futures.add(CompletableFuture.supplyAsync(() -> c.oidcRefresh(token), pool));
                }
                for (int i = 1; i < 20; i++) {
                    assertEquals("access-for-tok-" + i + "-at-" + DEFAULT_TENANT, access(get(futures.get(i))));
                }
                assertFalse(futures.get(0).isDone(), "token 0 is still held on the wire while the other 19 finished");
                rig.gate.countDown();
                assertEquals("access-for-hold-0-at-" + DEFAULT_TENANT, access(get(futures.get(0))));
                assertEquals(20, rig.calls.size());
            } finally {
                pool.shutdownNow();
            }
        }
    }

    /** Waits until {@code n} token calls have reached the transport. */
    private static void awaitCalls(Rig rig, int n) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (rig.calls.size() < n) {
            assertTrue(System.nanoTime() < deadline, "only " + rig.calls.size() + " of " + n + " calls reached the wire");
            Thread.sleep(5);
        }
    }

    /** No message, toString or cause of {@code t} may carry the raw refresh token. */
    private static void assertNoRawToken(Throwable t, String rawToken) {
        for (Throwable x = t; x != null; x = x.getCause()) {
            assertFalse(String.valueOf(x.getMessage()).contains(rawToken), "message leaks the token: " + x.getClass());
            assertFalse(x.toString().contains(rawToken), "toString leaks the token: " + x.getClass());
        }
    }

    /** More concurrent callers than the common pool has threads, so parked callers would starve it. */
    private static int beyondCommonPool() {
        return Math.max(20, 2 * java.util.concurrent.ForkJoinPool.getCommonPoolParallelism());
    }

    @Test
    void asyncSameTokenCallersBeyondTheCommonPoolShareOneWireCall() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            int n = beyondCommonPool();
            java.util.List<CompletableFuture<OidcTokenSet>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < n; i++) {
                futures.add(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("hold-A")));
            }
            assertTrue(rig.firstArrived.await(10, TimeUnit.SECONDS));
            // Every caller joins A's one flight while it is held on the wire (bounded wait, then judge the wire).
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (c.oidcRefreshUsers() < n && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            int joined = c.oidcRefreshUsers();
            rig.gate.countDown();
            for (CompletableFuture<OidcTokenSet> f : futures) {
                assertEquals("access-for-hold-A-at-" + DEFAULT_TENANT, access(get(f)));
            }
            assertEquals(1, rig.calls.size(), "one wire call for one single-use token, got " + rig.calls.size());
            assertEquals(n, joined, "every async caller joined the held flight");
        }
    }

    @Test
    void asyncDistinctTokensBeyondTheCommonPoolAreAllOnTheWireConcurrently() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            int n = beyondCommonPool();
            java.util.List<CompletableFuture<OidcTokenSet>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < n; i++) {
                futures.add(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("hold-" + i)));
            }
            awaitCalls(rig, n); // all n held on the transport at once
            rig.gate.countDown();
            for (int i = 0; i < n; i++) {
                assertEquals("access-for-hold-" + i + "-at-" + DEFAULT_TENANT, access(get(futures.get(i))));
            }
            assertEquals(n, rig.calls.size());
        }
    }

    @Test
    void asyncUnrelatedTokenStartsWhileASameTokenFlightIsHeld() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            java.util.List<CompletableFuture<OidcTokenSet>> held = new java.util.ArrayList<>();
            for (int i = 0; i < beyondCommonPool(); i++) {
                held.add(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("hold-A")));
            }
            assertTrue(rig.firstArrived.await(10, TimeUnit.SECONDS));
            CompletableFuture<OidcTokenSet> unrelated = c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("B"));
            assertEquals("access-for-B-at-" + DEFAULT_TENANT, access(get(unrelated)), "B must not starve behind A");
            assertTrue(held.stream().noneMatch(CompletableFuture::isDone), "A is still held");
            rig.gate.countDown();
            for (CompletableFuture<OidcTokenSet> f : held) {
                assertEquals("access-for-hold-A-at-" + DEFAULT_TENANT, access(get(f)));
            }
            assertEquals(2, rig.calls.size(), rig.calls.toString());
        }
    }

    @Test
    void aFailedRefreshNeverCarriesTheRawTokenToAnyCaller() throws Exception {
        try (Rig rig = new Rig(); AxiamClient c = rig.client()) {
            String raw = "fail-raw-secret-refresh-token";
            RuntimeException sync = assertThrows(RuntimeException.class, () -> c.oidcRefresh(raw));
            assertNoRawToken(sync, raw);
            java.util.concurrent.ExecutionException async = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> get(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of(raw))));
            assertNoRawToken(async, raw);
            assertEquals(2, rig.calls.size(), "after a full vacate each attempt is its own call");
        }
    }

    @Test
    void oidcRefreshAsyncAfterCloseFailsAsAClosedClient() throws Exception {
        try (Rig rig = new Rig()) {
            AxiamClient c = rig.client();
            c.close();
            java.util.concurrent.ExecutionException e = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> get(c.oidcRefreshAsync(io.axiam.sdk.Sensitive.of("raw-secret-after-close"))));
            assertTrue(e.getCause() instanceof io.axiam.sdk.errors.NetworkError, String.valueOf(e.getCause()));
            assertNoRawToken(e, "raw-secret-after-close");
            assertEquals(0, c.oidcRefreshSlotCount());
            assertEquals(0, rig.server.getRequestCount());
        }
    }
}
