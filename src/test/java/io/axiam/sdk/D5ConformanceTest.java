package io.axiam.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.AxiamClient.AccessResult;
import io.axiam.sdk.internal.DecisionMemo;
import io.axiam.sdk.internal.TelemetryDispatcher;
import io.axiam.sdk.telemetry.TelemetryEvent;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * D5 conformance — CONTRACT.md §16, §17, §18, §19.
 *
 * <p>These assert through the <strong>public {@code checkAccess} surface</strong>,
 * counting requests that reach the mock server, rather than against the helpers
 * in isolation. That distinction is normative as of contract 1.8.1: the
 * TypeScript SDK shipped a retry helper that was exported, unit-tested and green
 * while no production path called it, so that SDK performed no read-only retries
 * at all and every test passed. Counting on the wire is the only assertion that
 * catches it.
 *
 * <p>Java's {@code Retry} was already §16-conformant — it is the implementation
 * whose parameters the contract adopted — so the §16 cases here are a
 * regression lock on the wiring rather than a change in behaviour.
 */
class D5ConformanceTest {

    private MockWebServer server;

    private static final String ALLOW_BODY = "{\"allowed\":true,\"reason_code\":\"allowed\"}";

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    private AxiamClient.Builder builder() {
        return AxiamClient.builder(server.url("/").toString(), "acme").orgSlug("acme");
    }

    private void enqueue(int... statuses) {
        for (int status : statuses) {
            if (status == 200) {
                server.enqueue(new MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json").setBody(ALLOW_BODY));
            } else {
                server.enqueue(new MockResponse().setResponseCode(status));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §16 — the policy, asserted through the public surface
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("§16: a persistent 503 makes exactly three attempts")
    void persistent503MakesThreeAttempts() {
        enqueue(503, 503, 503);
        try (AxiamClient client = builder().build()) {
            assertThrows(NetworkError.class, () -> client.checkAccess("read", "r-1"));
            assertEquals(3, server.getRequestCount(),
                    "the §16 cap is 3 attempts, counted on the wire");
        }
    }

    @Test
    @DisplayName("§16: a transient failure is retried and the success returned")
    void transientFailureIsRetried() {
        enqueue(503, 200);
        try (AxiamClient client = builder().build()) {
            AccessResult result = client.checkAccess("read", "r-1");
            assertTrue(result.allowed());
            assertEquals(2, server.getRequestCount());
        }
    }

    @Test
    @DisplayName("§16: a decisive 403 is not retried — it is an answer, not a transport failure")
    void decisive403IsNotRetried() {
        enqueue(403);
        try (AxiamClient client = builder().build()) {
            assertThrows(AuthzError.class, () -> client.checkAccess("read", "r-1"));
            assertEquals(1, server.getRequestCount());
        }
    }

    @Test
    @DisplayName("§16.6: retryDisabled() makes exactly one attempt")
    void retryDisabledMakesOneAttempt() {
        enqueue(503);
        try (AxiamClient client = builder().retryDisabled().build()) {
            assertThrows(NetworkError.class, () -> client.checkAccess("read", "r-1"));
            assertEquals(1, server.getRequestCount());
        }
    }

    // -----------------------------------------------------------------------
    // §17 — decision memo
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("§17: the memo is OFF by default")
    void memoIsOffByDefault() {
        // The most important assertion here. §11.2 rule 6's ban on decision
        // caching is still the default; a build that quietly enabled this would
        // change authorization staleness for every existing caller without them
        // asking for it.
        enqueue(200, 200);
        try (AxiamClient client = builder().build()) {
            client.checkAccess("read", "r-1");
            client.checkAccess("read", "r-1");
            assertEquals(2, server.getRequestCount(), "the memo must be off by default");
        }
    }

    @Test
    @DisplayName("§17: a repeat inside the TTL is served without a second call")
    void memoServesRepeatInsideTtl() {
        enqueue(200);
        try (AxiamClient client = builder().decisionMemoTtl(Duration.ofSeconds(5)).build()) {
            AccessResult first = client.checkAccess("read", "r-1");
            AccessResult second = client.checkAccess("read", "r-1");
            assertEquals(1, server.getRequestCount());
            // §17.1 rule 5: the reason code survives the memo. Returning
            // `allowed` while dropping the code would make the field
            // intermittently absent — worse than never having had it.
            assertEquals(first.reasonCode(), second.reasonCode());
            assertNotNull(second.reasonCode());
        }
    }

    @Test
    @DisplayName("§17.1 rule 4: denies are memoized exactly like allows")
    void memoCachesDeniesLikeAllows() {
        // Asymmetric caching makes the two outcomes take measurably different
        // times, leaking which one occurred. Assert the call count, not the
        // outcome.
        server.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}"));
        try (AxiamClient client = builder().decisionMemoTtl(Duration.ofSeconds(5)).build()) {
            client.checkAccess("read", "r-1");
            AccessResult second = client.checkAccess("read", "r-1");
            assertEquals(1, server.getRequestCount());
            assertFalse(second.allowed());
            assertEquals("denied_by_rule", second.reasonCode());
        }
    }

    @Test
    @DisplayName("§17.1 rule 7: a failure is never memoized")
    void memoNeverCachesAFailure() {
        // Caching a transport error as a deny would turn a blip into a
        // TTL-long outage.
        enqueue(503, 503);
        try (AxiamClient client = builder()
                .decisionMemoTtl(Duration.ofSeconds(5)).retryDisabled().build()) {
            assertThrows(NetworkError.class, () -> client.checkAccess("read", "r-1"));
            assertThrows(NetworkError.class, () -> client.checkAccess("read", "r-1"));
            assertEquals(2, server.getRequestCount());
        }
    }

    @Test
    @DisplayName("§17.1 rule 3: every key component is distinguished")
    void memoKeyDistinguishesEveryComponent() {
        Set<String> keys = new HashSet<>(List.of(
                DecisionMemo.key(null, "r1", "read", null),
                DecisionMemo.key(null, "r1", "write", null),
                DecisionMemo.key(null, "r2", "read", null),
                DecisionMemo.key(null, "r1", "read", "col-a"),
                DecisionMemo.key("u1", "r1", "read", null)));
        assertEquals(5, keys.size());
        // An absent scope must never collide with a present empty one.
        assertFalse(DecisionMemo.key(null, "r1", "read", null)
                .equals(DecisionMemo.key(null, "r1", "read", "")));
    }

    @Test
    @DisplayName("§17.1 rule 2: a TTL above the ceiling is clamped, not rejected")
    void memoClampsTtl() {
        assertEquals(DecisionMemo.MAX_TTL.toMillis(),
                new DecisionMemo<AccessResult>(Duration.ofHours(1)).effectiveTtlMillis());
        assertEquals(2000L, new DecisionMemo<AccessResult>(Duration.ofSeconds(2)).effectiveTtlMillis());
        assertFalse(new DecisionMemo<AccessResult>(null).enabled());
        assertFalse(new DecisionMemo<AccessResult>(Duration.ofSeconds(-1)).enabled(),
                "a negative TTL disables rather than wrapping");
    }

    @Test
    @DisplayName("§17: an entry expires at exactly the TTL")
    void memoExpiresAtTtl() {
        AtomicLong now = new AtomicLong(1_000L);
        DecisionMemo<AccessResult> memo = new DecisionMemo<>(Duration.ofSeconds(5), now::get);
        AccessResult decision = new AccessResult(true, null, "allowed");
        memo.put("k", decision);

        now.set(1_000L + 4_999L);
        assertNotNull(memo.get("k"), "still live just before the TTL");
        now.set(1_000L + 5_000L);
        assertNull(memo.get("k"), "expired at exactly the TTL");
    }

    @Test
    @DisplayName("§17.1 rule 8: the memo evicts rather than growing without bound")
    void memoEvictsBeyondTheCap() {
        // An unbounded per-client cache keyed by (subject, resource, action,
        // scope) is a memory leak in any service that checks many resources.
        DecisionMemo<AccessResult> memo = new DecisionMemo<>(Duration.ofSeconds(5));
        AccessResult decision = new AccessResult(true, null, "allowed");
        for (int i = 0; i < 1100; i++) {
            memo.put(DecisionMemo.key(null, "r" + i, "read", null), decision);
        }
        assertEquals(1024, memo.size());
    }

    @Test
    @DisplayName("§17.1 rule 9: the memo is cleared on a credential change")
    void memoClearedOnCredentialChange() {
        enqueue(200);
        enqueue(200);
        try (AxiamClient client = builder().decisionMemoTtl(Duration.ofSeconds(5)).build()) {
            client.checkAccess("read", "r-1");
            client.checkAccess("read", "r-1");
            assertEquals(1, server.getRequestCount(), "the second check came from the memo");

            // logout() rejects with AuthError when there is no session to end,
            // but the memo clear runs FIRST — deliberately. The trigger is the
            // caller's intent to change credentials, not the server's answer:
            // a logout that failed still means this caller is done with the
            // principal whose decisions are cached, and entries are keyed by
            // subject rather than session, so keeping them would let a
            // re-authentication as a different principal inherit them.
            assertThrows(AuthError.class, client::logout);

            client.checkAccess("read", "r-1");
            assertEquals(2, server.getRequestCount(),
                    "the memo did not survive the credential change");
        }
    }

    // -----------------------------------------------------------------------
    // §18 — deterministic shutdown
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("§18: close() is idempotent")
    void closeIsIdempotent() {
        AxiamClient client = builder().build();
        client.close();
        client.close();
    }

    @Test
    @DisplayName("§18.1 rule 5: close() issues no network request — it does not log out")
    void closeIssuesNoNetworkRequest() {
        // The server-side session deliberately outlives the client object —
        // that is what lets a process restart and resume — so a close() that
        // logged out would silently end every user's session on each deploy.
        // Asserted against the wire, because a logout wired into close()
        // succeeds silently and would pass any return-value assertion.
        AxiamClient client = builder().build();
        client.close();
        assertEquals(0, server.getRequestCount(), "close() must not log out");
    }

    @Test
    @DisplayName("§18.1 rule 4: use-after-close throws rather than reconnecting")
    void useAfterCloseThrows() {
        enqueue(200);
        AxiamClient client = builder().build();
        client.checkAccess("read", "r-1");
        int before = server.getRequestCount();

        client.close();

        assertThrows(NetworkError.class, () -> client.checkAccess("read", "r-1"));
        assertThrows(NetworkError.class, () -> client.login("u@example.com", "pw"));
        assertThrows(NetworkError.class, client::logout);
        assertEquals(before, server.getRequestCount(),
                "no request may reach the server after close()");
    }

    // -----------------------------------------------------------------------
    // §19 — telemetry
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("§19.2 rule 5: one request pair per ATTEMPT, with a retry between")
    void emitsRequestPairPerAttempt() {
        enqueue(503, 200);
        List<TelemetryEvent> events = new ArrayList<>();
        try (AxiamClient client = builder().telemetryHook(events::add).build()) {
            client.checkAccess("read", "r-1");
        }

        List<String> kinds = new ArrayList<>();
        List<Integer> attempts = new ArrayList<>();
        for (TelemetryEvent e : events) {
            if (e instanceof TelemetryEvent.RequestStart start) {
                kinds.add("start");
                attempts.add(start.attempt());
                // The path TEMPLATE, never a substituted URL — a metric label
                // carrying a UUID is a cardinality bomb.
                assertEquals("/api/v1/authz/check", start.pathTemplate());
            } else if (e instanceof TelemetryEvent.RequestEnd) {
                kinds.add("end");
            } else if (e instanceof TelemetryEvent.Retry) {
                kinds.add("retry");
            }
        }
        assertEquals(List.of("start", "end", "retry", "start", "end"), kinds);
        // Emitting both pairs as attempt 1 would make a retried call
        // indistinguishable from a single slow one.
        assertEquals(List.of(1, 2), attempts);
    }

    @Test
    @DisplayName("§19.2 rule 2: a throwing hook cannot fail the operation")
    void throwingHookCannotFailTheOperation() {
        enqueue(200);
        try (AxiamClient client = builder().telemetryHook(e -> {
            throw new IllegalStateException("hook exploded");
        }).build()) {
            assertTrue(client.checkAccess("read", "r-1").allowed());
        }
    }

    @Test
    @DisplayName("§19.2 rule 3: no event payload carries a token")
    void noEventCarriesAToken() {
        // This surface exists to be shipped to a metrics backend, which is the
        // last place a bearer token should land.
        enqueue(503, 503, 503);
        List<TelemetryEvent> events = new ArrayList<>();
        try (AxiamClient client = builder().telemetryHook(events::add).build()) {
            assertThrows(NetworkError.class, () -> client.checkAccess("read", "r-1"));
        }
        String rendered = events.toString().toLowerCase(java.util.Locale.ROOT);
        assertFalse(rendered.contains("eyj"), "no JWT-shaped string in telemetry");
        assertFalse(rendered.contains("authorization"), "no auth header content in telemetry");
    }

    @Test
    @DisplayName("§19: an uninstalled dispatcher costs nothing and cannot throw")
    void uninstalledDispatcherIsInert() {
        TelemetryDispatcher dispatcher = new TelemetryDispatcher(null);
        assertFalse(dispatcher.installed());
        dispatcher.emit(new TelemetryEvent.Refresh(
                TelemetryEvent.RefreshRole.LEADER, Duration.ofMillis(1)));
        // A span from an uninstalled dispatcher must also be inert.
        dispatcher.startRequest("op", "POST", "/api/v1/authz/check", 1)
                .end(200, TelemetryEvent.Outcome.SUCCESS);
    }
}
