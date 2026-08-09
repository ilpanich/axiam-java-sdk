package io.axiam.sdk.examples.telemetryhook;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.AxiamClient.AccessResult;
import io.axiam.sdk.telemetry.TelemetryEvent;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Demonstrates telemetry hooks (CONTRACT.md &sect;19): wiring metrics to an
 * AXIAM client <strong>without this library depending on any metrics API</strong>.
 *
 * <p>The sink below aggregates in-process so the example runs with no extra
 * dependencies; the comment block at the bottom shows the exact mapping onto
 * Micrometer, which is a drop-in replacement for the body. Imports ONLY public
 * SDK entry points.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT_ID=... java TelemetryHookExample.java}
 */
public final class TelemetryHookExample {

    /** (operation, outcome) to [count, totalMillis]. */
    private static final Map<String, long[]> REQUESTS = new ConcurrentHashMap<>();
    /** operation to retry count. */
    private static final Map<String, AtomicLong> RETRIES = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenantId = getenv("AXIAM_TENANT_ID", "acme");
        String orgSlug = getenv("AXIAM_ORG_SLUG", "acme");

        // §18: try-with-resources. close() releases local resources and does
        // NOT log out — the server-side session outlives this object.
        try (AxiamClient client = AxiamClient.builder(baseUrl, tenantId)
                .orgSlug(orgSlug)
                .telemetryHook(TelemetryHookExample::record)
                .build()) {

            // This will usually fail against a host that is not running, which
            // is the point: a failing call still emits a RequestEnd carrying
            // the failure, and the §16 retries are visible as Retry events.
            try {
                AccessResult decision = client.checkAccess(
                        "read", "00000000-0000-0000-0000-000000000000");
                System.out.printf("allowed=%s (%s)%n",
                        decision.allowed(),
                        decision.reasonCode() == null ? "no reason code" : decision.reasonCode());
            } catch (RuntimeException e) {
                System.out.println("check failed as expected in this example: " + e.getMessage());
            }

            report();
        }
    }

    /** A §19 sink. Aggregates in memory; see the Micrometer mapping below. */
    private static void record(TelemetryEvent event) {
        if (event instanceof TelemetryEvent.RequestEnd end) {
            // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so
            // counting these gives the real number of wire calls — including
            // the ones a retry made on your behalf.
            String key = end.operation() + "/" + end.outcome();
            REQUESTS.compute(key, (k, v) -> {
                long[] stat = (v == null) ? new long[] {0, 0} : v;
                stat[0]++;
                stat[1] += end.duration().toMillis();
                return stat;
            });
        } else if (event instanceof TelemetryEvent.Retry retry) {
            // §16.5 — the reason this event exists. A retried-then-succeeded
            // operation is otherwise invisible: the caller sees a slow success
            // and no signal that the server is failing. Alert on this rate, not
            // on the error rate, or a degrading server looks healthy right up
            // until the retries stop being enough.
            RETRIES.computeIfAbsent(retry.operation(), k -> new AtomicLong()).incrementAndGet();
        }
    }

    private static void report() {
        System.out.println("--- requests (per attempt) ---");
        REQUESTS.forEach((key, stat) ->
                System.out.printf("  %-24s count=%d mean=%dms%n", key, stat[0], stat[1] / stat[0]));
        System.out.println("--- retries ---");
        if (RETRIES.isEmpty()) {
            System.out.println("  (none)");
        }
        RETRIES.forEach((op, n) -> System.out.printf("  %-24s %d%n", op, n.get()));
    }

    private static String getenv(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private TelemetryHookExample() {
    }
}

// ---------------------------------------------------------------------------
// The same sink, against Micrometer
// ---------------------------------------------------------------------------
//
// This library deliberately declares no micrometer/OpenTelemetry dependency —
// §19's whole point is that you choose your metrics stack. With Micrometer on
// YOUR classpath, record(...) becomes:
//
//     MeterRegistry registry = ...;
//
//     static void record(TelemetryEvent event) {
//         if (event instanceof TelemetryEvent.RequestEnd end) {
//             Timer.builder("axiam.client.request")
//                 .tag("axiam.operation", end.operation())
//                 // The path TEMPLATE, never a substituted URL: a metric label
//                 // carrying a UUID is a cardinality bomb.
//                 .tag("http.route", end.pathTemplate())
//                 .tag("http.response.status_code", String.valueOf(end.status()))
//                 .tag("axiam.outcome", end.outcome().name())
//                 .register(registry)
//                 .record(end.duration());
//         } else if (event instanceof TelemetryEvent.Retry retry) {
//             Counter.builder("axiam.client.retries")
//                 .tag("axiam.operation", retry.operation())
//                 .tag("axiam.attempt", String.valueOf(retry.attempt()))
//                 .register(registry)
//                 .increment();
//         }
//     }
//
// Two rules to keep in mind when writing any adapter:
//
//   * DO NOT BLOCK. Hooks run on the calling thread (§19.2 rule 4). Every
//     mature metrics library already buffers; if yours does not, buffer on your
//     side rather than doing I/O here.
//   * DO NOT ENRICH EVENTS FROM ELSEWHERE. TelemetryEvent is a sealed hierarchy
//     precisely so this surface cannot leak a token into a metrics backend
//     (§19.2 rule 3). Adding, say, the current Authorization header would
//     defeat that on your side of the boundary.
//
// A hook that throws is swallowed by the SDK (§19.2 rule 2) — an authorization
// check is never failed by telemetry — but that is a backstop, not a licence to
// let a sink throw.
