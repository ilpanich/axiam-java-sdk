package io.axiam.sdk.testutil;

import okhttp3.Headers;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * A {@link MockWebServer} that routes on method and exact path, records what
 * reached each route, and answers each route from a script (the last entry
 * repeats). Unmounted routes answer {@code 501} and are recorded as unmatched.
 *
 * <p>Used by the contract 1.53&ndash;1.58 suites, which assert on the request a
 * specific operation sent rather than on queue order.
 */
public final class RouteServer implements AutoCloseable {

    /** What a route saw. */
    public record Seen(String method, String path, Map<String, String> query, Headers headers,
                       String body, long atNanos) {

        /** The decoded form body, for a form-encoded request. */
        public Map<String, String> form() {
            Map<String, String> out = new LinkedHashMap<>();
            if (body.isEmpty()) {
                return out;
            }
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                String k = eq < 0 ? pair : pair.substring(0, eq);
                String v = eq < 0 ? "" : pair.substring(eq + 1);
                out.put(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
            }
            return out;
        }
    }

    /** One mounted route. */
    public static final class Route {
        private final Function<Integer, MockResponse> responder;
        private final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());

        Route(Function<Integer, MockResponse> responder) {
            this.responder = responder;
        }

        /** Every request that reached this route, in order. */
        public List<Seen> seen() {
            synchronized (seen) {
                return List.copyOf(seen);
            }
        }

        /** How many requests reached this route. */
        public int calls() {
            return seen.size();
        }

        /** The most recent request. */
        public Seen last() {
            List<Seen> all = seen();
            if (all.isEmpty()) {
                throw new AssertionError("route was never called");
            }
            return all.get(all.size() - 1);
        }
    }

    private final MockWebServer server = new MockWebServer();
    private final Map<String, Route> routes = new ConcurrentHashMap<>();
    private final List<String> unmatched = Collections.synchronizedList(new ArrayList<>());

    /** The access token the built-in login route minted last, or {@code null}. */
    private volatile String lastAccessToken;

    /** Starts the server. */
    public RouteServer() throws IOException {
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String raw = request.getPath() == null ? "" : request.getPath();
                String path = raw.contains("?") ? raw.substring(0, raw.indexOf('?')) : raw;
                Route route = routes.get(request.getMethod() + " " + path);
                if (route == null) {
                    unmatched.add(request.getMethod() + " " + path);
                    return new MockResponse().setResponseCode(501);
                }
                Map<String, String> query = new LinkedHashMap<>();
                if (raw.contains("?")) {
                    for (String pair : raw.substring(raw.indexOf('?') + 1).split("&")) {
                        int eq = pair.indexOf('=');
                        if (eq > 0) {
                            query.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                        }
                    }
                }
                int index = route.seen.size();
                route.seen.add(new Seen(request.getMethod(), path, query, request.getHeaders(),
                        request.getBody().readUtf8(), System.nanoTime()));
                return route.responder.apply(index);
            }
        });
        server.start();
    }

    /** The base URL, without a trailing slash. */
    public String base() {
        String url = server.url("/").toString();
        return url.substring(0, url.length() - 1);
    }

    /** The host the server listens on, as it appears in {@link #base()}. */
    public String host() {
        return server.url("/").host();
    }

    /** The port the server listens on. */
    public int port() {
        return server.getPort();
    }

    /**
     * Mounts a route answering from {@code script}, the last entry repeating.
     *
     * @param method the HTTP method
     * @param path   the exact path
     * @param script the responses, in order
     * @return the route
     */
    public Route on(String method, String path, MockResponse... script) {
        List<MockResponse> list = List.of(script);
        return onEach(method, path, i -> list.get(Math.min(i, list.size() - 1)));
    }

    /**
     * Mounts a route whose answer is computed from the 0-based request index.
     *
     * @param method    the HTTP method
     * @param path      the exact path
     * @param responder the answer for each request index
     * @return the route
     */
    public Route onEach(String method, String path, Function<Integer, MockResponse> responder) {
        Route route = new Route(responder);
        routes.put(method + " " + path, route);
        return route;
    }

    /** Requests that reached no route. */
    public List<String> unmatched() {
        synchronized (unmatched) {
            return List.copyOf(unmatched);
        }
    }

    /** Total requests that reached the server. */
    public int requestCount() {
        return server.getRequestCount();
    }

    /**
     * Mounts {@code POST /api/v1/auth/login}, answering with session cookies
     * carrying a fresh run-time access token for {@code tenantId}.
     *
     * @param tenantId the tenant claim
     * @return the route
     */
    public Route mountLogin(UUID tenantId) {
        return onEach("POST", "/api/v1/auth/login", i -> {
            String token = unsignedAccessToken(tenantId);
            lastAccessToken = token;
            return new MockResponse().setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + token + "; Path=/")
                    .addHeader("Set-Cookie", "axiam_refresh=r" + UUID.randomUUID() + "; Path=/")
                    .addHeader("X-CSRF-Token", "csrf-" + UUID.randomUUID())
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"session_id\":\"" + UUID.randomUUID() + "\",\"expires_in\":900}");
        });
    }

    /** The access token the login route minted last. */
    public String lastAccessToken() {
        return lastAccessToken;
    }

    /** A JSON response. */
    public static MockResponse json(int status, String body) {
        return new MockResponse().setResponseCode(status)
                .setHeader("Content-Type", "application/json").setBody(body);
    }

    /** A bodiless response. */
    public static MockResponse status(int status) {
        return new MockResponse().setResponseCode(status);
    }

    private static String unsignedAccessToken(UUID tenantId) {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String header = enc.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = enc.encodeToString(("{\"sub\":\"" + UUID.randomUUID() + "\",\"tenant_id\":\""
                + tenantId + "\",\"org_id\":\"" + UUID.randomUUID() + "\",\"jti\":\"" + UUID.randomUUID()
                + "\",\"exp\":" + (Instant.now().getEpochSecond() + 900) + "}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig" + UUID.randomUUID().toString().replace("-", "");
    }

    @Override
    public void close() throws IOException {
        server.close();
    }
}
