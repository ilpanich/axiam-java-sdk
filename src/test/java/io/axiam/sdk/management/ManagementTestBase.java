package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.axiam.sdk.AxiamClient;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared scaffolding for the CONTRACT §27 management tests.
 *
 * <p>The generated conformance suite and the hand-written semantics suites both
 * build a client the same way: a real {@code login()} against a mocked endpoint,
 * so the org and tenant UUIDs the management routes interpolate come from the
 * access token's claims exactly as they would in production, rather than being
 * poked into private fields by the test.
 *
 * <p>MockWebServer's default queue is the wrong shape here — a management test
 * mounts a route and asserts the SDK reached <em>that</em> path, which a queue
 * cannot express. So this installs a {@link Dispatcher} that routes on method
 * and path and fails loudly on anything unmounted.
 */
abstract class ManagementTestBase {

    /** The organization UUID the test client's access token carries. */
    static final UUID ORG_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");

    /** The tenant UUID the test client's access token carries. */
    static final UUID TENANT_ID = UUID.fromString("33333333-3333-4333-8333-333333333333");

    /** The identifier the generated cases pass for every {@code {..._id}} parameter. */
    static final UUID EXAMPLE_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");

    /** The slug the client is built with, and sends as {@code X-Tenant-ID} (§5 rule 2). */
    static final String TENANT_SLUG = "acme";

    /** Reads bodies in assertions. */
    static final ObjectMapper JSON = new ObjectMapper()
            .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());

    /** The mocked server every test in this hierarchy talks to. */
    protected MockWebServer server;

    /** A logged-in client pointed at {@link #server}. */
    protected AxiamClient client;

    /** Mounted routes, keyed by {@code "METHOD /path"}. */
    private final Map<String, Route> routes = new ConcurrentHashMap<>();

    /** Requests that reached no mounted route, for a clear failure message. */
    private final List<String> unmatched = new ArrayList<>();

    /** One mounted response, and what actually reached it. */
    static final class Route {
        private final int status;
        private final String body;
        private final List<Recorded> requests = new ArrayList<>();

        Route(int status, String body) {
            this.status = status;
            this.body = body;
        }

        /** How many requests reached this route. */
        int calls() {
            return requests.size();
        }

        /** The most recent request this route saw. */
        Recorded last() {
            if (requests.isEmpty()) {
                throw new AssertionError("route was never called");
            }
            return requests.get(requests.size() - 1);
        }
    }

    /** What a mounted route saw. */
    record Recorded(String method, String path, Map<String, String> query, String body,
                    Map<String, String> headers) {

        /** The request body's key set, sorted. */
        List<String> keys() throws IOException {
            JsonNode node = JSON.readTree(body);
            List<String> out = new ArrayList<>();
            node.fieldNames().forEachRemaining(out::add);
            out.sort(String::compareTo);
            return out;
        }

        /** The request body as a tree. */
        JsonNode json() throws IOException {
            return JSON.readTree(body);
        }
    }

    /** Starts the server and logs a client in against it. */
    @BeforeEach
    void startServer() throws Exception {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String path = request.getPath() == null ? "" : request.getPath();
                String bare = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;

                if ("/api/v1/auth/login".equals(bare)) {
                    return new MockResponse().setResponseCode(200)
                            .addHeader("Set-Cookie", "axiam_access=" + accessToken() + "; Path=/")
                            .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
                            .setBody("{\"session_id\":\"" + UUID.randomUUID()
                                    + "\",\"expires_in\":900}");
                }

                Route route = routes.get(request.getMethod() + " " + bare);
                if (route == null) {
                    unmatched.add(request.getMethod() + " " + bare);
                    return new MockResponse().setResponseCode(501)
                            .setBody("no route mounted for " + request.getMethod() + " " + bare);
                }
                Map<String, String> query = new LinkedHashMap<>();
                if (path.contains("?")) {
                    for (String pair : path.substring(path.indexOf('?') + 1).split("&")) {
                        int eq = pair.indexOf('=');
                        if (eq > 0) {
                            query.put(java.net.URLDecoder.decode(pair.substring(0, eq),
                                            StandardCharsets.UTF_8),
                                    java.net.URLDecoder.decode(pair.substring(eq + 1),
                                            StandardCharsets.UTF_8));
                        }
                    }
                }
                // Header names are case-insensitive on the wire, so the
                // recorded map is too: the SDK sends X-Tenant-Id and an
                // assertion spelling it X-Tenant-ID is still asserting the
                // same header.
                Map<String, String> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                request.getHeaders().forEach(pair -> headers.put(pair.getFirst(), pair.getSecond()));
                route.requests.add(new Recorded(request.getMethod(), bare, query,
                        request.getBody().readUtf8(), headers));

                MockResponse response = new MockResponse().setResponseCode(route.status);
                if (!route.body.isEmpty()) {
                    response.setHeader("Content-Type", "application/json").setBody(route.body);
                }
                return response;
            }
        });
        server.start();
        client = AxiamClient.builder(server.url("/").toString().replaceAll("/$", ""), TENANT_SLUG)
                .build();
        client.login("admin@example.test", "hunter2hunter2");
    }

    /** Shuts the client and server down. */
    @AfterEach
    void stopServer() throws Exception {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
    }

    /**
     * Mounts one route, answering {@code body} at {@code status}.
     *
     * <p>The match is exact on method and path, so an operation that sends its
     * request somewhere other than the registry's path fails here rather than
     * falling through to another mock.
     */
    protected Route mount(String method, String path, int status, String body) {
        Route route = new Route(status, body);
        routes.put(method + " " + path, route);
        return route;
    }

    /** The route mounted at {@code method path}, for assertions. */
    protected Route route(String method, String path) {
        Route found = routes.get(method + " " + path);
        if (found == null) {
            throw new AssertionError("no route mounted at " + method + " " + path);
        }
        return found;
    }

    /** Requests that reached no mounted route. */
    protected List<String> unmatched() {
        return List.copyOf(unmatched);
    }

    /** How many requests reached any mounted route, plus any that missed. */
    protected int totalCalls() {
        return routes.values().stream().mapToInt(Route::calls).sum() + unmatched.size();
    }

    /**
     * The {@code org_id} claim the mocked login endpoint mints.
     *
     * <p>Overridable so a test can mint a token whose claim is unusable and
     * assert the SDK refuses locally rather than putting a malformed segment
     * into a path.
     */
    private String orgClaim = ORG_ID.toString();

    /**
     * Makes every subsequent login mint a token whose {@code org_id} is {@code value}.
     *
     * @param value the raw claim to embed, valid UUID or not
     */
    protected void mintOrgClaim(String value) {
        this.orgClaim = value;
    }

    /**
     * Logs {@code other} in against this suite's mocked login endpoint.
     *
     * @param other a client built against {@link #server} but not yet logged in
     */
    protected void login(AxiamClient other) {
        other.login("admin@example.test", "hunter2hunter2");
    }

    /** An unsigned access token carrying the org and tenant this suite uses. */
    private String accessToken() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(
                "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(("{"
                + "\"sub\":\"" + EXAMPLE_ID + "\","
                + "\"tenant_id\":\"" + TENANT_ID + "\","
                + "\"org_id\":\"" + orgClaim + "\","
                + "\"jti\":\"" + UUID.randomUUID() + "\","
                + "\"exp\":" + (Instant.now().getEpochSecond() + 900)
                + "}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".not-a-real-signature";
    }

    /**
     * Every {@code namespace.operation} the registry declares, sorted.
     *
     * <p>Read from the registry rather than restated here, so a registry that
     * grows an operation fails the generated suite until the surface is
     * regenerated.
     */
    protected static List<String> expectedSurface() throws IOException {
        JsonNode namespaces = JSON.readTree(
                Files.readString(Path.of("management-registry.json"))).path("namespaces");
        List<String> out = new ArrayList<>();
        namespaces.fieldNames().forEachRemaining(ns ->
                namespaces.path(ns).path("operations").fieldNames()
                        .forEachRemaining(op -> out.add(ns + "." + op)));
        out.sort(String::compareTo);
        return out;
    }

    /** A minimal user response body, distinguishable by index. */
    protected static String userBody(int index) {
        return ("{\"id\":\"%08d-1111-4111-8111-111111111111\",\"username\":\"user%d\","
                + "\"email\":\"user%d@example.test\",\"email_verified\":true,"
                + "\"failed_login_attempts\":0,\"is_locked\":false,\"metadata\":{},"
                + "\"mfa_enabled\":false,\"status\":\"Active\",\"tenant_id\":\"%s\","
                + "\"created_at\":\"2026-08-26T00:00:00Z\",\"updated_at\":\"2026-08-26T00:00:00Z\"}")
                .formatted(index, index, index, TENANT_ID);
    }

    /** A minimal role response body. */
    protected static String roleBody(UUID id, String name, String description) {
        return ("{\"id\":\"%s\",\"name\":\"%s\",\"description\":\"%s\",\"is_global\":false,"
                + "\"tenant_id\":\"%s\",\"created_at\":\"2026-08-26T00:00:00Z\","
                + "\"updated_at\":\"2026-08-26T00:00:00Z\"}")
                .formatted(id, name, description, TENANT_ID);
    }

    /** A single-item page envelope around {@code item}. */
    protected static String pageOf(@Nullable String item) {
        return item == null
                ? "{\"items\":[],\"total\":0,\"offset\":0,\"limit\":200}"
                : "{\"items\":[" + item + "],\"total\":1,\"offset\":0,\"limit\":200}";
    }
}
