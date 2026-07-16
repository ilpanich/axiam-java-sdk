package io.axiam.sdk;

import io.axiam.sdk.errors.NetworkError;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The parts of {@code checkAccess}/{@code batchCheck} {@link io.axiam.sdk.rest.AuthzTest}
 * doesn't reach: the optional {@code scope} qualifier on both the single and batch wire bodies,
 * the async {@code CompletableFuture} twins, {@code batchCheck}'s own non-2xx mapping, and the
 * two low-level transport/parse failure wraps ({@code executeJsonPost}'s connect failure,
 * {@code readJson}'s malformed-body failure) that are shared by every REST call {@code
 * AxiamClient} makes.
 */
class AxiamClientAuthzExtraTest {

    @Test
    void checkAccessWithScopeIncludesScopeInTheRequestBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                client.checkAccess("users:get", "11111111-1111-1111-1111-111111111111", "profile");

                RecordedRequest recorded = server.takeRequest();
                assertTrue(recorded.getBody().readUtf8().contains("\"scope\":\"profile\""));
            }
        }
    }

    @Test
    void checkAccessAsyncTwoAndThreeArgOverloadsResolve() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertTrue(client.checkAccessAsync("users:get", "r1").get().allowed());
                assertTrue(client.checkAccessAsync("users:get", "r1", "profile").get().allowed());
            }
        }
    }

    @Test
    void checkAccessWithSubjectIdIncludesSubjectIdInTheRequestBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertTrue(client.checkAccess("end-user-1", "users:get",
                        "11111111-1111-1111-1111-111111111111", "profile").allowed());

                RecordedRequest recorded = server.takeRequest();
                String body = recorded.getBody().readUtf8();
                assertTrue(body.contains("\"subject_id\":\"end-user-1\""));
                assertTrue(body.contains("\"scope\":\"profile\""));
            }
        }
    }

    @Test
    void checkAccessAsyncWithSubjectIdResolves() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertTrue(client.checkAccessAsync("end-user-1", "users:get", "r1", null).get().allowed());

                RecordedRequest recorded = server.takeRequest();
                assertTrue(recorded.getBody().readUtf8().contains("\"subject_id\":\"end-user-1\""));
            }
        }
    }

    @Test
    void canAsyncTwoAndThreeArgOverloadsResolve() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertTrue(client.canAsync("users:get", "r1").get());
                assertTrue(client.canAsync("users:get", "r1", "profile").get());
            }
        }
    }

    @Test
    void batchCheckWithAScopedItemIncludesScopeForThatItemOnly() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"results\":[{\"allowed\":true},{\"allowed\":true}]}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                client.batchCheck(List.of(
                        new AxiamClient.AccessCheck("users:get", "r1"),
                        new AxiamClient.AccessCheck("users:get", "r2", "profile")));

                RecordedRequest recorded = server.takeRequest();
                String body = recorded.getBody().readUtf8();
                assertTrue(body.contains("\"scope\":\"profile\""));
            }
        }
    }

    @Test
    void batchCheckAsyncResolves() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"results\":[{\"allowed\":true}]}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                List<AxiamClient.AccessResult> results =
                        client.batchCheckAsync(List.of(new AxiamClient.AccessCheck("users:get", "r1"))).get();
                assertEquals(1, results.size());
                assertTrue(results.get(0).allowed());
            }
        }
    }

    @Test
    void batchCheckNonSuccessResponseThrowsMappedError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // A 5xx maps to NetworkError (ErrorMapper), which IS retryable (Retry.DEFAULT_MAX_ATTEMPTS
            // = 3) — enqueue one response per possible attempt so the dispatcher never blocks waiting
            // on a 4th request that never comes.
            server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
            server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
            server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(RuntimeException.class,
                        () -> client.batchCheck(List.of(new AxiamClient.AccessCheck("users:get", "r1"))));
            }
        }
    }

    @Test
    void connectionRefusedDuringExecuteJsonPostThrowsNetworkError() throws Exception {
        MockWebServer server = new MockWebServer();
        server.start();
        String baseUrl = server.url("/").toString();
        server.close(); // nothing is listening on this port/host anymore

        try (AxiamClient client = AxiamClient.builder(baseUrl, "acme")
                .connectTimeout(java.time.Duration.ofMillis(500))
                .build()) {
            assertThrows(NetworkError.class, () -> client.checkAccess("users:get", "r1"));
        }
    }

    @Test
    void malformedJsonResponseBodyThrowsNetworkErrorFromReadJson() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // readJson's IOException wrap is a NetworkError, which IS retryable — enqueue one
            // malformed response per possible attempt (see batchCheckNonSuccessResponseThrowsMappedError).
            for (int i = 0; i < 3; i++) {
                server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                        .setBody("{not valid json"));
            }
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(NetworkError.class, () -> client.checkAccess("users:get", "r1"));
            }
        }
    }
}
