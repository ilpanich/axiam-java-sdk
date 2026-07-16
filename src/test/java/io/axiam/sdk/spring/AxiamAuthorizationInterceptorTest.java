package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.annotations.AxiamRequireAccess;
import io.axiam.sdk.annotations.AxiamRequireAuth;
import io.axiam.sdk.annotations.AxiamRequireRole;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full CONTRACT.md &sect;11 matrix for {@link AxiamAuthorizationInterceptor}
 * driven through {@link MockMvc} (real Spring MVC handler mapping + path
 * variables) against a {@link MockWebServer} standing in for the AXIAM authz
 * endpoint: allow, deny&rarr;403, unauthenticated&rarr;401,
 * missing/non-UUID resource&rarr;400, transport failure&rarr;503 (fail closed),
 * {@code subject_id} asserted on the wire, scope passthrough, {@code require_auth},
 * {@code require_role}, and a type-level annotation.
 *
 * <p>{@code SecurityContextHolder} is populated in the calling thread before
 * {@code perform(...)} (MockMvc runs synchronously in that thread), mirroring
 * what {@link AxiamAuthenticationFilter} would have set for a real request.
 */
class AxiamAuthorizationInterceptorTest {

    private static final String UUID_A = "11111111-1111-1111-1111-111111111111";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static MockMvc mvc(AxiamClient client) {
        return MockMvcBuilders
                .standaloneSetup(new DocController(), new TypeLevelController())
                .addInterceptors(new AxiamAuthorizationInterceptor(client))
                .build();
    }

    private static void authenticateAs(String userId, String... authorities) {
        List<SimpleGrantedAuthority> granted = java.util.Arrays.stream(authorities)
                .map(SimpleGrantedAuthority::new)
                .toList();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(userId, null, granted));
    }

    private static MockWebServer serverReturning(String jsonBody) throws Exception {
        MockWebServer server = new MockWebServer();
        server.enqueue(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json").setBody(jsonBody));
        server.start();
        return server;
    }

    // ------------------------------------------------------------------
    // require_access
    // ------------------------------------------------------------------

    @Test
    void allowedCheckReaches200AndSendsSubjectIdOnTheWire() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                mvc(client).perform(get("/documents/{id}", UUID_A)).andExpect(status().isOk());

                RecordedRequest recorded = server.takeRequest();
                assertEquals("/api/v1/authz/check", recorded.getPath());
                JsonNode body = MAPPER.readTree(recorded.getBody().readUtf8());
                assertEquals("user-123", body.path("subject_id").asText());
                assertEquals("read", body.path("action").asText());
                assertEquals(UUID_A, body.path("resource_id").asText());
                assertFalse(body.has("scope"));
            }
        }
    }

    @Test
    void scopeIsPassedThroughOnTheWire() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-9");
                mvc(client).perform(get("/scoped/{id}", UUID_A)).andExpect(status().isOk());

                RecordedRequest recorded = server.takeRequest();
                JsonNode body = MAPPER.readTree(recorded.getBody().readUtf8());
                assertEquals("fields:title", body.path("scope").asText());
                assertEquals("update", body.path("action").asText());
            }
        }
    }

    @Test
    void deniedCheckMapsTo403() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":false,\"reason\":\"nope\"}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden())
                        .andReturn();
                JsonNode body = MAPPER.readTree(result.getResponse().getContentAsString());
                assertEquals("authorization_denied", body.path("error").asText());
            }
        }
    }

    @Test
    void serverForbiddenMapsTo403() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(403).setBody("forbidden"));
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                mvc(client).perform(get("/documents/{id}", UUID_A)).andExpect(status().isForbidden());
            }
        }
    }

    @Test
    void unauthenticatedMapsTo401() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                // No SecurityContext authentication set.
                MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isUnauthorized())
                        .andReturn();
                JsonNode body = MAPPER.readTree(result.getResponse().getContentAsString());
                assertEquals("authentication_failed", body.path("error").asText());
                // The authz endpoint must NOT have been called.
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    @Test
    void nonUuidPathVariableMapsTo400() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                MvcResult result = mvc(client).perform(get("/documents/{id}", "not-a-uuid"))
                        .andExpect(status().isBadRequest())
                        .andReturn();
                JsonNode body = MAPPER.readTree(result.getResponse().getContentAsString());
                assertEquals("invalid_request", body.path("error").asText());
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    @Test
    void missingPathVariableMapsTo400() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                // /novar is annotated resourceParam="id" but its path has no {id}.
                mvc(client).perform(get("/novar")).andExpect(status().isBadRequest());
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    @Test
    void transportFailureFailsClosedWith503() throws Exception {
        // A started-then-closed server yields a refused connection → NetworkError.
        MockWebServer dead = new MockWebServer();
        dead.start();
        String url = dead.url("/").toString();
        dead.close();

        try (AxiamClient client = AxiamClient.builder(url, "acme").build()) {
            authenticateAs("user-123");
            MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                    .andExpect(status().is(503))
                    .andReturn();
            JsonNode body = MAPPER.readTree(result.getResponse().getContentAsString());
            assertEquals("authz_unavailable", body.path("error").asText());
        }
    }

    @Test
    void staticResourceIdOverridesPathVariable() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                mvc(client).perform(get("/singleton/{id}", "ignored-path-value"))
                        .andExpect(status().isOk());

                RecordedRequest recorded = server.takeRequest();
                JsonNode body = MAPPER.readTree(recorded.getBody().readUtf8());
                assertEquals(UUID_A, body.path("resource_id").asText());
            }
        }
    }

    // ------------------------------------------------------------------
    // type-level annotation
    // ------------------------------------------------------------------

    @Test
    void typeLevelAnnotationIsEnforced() throws Exception {
        try (MockWebServer server = serverReturning("{\"allowed\":false}")) {
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                mvc(client).perform(get("/type/{id}", UUID_A)).andExpect(status().isForbidden());
                assertEquals(1, server.getRequestCount());
            }
        }
    }

    // ------------------------------------------------------------------
    // require_auth
    // ------------------------------------------------------------------

    @Test
    void requireAuthAllowsAuthenticated() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123");
                mvc(client).perform(get("/authed")).andExpect(status().isOk());
                assertEquals(0, server.getRequestCount()); // no server round-trip
            }
        }
    }

    @Test
    void requireAuthRejectsUnauthenticated() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                mvc(client).perform(get("/authed")).andExpect(status().isUnauthorized());
            }
        }
    }

    // ------------------------------------------------------------------
    // require_role (local, no server round-trip)
    // ------------------------------------------------------------------

    @Test
    void requireRoleAllowsHolder() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123", "ROLE_admin");
                mvc(client).perform(get("/adminonly")).andExpect(status().isOk());
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    @Test
    void requireRoleAllowsUnprefixedAuthority() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123", "admin");
                mvc(client).perform(get("/adminonly")).andExpect(status().isOk());
            }
        }
    }

    @Test
    void requireRoleRejectsNonHolder() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                authenticateAs("user-123", "ROLE_user");
                mvc(client).perform(get("/adminonly")).andExpect(status().isForbidden());
            }
        }
    }

    @Test
    void requireRoleRejectsUnauthenticated() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                mvc(client).perform(get("/adminonly")).andExpect(status().isUnauthorized());
            }
        }
    }

    // ------------------------------------------------------------------
    // Handler with no §11 annotation is untouched.
    // ------------------------------------------------------------------

    @Test
    void unannotatedHandlerIsNotIntercepted() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                // No auth, no annotation → passes through to the handler (200).
                mvc(client).perform(get("/open")).andExpect(status().isOk());
            }
        }
    }

    // ------------------------------------------------------------------
    // Test controllers
    // ------------------------------------------------------------------

    @RestController
    static class DocController {

        @AxiamRequireAccess(action = "read", resourceParam = "id")
        @GetMapping("/documents/{id}")
        String read(@PathVariable("id") String id) {
            return "doc:" + id;
        }

        @AxiamRequireAccess(action = "update", resourceParam = "id", scope = "fields:title")
        @GetMapping("/scoped/{id}")
        String scoped(@PathVariable("id") String id) {
            return "scoped:" + id;
        }

        @AxiamRequireAccess(action = "read", resourceId = UUID_A)
        @GetMapping("/singleton/{id}")
        String singleton(@PathVariable("id") String id) {
            return "singleton";
        }

        @AxiamRequireAccess(action = "read", resourceParam = "id")
        @GetMapping("/novar")
        String noVar() {
            return "novar";
        }

        @AxiamRequireAuth
        @GetMapping("/authed")
        String authed() {
            return "authed";
        }

        @AxiamRequireRole({"admin"})
        @GetMapping("/adminonly")
        String adminOnly() {
            return "admin";
        }

        @GetMapping("/open")
        String open() {
            return "open";
        }
    }

    @RestController
    @AxiamRequireAccess(action = "read", resourceParam = "id")
    static class TypeLevelController {

        @GetMapping("/type/{id}")
        String read(@PathVariable("id") String id) {
            return "type:" + id;
        }
    }
}
