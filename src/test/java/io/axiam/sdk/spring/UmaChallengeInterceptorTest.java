package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.annotations.AxiamRequireAccess;
import io.axiam.sdk.oidc.UmaChallenge;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The &sect;20.3 emit half, wired into the &sect;11 interceptor.
 *
 * <p>A {@link UmaChallenger} turns a denial from a bare 403 into a 403 that
 * tells the caller where to obtain authority. Everything asserted here is about
 * the <em>deny</em> path, because that is the only path that mints anything:
 *
 * <ol>
 *   <li>A denial with a challenger mints exactly one ticket and emits it.</li>
 *   <li>An allow mints nothing — an interceptor that minted on the happy path
 *       would put a Protection API call in front of every authorized
 *       request.</li>
 *   <li>A minting failure still denies, without a challenge. An outage must not
 *       turn a deny into a 500, and must never turn it into an allow.</li>
 * </ol>
 */
class UmaChallengeInterceptorTest {

    private static final String UUID_A = "11111111-1111-1111-1111-111111111111";
    private static final String PAT = "pat-token-value";
    private static final String TICKET = "ticket-value";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * A server that answers the authz check with {@code allowed} and the
     * Protection API's permission endpoint with {@code permStatus}, recording
     * every {@code /uma2/perm} body it saw.
     */
    private static final class Backend extends Dispatcher implements AutoCloseable {

        private final MockWebServer server = new MockWebServer();
        private final boolean allowed;
        private final int permStatus;
        final List<String> permBodies = new ArrayList<>();

        Backend(boolean allowed, int permStatus) throws Exception {
            this.allowed = allowed;
            this.permStatus = permStatus;
            server.setDispatcher(this);
            server.start();
        }

        @Override
        public @NonNull MockResponse dispatch(RecordedRequest request) {
            String path = request.getPath();
            if (path != null && path.startsWith("/uma2/perm")) {
                permBodies.add(request.getBody().readUtf8());
                if (permStatus != 201) {
                    return new MockResponse().setResponseCode(permStatus).setBody("nope");
                }
                return json(201, "{\"ticket\":\"" + TICKET + "\"}");
            }
            return json(200, "{\"allowed\":" + allowed + "}");
        }

        private static MockResponse json(int code, String body) {
            return new MockResponse().setResponseCode(code)
                    .setHeader("Content-Type", "application/json").setBody(body);
        }

        String url() {
            return server.url("/").toString();
        }

        @Override
        public void close() throws Exception {
            server.close();
        }
    }

    private static MockMvc mvc(AxiamClient client, UmaChallenger challenger) {
        return MockMvcBuilders
                .standaloneSetup(new DocController())
                .addInterceptors(new AxiamAuthorizationInterceptor(client, challenger))
                .build();
    }

    private static UmaChallenger challenger(AxiamClient client) {
        return new UmaChallenger("invoices", "https://id.example", Sensitive.of(PAT), client);
    }

    private static void authenticate() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("user-1", null, List.of()));
    }

    @Test
    void aDenialMintsOneTicketAndEmitsTheChallenge() throws Exception {
        try (Backend backend = new Backend(false, 201)) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MvcResult result = mvc(client, challenger(client))
                        .perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden())
                        .andReturn();

                assertEquals(1, backend.permBodies.size(), "one ticket, not two");

                // The emitted header is the one the consuming half parses — the
                // round trip is the point of shipping both halves.
                String header = result.getResponse().getHeader("WWW-Authenticate");
                assertNotNull(header);
                UmaChallenge parsed = UmaChallenge.parse(header);
                assertNotNull(parsed);
                assertEquals("invoices", parsed.realm());
                assertEquals("https://id.example", parsed.asUri());
                assertNotNull(parsed.ticket());
                assertEquals(TICKET, parsed.ticket().expose());

                // The challenge is additive: the body is still the ordinary §11
                // denial, so a caller that ignores the header is unaffected.
                JsonNode body = MAPPER.readTree(result.getResponse().getContentAsString());
                assertEquals("authorization_denied", body.path("error").asText());
            }
        }
    }

    @Test
    void theTicketAsksForTheActionThatWasRefused() throws Exception {
        try (Backend backend = new Backend(false, 201)) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                mvc(client, challenger(client)).perform(get("/approve/{id}", UUID_A))
                        .andExpect(status().isForbidden());

                // §20.2: the UMA scope is the AXIAM *action*. Asking for anything
                // else would mint a ticket for authority other than the one just
                // refused — and would step outside the grants the engine
                // evaluated, deny rules included.
                JsonNode requested = MAPPER.readTree(backend.permBodies.get(0));
                assertEquals(1, requested.size());
                assertEquals(UUID_A, requested.get(0).path("resource_id").asText());
                assertEquals("approve",
                        requested.get(0).path("resource_scopes").get(0).asText());
            }
        }
    }

    @Test
    void anAllowMintsNothing() throws Exception {
        try (Backend backend = new Backend(true, 201)) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                mvc(client, challenger(client)).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isOk());

                // Minting on the happy path would put a Protection API call — and
                // a live credential — in front of every authorized request.
                assertTrue(backend.permBodies.isEmpty());
            }
        }
    }

    @Test
    void aMintingFailureStillDeniesWithoutAChallenge() throws Exception {
        try (Backend backend = new Backend(false, 500)) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MvcResult result = mvc(client, challenger(client))
                        .perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden())
                        .andReturn();

                // Failure is not escalation: the caller was going to be refused,
                // and a Protection API outage must not turn that into a 500 — nor,
                // far worse, into an allow.
                assertNull(result.getResponse().getHeader("WWW-Authenticate"));
                assertEquals(1, backend.permBodies.size());
            }
        }
    }

    @Test
    void withoutAChallengerADenialIsThePlain403ItAlwaysWas() throws Exception {
        try (Backend backend = new Backend(false, 201)) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MvcResult result = MockMvcBuilders
                        .standaloneSetup(new DocController())
                        .addInterceptors(new AxiamAuthorizationInterceptor(client))
                        .build()
                        .perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden())
                        .andReturn();

                // Opt-in means opt-in: an application that never asked for UMA
                // semantics gets no Protection API traffic from its guards.
                assertNull(result.getResponse().getHeader("WWW-Authenticate"));
                assertTrue(backend.permBodies.isEmpty());
            }
        }
    }

    @Test
    void theChallengerNeverRendersItsPat() throws Exception {
        try (Backend backend = new Backend(false, 201)) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                // §7: a challenger is configuration an application may reasonably
                // log, and the PAT inside it is not.
                String rendered = challenger(client).toString();
                assertTrue(rendered.contains("invoices"));
                assertTrue(rendered.contains("[SENSITIVE]"), rendered);
                assertTrue(!rendered.contains(PAT), rendered);
            }
        }
    }

    @RestController
    static class DocController {

        @AxiamRequireAccess(action = "read", resourceParam = "id")
        @GetMapping("/documents/{id}")
        String read(@PathVariable("id") String id) {
            return "doc:" + id;
        }

        @AxiamRequireAccess(action = "approve", resourceParam = "id")
        @GetMapping("/approve/{id}")
        String approve(@PathVariable("id") String id) {
            return "approved:" + id;
        }
    }
}
