package io.axiam.sdk.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.mcp.Mcp;
import io.axiam.sdk.mcp.ProtectedResourceMetadata;

import jakarta.servlet.FilterChain;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * CONTRACT.md &sect;28.9 required tests 3-5 (401 with the challenge, 403
 * {@code insufficient_scope}, an {@code aud}-mismatched token refused) plus
 * the additive regression, exercised against the Spring MVC guards
 * ({@link AxiamAuthenticationFilter}, {@link AxiamAuthorizationInterceptor},
 * {@link AxiamProtectedResourceMetadataController}). Tests 1-2 are
 * framework-independent and live in {@code io.axiam.sdk.mcp.McpTest}.
 *
 * <p>The fixture is &sect;28.9's, verbatim.
 */
class McpGuardTest {

    private static final String RESOURCE = "https://mcp.example.com/mcp";
    private static final String METADATA_PATH = "/.well-known/oauth-protected-resource/mcp";
    private static final String METADATA_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
    private static final String CONFIGURED_TENANT = "tenant-a";
    private static final String VECTOR_1 = "Bearer resource_metadata=\"" + METADATA_URL + "\"";
    private static final String VECTOR_2 =
            "Bearer error=\"invalid_token\", resource_metadata=\"" + METADATA_URL + "\"";
    private static final String VECTOR_3 =
            "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"" + METADATA_URL + "\"";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private static JwksVerifier mcpVerifier(MockWebServer server) {
        return new JwksVerifier(server.url("/").toString(),
                new JwksVerifier.LocalVerificationPolicy(null, RESOURCE, JwksVerifier.DEFAULT_CLOCK_SKEW_SECONDS));
    }

    private static MockWebServer startJwksServer(OctetKeyPair keyPair) throws Exception {
        MockWebServer server = new MockWebServer();
        for (int i = 0; i < 8; i++) {
            server.enqueue(jwksResponse(keyPair.toPublicJWK()));
        }
        server.start();
        return server;
    }

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(List.of(publicKey)).toString();
        return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body);
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static String signEdDsa(OctetKeyPair keyPair, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(JOSEObjectType.JWT).keyID(keyPair.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(keyPair));
        return jwt.serialize();
    }

    private static JWTClaimsSet.Builder baseClaims(String aud, long expiresInMillis) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", CONFIGURED_TENANT)
                .audience(aud)
                .expirationTime(new Date(System.currentTimeMillis() + expiresInMillis));
    }

    // ------------------------------------------------------------------
    // Test 3 — 401 with the challenge
    // ------------------------------------------------------------------

    @Test
    void noCredentialFilterPassesThroughUnauthenticated_thenEntryPointEmitsVector1() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);

            // The filter's own half: no credential passes through unauthenticated
            // (byte-for-byte its pre-§28 behaviour) — the entry point, not the
            // filter, is what turns that into the 401 (see the class Javadoc).
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI("/mcp");
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();
            filter.doFilter(request, response, chain);
            assertTrue(chain.invoked);

            // The entry point's own half: the same configuration, the vector-1
            // challenge, and the §10 JSON body unchanged.
            AxiamMcpAuthenticationEntryPoint entryPoint = new AxiamMcpAuthenticationEntryPoint(verifier, METADATA_URL);
            MockHttpServletResponse entryResponse = new MockHttpServletResponse();
            entryPoint.commence(request, entryResponse, null);

            assertEquals(401, entryResponse.getStatus());
            assertEquals(VECTOR_1, entryResponse.getHeader("WWW-Authenticate"));
            assertFalse(entryResponse.getContentAsString().contains("error_description"));
            JsonNode body = MAPPER.readTree(entryResponse.getContentAsString());
            assertEquals("authentication_failed", body.path("error").asText());
        }
    }

    @Test
    void expiredTokenGets401WithVector2AndUnchangedJsonBody() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);
            String expired = signEdDsa(keyPair, baseClaims(RESOURCE, -3_600_000).build());

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + expired);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new RecordingFilterChain());

            assertEquals(401, response.getStatus());
            assertEquals(VECTOR_2, response.getHeader("WWW-Authenticate"));
            assertFalse(response.getContentAsString().contains("error_description"));
            assertFalse(response.getContentAsString().contains(expired), "must not echo the token");
            JsonNode body = MAPPER.readTree(response.getContentAsString());
            assertEquals("authentication_failed", body.path("error").asText());
        }
    }

    @Test
    void aMalformedTokenGets401WithVector2ViaTheGenericVerificationFailurePath() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer not-a-jwt-at-all");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new RecordingFilterChain());

            assertEquals(401, response.getStatus());
            assertEquals(VECTOR_2, response.getHeader("WWW-Authenticate"));
        }
    }

    @Test
    void metadataDocumentPathIsExemptedFromTheFilterAndTheControllerServesItUnauthenticated() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);

            // The globally-mounted guard exempts exactly this path, GET, no credential.
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setMethod("GET");
            request.setRequestURI(METADATA_PATH);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();
            filter.doFilter(request, response, chain);
            assertTrue(chain.invoked, "the metadata document path must reach the controller unauthenticated");

            // The controller behind that path answers 200 with the exact document.
            ProtectedResourceMetadata metadata = Mcp.protectedResourceMetadata(
                    RESOURCE, List.of("https://axiam.example.com"), List.of("mcp:read", "mcp:tools"));
            var handlerMapping = new org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping();
            var appContext = new org.springframework.web.context.support.StaticWebApplicationContext();
            appContext.refresh();
            handlerMapping.setApplicationContext(appContext);
            handlerMapping.afterPropertiesSet();
            AxiamProtectedResourceMetadataController controller =
                    new AxiamProtectedResourceMetadataController(metadata, handlerMapping);

            // afterPropertiesSet() registers exactly one route, at the derived path.
            controller.afterPropertiesSet();
            assertEquals(1, handlerMapping.getHandlerMethods().size());
            assertTrue(handlerMapping.getHandlerMethods().keySet().iterator().next()
                    .toString().contains(METADATA_PATH));

            var serveResponse = controller.serve();

            assertEquals(200, serveResponse.getStatusCode().value());
            assertEquals("application/json", serveResponse.getHeaders().getFirst("Content-Type"));
            assertEquals("public, max-age=3600", serveResponse.getHeaders().getFirst("Cache-Control"));
            assertEquals("*", serveResponse.getHeaders().getFirst("Access-Control-Allow-Origin"));
            JsonNode parsed = MAPPER.readTree(serveResponse.getBody());
            assertEquals(RESOURCE, parsed.path("resource").asText());
        }
    }

    // ------------------------------------------------------------------
    // Test 4 — 403 insufficient_scope
    // ------------------------------------------------------------------

    /** A server that answers the authz check with a fixed {@code allowed}/{@code reason_code}. */
    private static final class Backend extends Dispatcher implements AutoCloseable {
        private final MockWebServer server = new MockWebServer();
        private final String body;

        Backend(String body) throws Exception {
            this.body = body;
            server.setDispatcher(this);
            server.start();
        }

        @Override
        public @NonNull MockResponse dispatch(RecordedRequest request) {
            return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body);
        }

        String url() {
            return server.url("/").toString();
        }

        @Override
        public void close() throws Exception {
            server.close();
        }
    }

    private static void authenticate() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("user-1", null, List.of()));
    }

    private static MockMvc mvc(AxiamClient client) {
        return MockMvcBuilders.standaloneSetup(new DocController())
                .addInterceptors(new AxiamAuthorizationInterceptor(client, null, METADATA_URL, RESOURCE))
                .build();
    }

    @Test
    void theInterceptorsOwn401ForAnUnauthenticatedRequestAlsoCarriesVector1() throws Exception {
        try (Backend backend = new Backend("{\"allowed\":true}")) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                // No authenticate() call: SecurityContextHolder stays empty, which
                // is always the "no credential" case here (D-14: this interceptor
                // runs strictly after AxiamAuthenticationFilter).
                MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isUnauthorized()).andReturn();
                assertEquals(VECTOR_1, result.getResponse().getHeader("WWW-Authenticate"));
            }
        }
    }

    @Test
    void noGrantOnARouteThatNamedAScopeGetsVector3AndTheJsonBodyIsStillAuthorizationDenied() throws Exception {
        try (Backend backend = new Backend("{\"allowed\":false,\"reason_code\":\"no_grant\"}")) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden()).andReturn();

                assertEquals(VECTOR_3, result.getResponse().getHeader("WWW-Authenticate"));
                JsonNode body = MAPPER.readTree(result.getResponse().getContentAsString());
                assertEquals("authorization_denied", body.path("error").asText());
            }
        }
    }

    @Test
    void deniedByRuleGetsNoHeader() throws Exception {
        try (Backend backend = new Backend("{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}")) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden()).andReturn();
                assertNull(result.getResponse().getHeader("WWW-Authenticate"));
            }
        }
    }

    @Test
    void anAbsentReasonCodeGetsNoHeader() throws Exception {
        try (Backend backend = new Backend("{\"allowed\":false}")) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MvcResult result = mvc(client).perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden()).andReturn();
                assertNull(result.getResponse().getHeader("WWW-Authenticate"));
            }
        }
    }

    @Test
    void aDenialWithNoScopeArgumentGetsNoHeader() throws Exception {
        try (Backend backend = new Backend("{\"allowed\":false,\"reason_code\":\"no_grant\"}")) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MockMvc noScopeMvc = MockMvcBuilders.standaloneSetup(new DocController())
                        .addInterceptors(new AxiamAuthorizationInterceptor(client, null, METADATA_URL, RESOURCE))
                        .build();
                MvcResult result = noScopeMvc.perform(get("/noscope/{id}", UUID_A))
                        .andExpect(status().isForbidden()).andReturn();
                assertNull(result.getResponse().getHeader("WWW-Authenticate"));
            }
        }
    }

    // ------------------------------------------------------------------
    // Test 5 — a token whose aud is not the resource is refused
    // ------------------------------------------------------------------

    @Test
    void aTokenWithADifferentAudIsRefused401WithVector2() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);
            String wrongAud = signEdDsa(keyPair, baseClaims("https://other.example.com/mcp", 900_000).build());

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + wrongAud);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new RecordingFilterChain());

            assertEquals(401, response.getStatus());
            assertEquals(VECTOR_2, response.getHeader("WWW-Authenticate"));
        }
    }

    @Test
    void aGeneralPurposeAxiamUserTokenIsRefused401WithVector2() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);
            String userToken = signEdDsa(keyPair,
                    baseClaims(JwksVerifier.RECOMMENDED_RESOURCE_SERVER_AUDIENCE, 900_000).build());

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + userToken);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new RecordingFilterChain());

            assertEquals(401, response.getStatus());
            assertEquals(VECTOR_2, response.getHeader("WWW-Authenticate"));
        }
    }

    @Test
    void aTokenWithTheMatchingAudIsAdmitted() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = mcpVerifier(server);
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT, METADATA_URL);
            String matching = signEdDsa(keyPair, baseClaims(RESOURCE, 900_000).build());

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + matching);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();
            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked);
            assertNull(response.getHeader("WWW-Authenticate"));
        }
    }

    @Test
    void constructingTheFilterWithResourceMetadataUrlAndNoExpectedAudienceFailsAtConstructionNamingBoth() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier noAudienceVerifier = new JwksVerifier(server.url("/").toString());
            ValidationError e = assertThrows(ValidationError.class,
                    () -> new AxiamAuthenticationFilter(noAudienceVerifier, CONFIGURED_TENANT, METADATA_URL));
            assertTrue(e.getMessage().contains("resourceMetadataUrl"));
            assertTrue(e.getMessage().contains("expectedAudience"));
        }
    }

    @Test
    void constructingTheInterceptorWithResourceMetadataUrlAndNoExpectedAudienceFailsAtConstruction() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "acme").build()) {
            assertThrows(ValidationError.class,
                    () -> new AxiamAuthorizationInterceptor(client, null, METADATA_URL, null));
        }
    }

    // ------------------------------------------------------------------
    // The regression that matters more than the five: off is off
    // ------------------------------------------------------------------

    @Test
    void withResourceMetadataUrlUnsetNoResponseEverGainsAHeader() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            AxiamAuthenticationFilter filter = new AxiamAuthenticationFilter(verifier, CONFIGURED_TENANT);

            MockHttpServletRequest noCredRequest = new MockHttpServletRequest();
            MockHttpServletResponse noCredResponse = new MockHttpServletResponse();
            RecordingFilterChain chain = new RecordingFilterChain();
            filter.doFilter(noCredRequest, noCredResponse, chain);
            assertTrue(chain.invoked);
            assertNull(noCredResponse.getHeader("WWW-Authenticate"));

            String expired = signEdDsa(keyPair, baseClaims(RESOURCE, -3_600_000).build());
            MockHttpServletRequest invalidRequest = new MockHttpServletRequest();
            invalidRequest.addHeader("Authorization", "Bearer " + expired);
            MockHttpServletResponse invalidResponse = new MockHttpServletResponse();
            filter.doFilter(invalidRequest, invalidResponse, new RecordingFilterChain());
            assertEquals(401, invalidResponse.getStatus());
            assertNull(invalidResponse.getHeader("WWW-Authenticate"));
        }

        try (Backend backend = new Backend("{\"allowed\":false,\"reason_code\":\"no_grant\"}")) {
            try (AxiamClient client = AxiamClient.builder(backend.url(), "acme").build()) {
                authenticate();
                MockMvc mvcNoMcp = MockMvcBuilders.standaloneSetup(new DocController())
                        .addInterceptors(new AxiamAuthorizationInterceptor(client))
                        .build();
                MvcResult result = mvcNoMcp.perform(get("/documents/{id}", UUID_A))
                        .andExpect(status().isForbidden()).andReturn();
                assertNull(result.getResponse().getHeader("WWW-Authenticate"),
                        "an interceptor built with the two/three-argument constructors must never emit a §28 header");
            }
        }
    }

    private static final String UUID_A = "11111111-1111-1111-1111-111111111111";

    /** Records whether the downstream chain (the protected endpoint) was reached. */
    private static final class RecordingFilterChain implements FilterChain {
        private boolean invoked = false;

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
            invoked = true;
        }
    }

    @RestController
    static class DocController {

        @io.axiam.sdk.annotations.AxiamRequireAccess(action = "read", resourceParam = "id", scope = "mcp:tools")
        @GetMapping("/documents/{id}")
        String read(@PathVariable("id") String id) {
            return "doc:" + id;
        }

        @io.axiam.sdk.annotations.AxiamRequireAccess(action = "read", resourceParam = "id")
        @GetMapping("/noscope/{id}")
        String noScope(@PathVariable("id") String id) {
            return "doc:" + id;
        }
    }
}
