package io.axiam.sdk.spring;

import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.oidc.MemoryOidcStateStore;
import io.axiam.sdk.oidc.OidcStateEntry;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12 "Login with AXIAM" Spring glue:
 * {@link AxiamOidcLoginRoutes#routes} redirects to the IdP on the login path
 * and completes the exchange on the callback path, mapping failures per the
 * class's documented status codes (400/401/503).
 */
class AxiamOidcLoginRoutesTest {

    private static final List<HttpMessageConverter<?>> CONVERTERS =
            List.of(new StringHttpMessageConverter(), new MappingJackson2HttpMessageConverter());

    @Test
    void loginPathRedirectsToTheAuthorizationEndpointAndSavesState() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, "33333333-3333-3333-3333-333333333333")
                    .oidcClientId("my-app").build()) {
                MemoryOidcStateStore store = new MemoryOidcStateStore();
                RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, store,
                        new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/oidc/callback"));

                MockHttpServletResponse response = dispatch(routes, "GET", "/oidc/login");

                assertEquals(302, response.getStatus());
                String location = response.getHeader("Location");
                assertNotNull(location);
                assertTrue(location.startsWith(stripSlash(base) + "/oauth2/authorize"));
                assertEquals(1, store.size(), "beginLogin must park state/nonce/codeVerifier in the store");
            }
        }
    }

    @Test
    void callbackWithMissingStateOrCodeIs400() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "33333333-3333-3333-3333-333333333333")
                .oidcClientId("my-app").build()) {
            RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, new MemoryOidcStateStore(),
                    new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/cb"));

            MockHttpServletResponse response = dispatch(routes, "GET", "/oidc/callback");

            assertEquals(400, response.getStatus());
            assertTrue(response.getContentAsString().contains("invalid_request"));
        }
    }

    @Test
    void callbackWithIdpErrorIs401() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "33333333-3333-3333-3333-333333333333")
                .oidcClientId("my-app").build()) {
            RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, new MemoryOidcStateStore(),
                    new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/cb"));

            MockHttpServletResponse response = dispatch(routes, "GET",
                    "/oidc/callback?error=access_denied&error_description=user+cancelled");

            assertEquals(401, response.getStatus());
            assertTrue(response.getContentAsString().contains("authentication_failed"));
        }
    }

    @Test
    void callbackWithUnknownStateIs401() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "33333333-3333-3333-3333-333333333333")
                .oidcClientId("my-app").build()) {
            RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, new MemoryOidcStateStore(),
                    new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/cb"));

            MockHttpServletResponse response = dispatch(routes, "GET", "/oidc/callback?state=never-issued&code=some-code");

            assertEquals(401, response.getStatus());
        }
    }

    @Test
    void callbackHappyPathExchangesTheCodeAndRedirectsToReturnTo() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            String idToken = OidcTestSupport.signEdDsa(keyPair,
                    OidcTestSupport.validIdTokenClaims(stripSlash(base), "my-app", "nonce-1"));
            server.enqueue(OidcTestSupport.tokenResponse("access-1", null, idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, "33333333-3333-3333-3333-333333333333")
                    .oidcClientId("my-app").build()) {
                MemoryOidcStateStore store = new MemoryOidcStateStore();
                store.save(new OidcStateEntry("state-1", "nonce-1", io.axiam.sdk.Sensitive.of("verifier-1"),
                        "https://app.example.com/oidc/callback", "/dashboard"));

                RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, store,
                        new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/oidc/callback"));

                MockHttpServletResponse response = dispatch(routes, "GET", "/oidc/callback?state=state-1&code=code-1");

                assertEquals(302, response.getStatus());
                assertEquals("/dashboard", response.getHeader("Location"));
                assertEquals(0, store.size(), "the state must be consumed (single-use)");
            }
        }
    }

    @Test
    void callbackHappyPathWithNoDestinationReturnsJsonSummary() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            String idToken = OidcTestSupport.signEdDsa(keyPair,
                    OidcTestSupport.validIdTokenClaims(stripSlash(base), "my-app", "nonce-1"));
            server.enqueue(OidcTestSupport.tokenResponse("access-1", null, idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, "33333333-3333-3333-3333-333333333333")
                    .oidcClientId("my-app").build()) {
                MemoryOidcStateStore store = new MemoryOidcStateStore();
                store.save(new OidcStateEntry("state-1", "nonce-1", io.axiam.sdk.Sensitive.of("verifier-1"),
                        "https://app.example.com/oidc/callback"));

                RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, store,
                        new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/oidc/callback"));

                MockHttpServletResponse response = dispatch(routes, "GET", "/oidc/callback?state=state-1&code=code-1");

                assertEquals(200, response.getStatus());
                String body = response.getContentAsString();
                assertTrue(body.contains("\"authenticated\":true"));
                assertTrue(body.contains("\"sub\":\"user-1\""));
            }
        }
    }

    @Test
    void loginPathFailureIs503WhenDiscoveryUnreachable() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(500));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "33333333-3333-3333-3333-333333333333")
                    .oidcClientId("my-app").build()) {
                RouterFunction<ServerResponse> routes = AxiamOidcLoginRoutes.routes(client, new MemoryOidcStateStore(),
                        new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", "https://app.example.com/cb"));

                MockHttpServletResponse response = dispatch(routes, "GET", "/oidc/login");

                assertEquals(503, response.getStatus());
            }
        }
    }

    private static MockHttpServletResponse dispatch(RouterFunction<ServerResponse> routes, String method, String uri) throws Exception {
        String path = uri.contains("?") ? uri.substring(0, uri.indexOf('?')) : uri;
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (uri.contains("?")) {
            request.setQueryString(uri.substring(uri.indexOf('?') + 1));
            for (String pair : uri.substring(uri.indexOf('?') + 1).split("&")) {
                String[] kv = pair.split("=", 2);
                request.addParameter(kv[0], java.net.URLDecoder.decode(kv.length > 1 ? kv[1] : "", "UTF-8"));
            }
        }
        ServerRequest serverRequest = ServerRequest.create(request, CONVERTERS);
        HandlerFunction<ServerResponse> handler = routes.route(serverRequest).orElseThrow();
        ServerResponse serverResponse = handler.handle(serverRequest);

        MockHttpServletResponse response = new MockHttpServletResponse();
        serverResponse.writeTo(request, response, new ServerResponse.Context() {
            @Override
            public List<HttpMessageConverter<?>> messageConverters() {
                return CONVERTERS;
            }
        });
        return response;
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
