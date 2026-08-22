package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.PushedAuthorizationRequest;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;26 — Pushed Authorization Requests (RFC 9126).
 *
 * <p>Two assertions carry the section:
 *
 * <ul>
 *   <li>{@code aSuccessfulPushAnswers201} — RFC 9126 &sect;2.2 specifies
 *       <em>Created</em>. A success predicate written {@code == 200} passes
 *       every other test in this file and treats every real push as a failure.
 *   <li>{@code theRedirectUrlCarriesExactlyTwoParameters} — the server refuses
 *       a request that mixes a {@code request_uri} with inline authorization
 *       parameters rather than merging them, and merging is where parameter
 *       confusion lives (&sect;26.2 rule 2).
 * </ul>
 */
class AxiamClientParTest {

    private static final UUID TENANT_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final String REDIRECT_URI = "https://app.example.com/callback";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c";

    private static AxiamClient client(String base) {
        return AxiamClient.builder(base, TENANT_ID.toString())
                .oidcClientId("app")
                .oidcClientSecret("s3cret")
                .build();
    }

    private static MockResponse parResponse() {
        return new MockResponse()
                .setResponseCode(201)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"request_uri\":\"" + REQUEST_URI + "\",\"expires_in\":90}");
    }

    private static Map<String, String> form(RecordedRequest request) {
        Map<String, String> fields = new HashMap<>();
        for (String pair : request.getBody().readUtf8().split("&")) {
            int eq = pair.indexOf('=');
            fields.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return fields;
    }

    /** Drive discovery, then {@code oidcBegin}, leaving PAR as the next call. */
    private static AuthorizationRequest begin(MockWebServer server, AxiamClient client) throws Exception {
        server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
        OidcConfiguration config = client.oidcDiscover();
        server.takeRequest();
        return client.oidcBegin(config, REDIRECT_URI);
    }

    // -----------------------------------------------------------------------
    // §26.1 — the push
    // -----------------------------------------------------------------------

    @Test
    void aSuccessfulPushAnswers201() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                PushedAuthorizationRequest pushed =
                        client.oidcPar(null, begun, REDIRECT_URI, "openid profile", null);

                assertEquals(REQUEST_URI, pushed.requestUri().expose());
                assertEquals(90, pushed.expiresIn());
            }
        }
    }

    @Test
    void thePushGoesToTheDiscoveredEndpointWithTheTenantQuery() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                client.oidcPar(null, begun, REDIRECT_URI, null, null);

                RecordedRequest request = server.takeRequest();
                assertEquals("POST", request.getMethod());
                HttpUrl url = Objects.requireNonNull(request.getRequestUrl());
                assertEquals("/oauth2/par", url.encodedPath());
                // §12.1 rule 2: /oauth2/* carries the tenant as a query
                // parameter, and PAR is one of those endpoints.
                assertEquals(TENANT_ID.toString(), url.queryParameter("tenant_id"));
            }
        }
    }

    @Test
    void thePushCarriesEverythingOidcBeginComputedAndGeneratesNothingNew() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                PushedAuthorizationRequest pushed =
                        client.oidcPar(null, begun, REDIRECT_URI, "openid profile", null);

                Map<String, String> fields = form(server.takeRequest());
                // §26.2 rule 1: no second generator. state, nonce and the PKCE
                // pair all come from the AuthorizationRequest that was pushed —
                // two sources for any of them are two things that can disagree.
                assertEquals(begun.state(), fields.get("state"));
                assertEquals(begun.nonce(), fields.get("nonce"));
                assertEquals(begun.state(), pushed.state());
                assertEquals(begun.nonce(), pushed.nonce());
                assertEquals(begun.codeVerifier().expose(), pushed.codeVerifier().expose());

                assertEquals("app", fields.get("client_id"));
                assertEquals("code", fields.get("response_type"));
                assertEquals(REDIRECT_URI, fields.get("redirect_uri"));
                assertEquals("openid profile", fields.get("scope"));
                assertEquals("S256", fields.get("code_challenge_method"));
                assertNotNull(fields.get("code_challenge"));
            }
        }
    }

    @Test
    void aConfidentialClientAuthenticatesThePush() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                client.oidcPar(null, begun, REDIRECT_URI, null, null);

                assertEquals("s3cret", form(server.takeRequest()).get("client_secret"));
            }
        }
    }

    @Test
    void aPublicClientPushesWithoutASecret() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            String base = server.url("/").toString();
            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID.toString())
                    .oidcClientId("spa").build()) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                client.oidcPar(null, begun, REDIRECT_URI, null, null);

                assertTrue(form(server.takeRequest()).get("client_secret") == null,
                        "a public client has no secret to send");
            }
        }
    }

    @Test
    void openidIsAddedToAScopeThatOmitsIt() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                client.oidcPar(null, begun, REDIRECT_URI, "profile email", null);

                String scope = form(server.takeRequest()).get("scope");
                assertTrue(Set.of(Objects.requireNonNull(scope).split(" ")).contains("openid"),
                        "an OIDC request without the openid scope is not an OIDC request: " + scope);
            }
        }
    }

    // -----------------------------------------------------------------------
    // §26.2 rule 2 — the redirect URL
    // -----------------------------------------------------------------------

    @Test
    void theRedirectUrlCarriesExactlyTwoParameters() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                PushedAuthorizationRequest pushed =
                        client.oidcPar(null, begun, REDIRECT_URI, "openid", null);

                HttpUrl url = Objects.requireNonNull(HttpUrl.parse(pushed.url()));
                assertEquals(Set.of("client_id", "request_uri"), url.queryParameterNames(),
                        "the server REFUSES a request_uri mixed with inline parameters rather "
                                + "than merging them — re-adding scope/state/redirect_uri here "
                                + "restores the parameter-confusion attack (§26.2 rule 2)");
                assertEquals("app", url.queryParameter("client_id"));
                assertEquals(REQUEST_URI, url.queryParameter("request_uri"));
                assertEquals("/oauth2/authorize", url.encodedPath());
            }
        }
    }

    @Test
    void theRedirectUrlDropsAnyQueryTheDiscoveredEndpointCarried() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                String base = server.url("/").toString();
                String trimmed = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
                // An authorization_endpoint that already carries a query is
                // legal, and its parameters are exactly the ones rule 2 forbids
                // travelling alongside a request_uri.
                OidcConfiguration config = new OidcConfiguration(
                        trimmed, trimmed + "/oauth2/authorize?audience=legacy&scope=all",
                        trimmed + "/oauth2/token", trimmed + "/oauth2/userinfo",
                        trimmed + "/oauth2/jwks", trimmed + "/oauth2/revoke",
                        trimmed + "/oauth2/introspect",
                        java.util.List.of("code"), java.util.List.of("public"),
                        java.util.List.of("EdDSA"), java.util.List.of("openid"),
                        java.util.List.of("client_secret_post"), java.util.List.of(),
                        java.util.List.of("authorization_code"),
                        null, trimmed + "/oauth2/par", null, false, false);

                AuthorizationRequest begun = client.oidcBegin(config, REDIRECT_URI);
                server.enqueue(parResponse());

                PushedAuthorizationRequest pushed =
                        client.oidcPar(config, begun, REDIRECT_URI, "openid", null);

                HttpUrl url = Objects.requireNonNull(HttpUrl.parse(pushed.url()));
                assertEquals(Set.of("client_id", "request_uri"), url.queryParameterNames());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §26.1 / §26.2 — refusals
    // -----------------------------------------------------------------------

    @Test
    void aServerWithoutParIsRefusedClientSideWithNoWireCall() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(OidcTestSupport.discoveryResponseWithoutOptionalEndpoints(
                        server.url("/").toString()));
                OidcConfiguration config = client.oidcDiscover();
                server.takeRequest();
                AuthorizationRequest begun = client.oidcBegin(config, REDIRECT_URI);
                int before = server.getRequestCount();

                AuthError error = assertThrows(AuthError.class,
                        () -> client.oidcPar(config, begun, REDIRECT_URI, "openid", null));
                assertTrue(error.getMessage().contains("pushed_authorization_request_endpoint"));

                // §12.7.2 rule 1: no URL is concatenated onto the issuer.
                assertEquals(0, server.getRequestCount() - before);
            }
        }
    }

    @Test
    void anOAuthErrorBodyBecomesAnOAuthProtocolError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(OidcTestSupport.oauthError(400, "invalid_request_uri"));

                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.oidcPar(null, begun, REDIRECT_URI, "openid", null));
                assertEquals("invalid_request_uri", error.error());
            }
        }
    }

    @Test
    void a503IsNotRetried() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                int before = server.getRequestCount();
                server.enqueue(new MockResponse().setResponseCode(503).setBody("{}"));

                assertThrows(NetworkError.class,
                        () -> client.oidcPar(null, begun, REDIRECT_URI, "openid", null));

                // §26.2 rule 4: a POST that creates server state falls outside
                // §16.2's read-only eligibility. The safe recovery is a fresh
                // push, which cannot double-consume anything.
                assertEquals(1, server.getRequestCount() - before, "the push must not be retried");
            }
        }
    }

    @Test
    void parRefusesOnAClosedClient() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            AxiamClient client = client(server.url("/").toString());
            AuthorizationRequest begun = begin(server, client);
            client.close();

            assertThrows(NetworkError.class,
                    () -> client.oidcPar(null, begun, REDIRECT_URI, "openid", null));
        }
    }

    // -----------------------------------------------------------------------
    // §26.5 / discovery / async
    // -----------------------------------------------------------------------

    @Test
    void theRequestUriIsSensitive() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                PushedAuthorizationRequest pushed =
                        client.oidcPar(null, begun, REDIRECT_URI, "openid", null);

                // Between the push and the redirect it is a bearer handle to a
                // fully-formed authorization request (§26.5). The URL it goes
                // into is not secret; the bare handle in a log line is.
                assertTrue(pushed.requestUri().toString().contains("REDACTED")
                                || !pushed.requestUri().toString().contains(REQUEST_URI),
                        "the handle must not survive into a naive toString(): "
                                + pushed.requestUri());
            }
        }
    }

    @Test
    void discoveryExposesThePushedAuthorizationRequestEndpoint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));

                OidcConfiguration config = client.oidcDiscover();

                String base = server.url("/").toString();
                String trimmed = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
                assertEquals(trimmed + "/oauth2/par", config.pushed_authorization_request_endpoint());
            }
        }
    }

    @Test
    void aDiscoveryDocumentWithoutParParsesWithANullEndpoint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(OidcTestSupport.discoveryResponseWithoutOptionalEndpoints(
                        server.url("/").toString()));

                OidcConfiguration config = client.oidcDiscover();

                // Absent, not empty: §26 is optional, and an SDK that
                // synthesized an endpoint here would POST a fully-formed
                // authorization request at a 404.
                assertTrue(config.pushed_authorization_request_endpoint() == null);
            }
        }
    }

    @Test
    void theAsyncTwinPushesTheSameRequest() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                PushedAuthorizationRequest pushed =
                        client.oidcParAsync(null, begun, REDIRECT_URI, "openid", null).join();

                assertEquals(REQUEST_URI, pushed.requestUri().expose());
                assertEquals("/oauth2/par",
                        Objects.requireNonNull(server.takeRequest().getRequestUrl()).encodedPath());
            }
        }
    }

    @Test
    void anExplicitTenantOverridesTheClientTenant() throws Exception {
        UUID other = UUID.fromString("44444444-4444-4444-4444-444444444444");
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                AuthorizationRequest begun = begin(server, client);
                server.enqueue(parResponse());

                client.oidcPar(null, begun, REDIRECT_URI, "openid", other);

                assertEquals(other.toString(), Objects.requireNonNull(
                        server.takeRequest().getRequestUrl()).queryParameter("tenant_id"));
            }
        }
    }

    @Test
    void parDiscoversWhenGivenNoConfiguration() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
                OidcConfiguration config = client.oidcDiscover();
                server.takeRequest();
                AuthorizationRequest begun = client.oidcBegin(config, REDIRECT_URI);

                // The document is cached per origin (§12.3 rule 6), so passing
                // null costs no second fetch.
                server.enqueue(parResponse());
                client.oidcPar(null, begun, REDIRECT_URI, "openid", null);

                assertEquals("/oauth2/par",
                        Objects.requireNonNull(server.takeRequest().getRequestUrl()).encodedPath());
                assertEquals(2, server.getRequestCount());
            }
        }
    }
}
