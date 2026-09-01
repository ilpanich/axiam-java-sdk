package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.oidc.FederationProvider;
import io.axiam.sdk.oidc.FederationProviderList;
import io.axiam.sdk.oidc.SsoCompleteResult;
import io.axiam.sdk.oidc.SsoStartResult;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The four public "Sign in with X" operations added by contract 1.38 —
 * {@code ssoProviders}, {@code ssoStartOauth2}, {@code ssoCompleteOauth2} and
 * {@code ssoCompleteHandoff} (CONTRACT.md &sect;12.1).
 *
 * <p>Two kinds of assertion live here, and both are needed.
 *
 * <p>The <strong>wire-shape</strong> tests read the vendored
 * {@code openapi.json} and assert the method, path, content type and — for
 * {@code ssoProviders} — the <em>parameter location</em> the server declares,
 * then assert that what this SDK actually puts on the wire matches. Asserting
 * only against the mock would pin the SDK to the test's own idea of the
 * endpoint; asserting only against the spec would not notice an SDK that agrees
 * with the spec and calls something else.
 *
 * <p>The <strong>rule</strong> tests cover the four &sect;12.1 notes easiest to
 * get quietly wrong: note 9 (an empty provider list is a success, not a
 * not-found), note 10 ({@code protocol} selects the start operation), note 12
 * (a handoff {@code 401} is terminal and is never retried) and rule 12a (a
 * {@code 400} from a start call is a configuration refusal, not something to
 * retry).
 */
class AxiamClientLoginProvidersTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";
    private static final String CONFIG_ID = "55555555-5555-5555-5555-555555555555";
    private static final String REDIRECT_URI = "https://app.example.com/sso-cb";

    private static final String PROVIDERS_PATH = "/api/v1/auth/federation/providers";
    private static final String OIDC_START_PATH = "/api/v1/auth/federation/oidc/start";
    private static final String OAUTH2_START_PATH = "/api/v1/auth/federation/oauth2/start";
    private static final String OAUTH2_CALLBACK_PATH = "/api/v1/auth/federation/oauth2/callback";
    private static final String HANDOFF_PATH = "/api/v1/auth/federation/handoff";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode openApi() throws Exception {
        return MAPPER.readTree(Files.readString(Path.of("openapi.json")));
    }

    private static MockResponse json(int code, String body) {
        return new MockResponse()
                .setResponseCode(code)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    /** A 200 delivering the session as Set-Cookie, exactly as the login endpoint does. */
    private static MockResponse sessionResponse() {
        return json(200, "{\"user_id\":\"99999999-8888-7777-6666-555555555555\","
                + "\"session_id\":\"12121212-3434-5656-7878-909090909090\","
                + "\"expires_in\":900,\"redirect_uri\":\"" + REDIRECT_URI + "\"}")
                .addHeader("Set-Cookie", "axiam_access=federation-access; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_csrf=federation-csrf; Path=/");
    }

    private static AxiamClient client(MockWebServer server) {
        return AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                .orgId(UUID.fromString(ORG_ID))
                .build();
    }

    // -----------------------------------------------------------------------
    // Wire shape, against openapi.json
    // -----------------------------------------------------------------------

    @Test
    void openApiDeclaresSsoProvidersAsAGetWithNoBody() throws Exception {
        JsonNode operation = openApi().path("paths").path(PROVIDERS_PATH).path("get");
        assertFalse(operation.isMissingNode(), "openapi.json must declare GET " + PROVIDERS_PATH);
        assertTrue(operation.path("requestBody").isMissingNode(),
                "ssoProviders is a GET and must have no request body (§12.1)");
        assertEquals("#/components/schemas/PublicFederationProvidersResponse",
                operation.path("responses").path("200").path("content")
                        .path("application/json").path("schema").path("$ref").asText());
    }

    @Test
    void openApiDeclaresTheThreePostsWithTheirContractSchemas() throws Exception {
        JsonNode paths = openApi().path("paths");
        String[][] cases = {
            {OAUTH2_START_PATH, "OAuth2StartRequest", "OAuth2StartResponse"},
            {OAUTH2_CALLBACK_PATH, "OAuth2CallbackRequest", "SsoLoginSuccessResponse"},
            {HANDOFF_PATH, "SsoHandoffRequest", "SsoLoginSuccessResponse"},
        };
        for (String[] c : cases) {
            JsonNode operation = paths.path(c[0]).path("post");
            assertFalse(operation.isMissingNode(), "openapi.json must declare POST " + c[0]);
            assertEquals("#/components/schemas/" + c[1],
                    operation.path("requestBody").path("content").path("application/json")
                            .path("schema").path("$ref").asText(),
                    c[0] + " must carry the " + c[1] + " body §12.1 names");
            assertEquals("#/components/schemas/" + c[2],
                    operation.path("responses").path("200").path("content")
                            .path("application/json").path("schema").path("$ref").asText());
        }
    }

    /**
     * &sect;12.1: the provider identifiers are <strong>query</strong>
     * parameters. Asserted because the neighbouring start operations take the
     * same four in a JSON body, and the two are one copy-paste apart.
     */
    @Test
    void openApiPutsTheProviderIdentifiersInTheQueryString() throws Exception {
        List<String> names = new ArrayList<>();
        for (JsonNode parameter : openApi().path("paths").path(PROVIDERS_PATH).path("get").path("parameters")) {
            assertEquals("query", parameter.path("in").asText(),
                    parameter.path("name").asText() + " must be a query parameter, not a body field");
            names.add(parameter.path("name").asText());
        }
        Collections.sort(names);
        assertEquals(List.of("org_id", "org_slug", "tenant_id", "tenant_slug"), names);
    }

    /**
     * The six required fields plus the nullable {@code button_icon}, and none of
     * the configuration a narrowed admin response would have leaked
     * (&sect;12.1 note 9).
     */
    @Test
    void openApiPublicProviderShapeMatchesTheSdkRecord() throws Exception {
        JsonNode schema = openApi().path("components").path("schemas").path("PublicFederationProvider");
        List<String> required = new ArrayList<>();
        schema.path("required").forEach(node -> required.add(node.asText()));
        Collections.sort(required);
        assertEquals(List.of("display_name", "has_bundled_mark", "id", "inherited", "protocol", "provider_kind"),
                required);

        JsonNode properties = schema.path("properties");
        assertFalse(properties.path("button_icon").isMissingNode(),
                "button_icon is part of the shape even though it is nullable");
        boolean nullable = false;
        for (JsonNode type : properties.path("button_icon").path("type")) {
            nullable |= "null".equals(type.asText());
        }
        assertTrue(nullable, "button_icon must be nullable — absent for most providers");

        for (String absent : List.of("client_id", "client_secret", "metadata_url", "token_endpoint")) {
            assertTrue(properties.path(absent).isMissingNode(),
                    "the unauthenticated provider response must not carry " + absent);
        }
    }

    /**
     * &sect;12.1 note 11: the verifier is generated and held server-side, so
     * neither schema carries PKCE material and neither may the SDK.
     */
    @Test
    void openApiOauth2StartCarriesNoPkceMaterial() throws Exception {
        JsonNode schemas = openApi().path("components").path("schemas");
        for (String name : List.of("OAuth2StartRequest", "OAuth2StartResponse")) {
            JsonNode properties = schemas.path(name).path("properties");
            for (String pkce : List.of("code_verifier", "code_challenge", "code_challenge_method")) {
                assertTrue(properties.path(pkce).isMissingNode(),
                        name + " must not carry " + pkce + ": PKCE is server-side here (§12.1 note 11)");
            }
        }
    }

    // -----------------------------------------------------------------------
    // ssoProviders — wire shape and §12.1 note 9
    // -----------------------------------------------------------------------

    @Test
    void ssoProvidersSendsIdentifiersAsQueryParametersAndNoBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"providers\":[]}"));
            server.start();

            // A slug-configured client, so the slug forms are what resolve. The
            // UUID form wins when both are available, exactly as it does for
            // ssoStart — the four new operations do not invent a new rule.
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme")
                    .orgSlug("acme-org")
                    .build()) {
                client.ssoProviders(null, "other-org", null, "engineering");
            }

            RecordedRequest request = server.takeRequest();
            assertEquals("GET", request.getMethod());
            assertEquals(PROVIDERS_PATH, request.getRequestUrl().encodedPath());
            assertEquals("other-org", request.getRequestUrl().queryParameter("org_slug"));
            assertEquals("engineering", request.getRequestUrl().queryParameter("tenant_slug"));
            // An unset identifier is omitted, not sent empty.
            assertNull(request.getRequestUrl().queryParameter("org_id"));
            assertNull(request.getRequestUrl().queryParameter("tenant_id"));
            assertEquals(0L, request.getBodySize(), "ssoProviders is a GET with no body (§12.1)");
        }
    }

    @Test
    void ssoProvidersDefaultsTheWorkspaceFromClientConfiguration() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"providers\":[]}"));
            server.start();

            try (AxiamClient client = client(server)) {
                client.ssoProviders();
            }

            RecordedRequest request = server.takeRequest();
            assertEquals(ORG_ID, request.getRequestUrl().queryParameter("org_id"));
            assertEquals(TENANT_ID, request.getRequestUrl().queryParameter("tenant_id"));
        }
    }

    /**
     * &sect;12.1 note 9. The three cases the endpoint makes indistinguishable —
     * unknown organization, known-but-empty, and no workspace named — are all
     * ordinary successes. Mapping any of them to an error would restore the
     * two-valued answer the empty list removes, and with it the
     * organization-slug oracle.
     */
    @Test
    void anEmptyProviderListIsASuccessNotAnError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            for (int i = 0; i < 3; i++) {
                server.enqueue(json(200, "{\"providers\":[]}"));
            }
            server.start();

            try (AxiamClient client = client(server)) {
                assertTrue(client.ssoProviders(null, "no-such-organization", null, null).providers().isEmpty());
                assertTrue(client.ssoProviders(UUID.fromString(ORG_ID), null,
                        UUID.fromString(TENANT_ID), null).providers().isEmpty());
                assertTrue(client.ssoProviders().providers().isEmpty());
            }
        }
    }

    /**
     * The consequence of note 9 easiest to get wrong: unlike the start
     * operations, a request resolving no organization is <strong>sent</strong>
     * rather than refused client-side. A {@code 400} for "you named nothing"
     * against a {@code 200 []} for an unknown slug would be that same
     * two-valued answer by another route.
     */
    @Test
    void ssoProvidersSendsTheRequestEvenWithNoOrganizationContext() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"providers\":[]}"));
            server.start();

            // No orgId/orgSlug configured: ssoStart refuses this client-side.
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                assertThrows(AuthError.class, () -> client.ssoStart(CONFIG_ID, REDIRECT_URI));
                assertTrue(client.ssoProviders().providers().isEmpty());
            }

            assertEquals(1, server.getRequestCount(), "only ssoProviders may reach the wire");
            assertEquals(PROVIDERS_PATH, server.takeRequest().getRequestUrl().encodedPath());
        }
    }

    @Test
    void ssoProvidersMapsEveryFieldIncludingTheNullableButtonIcon() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"providers\":["
                    + "{\"id\":\"11111111-1111-1111-1111-111111111111\",\"provider_kind\":\"google\","
                    + "\"display_name\":\"Google\",\"protocol\":\"OidcConnect\",\"has_bundled_mark\":true,"
                    + "\"inherited\":true,\"button_icon\":null},"
                    + "{\"id\":\"22222222-2222-2222-2222-222222222222\",\"provider_kind\":\"generic_oauth2\","
                    + "\"display_name\":\"Acme SSO\",\"protocol\":\"OAuth2\",\"has_bundled_mark\":false,"
                    + "\"inherited\":false,\"button_icon\":\"data:image/png;base64,iVBORw0KGgo=\"}]}"));
            server.start();

            try (AxiamClient client = client(server)) {
                FederationProviderList list = client.ssoProviders();
                assertEquals(2, list.providers().size());

                FederationProvider google = list.providers().get(0);
                assertEquals("google", google.providerKind());
                assertEquals(FederationProvider.PROTOCOL_OIDC_CONNECT, google.protocol());
                assertTrue(google.hasBundledMark());
                // Reported so an admin surface can show that a provider is not
                // the tenant's to edit; nothing here computes it (§12.1 note 13).
                assertTrue(google.inherited());
                assertNull(google.buttonIcon(), "button_icon is absent for most providers");

                FederationProvider acme = list.providers().get(1);
                assertEquals(FederationProvider.PROTOCOL_OAUTH2, acme.protocol());
                assertFalse(acme.hasBundledMark());
                assertEquals("data:image/png;base64,iVBORw0KGgo=", acme.buttonIcon());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §12.1 note 10 — protocol selects the start operation
    // -----------------------------------------------------------------------

    /**
     * All three branches, asserted on which endpoint the resulting call
     * reached.
     *
     * <p>{@code provider_kind} is deliberately misleading in this fixture: the
     * {@code Saml} row is {@code google}, the kind whose OIDC connector
     * everybody assumes. A dispatch that read the kind would send it to the
     * OIDC start endpoint and be caught by the recorded-path assertion.
     */
    @Test
    void protocolSelectsTheStartOperationForAllThreeBranches() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"providers\":["
                    + "{\"id\":\"11111111-1111-1111-1111-111111111111\",\"provider_kind\":\"microsoft\","
                    + "\"display_name\":\"Microsoft\",\"protocol\":\"OidcConnect\",\"has_bundled_mark\":true,\"inherited\":false},"
                    + "{\"id\":\"22222222-2222-2222-2222-222222222222\",\"provider_kind\":\"github\","
                    + "\"display_name\":\"GitHub\",\"protocol\":\"OAuth2\",\"has_bundled_mark\":true,\"inherited\":false},"
                    + "{\"id\":\"33333333-3333-3333-3333-333333333333\",\"provider_kind\":\"google\","
                    + "\"display_name\":\"Corporate SAML\",\"protocol\":\"Saml\",\"has_bundled_mark\":true,\"inherited\":false}]}"));
            String start = "{\"authorize_url\":\"https://upstream.example.com/authorize\","
                    + "\"state\":\"dispatch-state\",\"expires_in_secs\":600}";
            server.enqueue(json(200, start));
            server.enqueue(json(200, start));
            server.start();

            boolean samlSeen = false;
            try (AxiamClient client = client(server)) {
                for (FederationProvider provider : client.ssoProviders().providers()) {
                    switch (provider.protocol()) {
                        case FederationProvider.PROTOCOL_OIDC_CONNECT ->
                                client.ssoStart(provider.id(), REDIRECT_URI);
                        case FederationProvider.PROTOCOL_OAUTH2 ->
                                client.ssoStartOauth2(provider.id(), REDIRECT_URI);
                        case FederationProvider.PROTOCOL_SAML ->
                                // Saml goes to the SAML login endpoint, which §12.1 note 10
                                // says is NOT a §12 vocabulary operation. The branch exists
                                // so a Saml provider is never quietly handed to one of the
                                // other two.
                                samlSeen = true;
                        default -> throw new AssertionError("unknown protocol " + provider.protocol());
                    }
                }
            }
            assertTrue(samlSeen, "the Saml branch must be reachable");

            assertEquals(3, server.getRequestCount(), "the Saml provider must reach neither start endpoint");
            assertEquals(PROVIDERS_PATH, server.takeRequest().getRequestUrl().encodedPath());
            assertEquals(OIDC_START_PATH, server.takeRequest().getPath());
            assertEquals(OAUTH2_START_PATH, server.takeRequest().getPath());
        }
    }

    // -----------------------------------------------------------------------
    // ssoStartOauth2
    // -----------------------------------------------------------------------

    @Test
    void ssoStartOauth2PostsTheBodyAndSendsNoPkce() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"authorize_url\":\"https://github.com/login/oauth/authorize\","
                    + "\"state\":\"abc\",\"expires_in_secs\":600}"));
            server.start();

            try (AxiamClient client = client(server)) {
                SsoStartResult result = client.ssoStartOauth2(CONFIG_ID, REDIRECT_URI);
                assertEquals("abc", result.state());
                assertEquals(600, result.expiresInSecs());
            }

            RecordedRequest request = server.takeRequest();
            assertEquals(OAUTH2_START_PATH, request.getPath());
            assertEquals("application/json; charset=utf-8", request.getHeader("Content-Type"));
            String body = request.getBody().readUtf8();
            assertTrue(body.contains("\"federation_config_id\":\"" + CONFIG_ID + "\""));
            assertTrue(body.contains("\"redirect_uri\":\"" + REDIRECT_URI + "\""));
            assertTrue(body.contains("\"tenant_id\":\"" + TENANT_ID + "\""));
            assertTrue(body.contains("\"org_id\":\"" + ORG_ID + "\""));
            // §12.1 note 11: the verifier is server-side. Its absence is the contract.
            for (String pkce : List.of("code_verifier", "code_challenge", "code_challenge_method")) {
                assertFalse(body.contains(pkce), "the SDK must not send " + pkce);
            }
        }
    }

    @Test
    void ssoStartOauth2RefusesClientSideWithoutOrgContext() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                AuthError error = assertThrows(AuthError.class,
                        () -> client.ssoStartOauth2(CONFIG_ID, REDIRECT_URI));
                assertTrue(error.getMessage().contains("organization context"));
            }
            assertEquals(0, server.getRequestCount(), "no wire call may be made");
        }
    }

    // -----------------------------------------------------------------------
    // §12.1 rule 12a — a 400 from a start call is a configuration refusal
    // -----------------------------------------------------------------------

    /**
     * On the SAML and Apple flows the identity provider never validates the SPA
     * {@code redirect_uri}, so the server confines it to its own issuer origin
     * plus {@code AXIAM__AUTH__SSO_SPA_ORIGINS} and answers {@code 400}
     * otherwise.
     *
     * <p>That {@code 400} is a <strong>configuration</strong> refusal —
     * &sect;2's {@code 400} row, whose taxonomy member in this SDK is
     * {@link NetworkError} ("malformed request / SDK programming error"), as
     * distinct from the {@link AuthError} an unknown workspace gets. It must not
     * be retried: the deployment will refuse the same origin every time.
     *
     * <p>Asserted on both start operations, because Apple arrives over the OIDC
     * one and a caller can reach the refusal from either entry point.
     */
    @Test
    void a400FromEitherStartCallIsAConfigurationErrorAndIsNotRetried() throws Exception {
        for (boolean oauth2 : new boolean[] {false, true}) {
            try (MockWebServer server = new MockWebServer()) {
                server.enqueue(json(400, "{\"message\":\"redirect_uri origin is not permitted\"}"));
                server.start();

                try (AxiamClient client = client(server)) {
                    assertThrows(NetworkError.class, () -> {
                        if (oauth2) {
                            client.ssoStartOauth2(CONFIG_ID, "https://attacker.example/");
                        } else {
                            client.ssoStart(CONFIG_ID, "https://attacker.example/");
                        }
                    }, "rule 12a: a 400 is a configuration refusal, not an authentication outcome");
                }

                assertEquals(1, server.getRequestCount(),
                        "rule 12a: the refusal must not be retried — the origin will be refused again");
                assertEquals(oauth2 ? OAUTH2_START_PATH : OIDC_START_PATH, server.takeRequest().getPath());
            }
        }
    }

    /**
     * A {@code 401} is the uniform "unknown workspace or provider" answer, and a
     * <em>different</em> taxonomy member from the rule-12a {@code 400}.
     * Asserted so the two cannot quietly collapse into one.
     */
    @Test
    void a401FromAStartCallStaysAnAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(401, "{\"message\":\"unauthorized\"}"));
            server.start();
            try (AxiamClient client = client(server)) {
                assertThrows(AuthError.class, () -> client.ssoStartOauth2(CONFIG_ID, REDIRECT_URI));
            }
        }
    }

    // -----------------------------------------------------------------------
    // The two completions, and §12.1 note 12
    // -----------------------------------------------------------------------

    @Test
    void ssoCompleteOauth2PostsStateAndCodeAndMapsTheSuccessBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(sessionResponse());
            server.start();

            try (AxiamClient client = client(server)) {
                SsoCompleteResult result = client.ssoCompleteOauth2("abc", "provider-code");
                assertEquals("99999999-8888-7777-6666-555555555555", result.userId());
                assertEquals(900, result.expiresIn());
                assertEquals(REDIRECT_URI, result.redirectUri());
            }

            RecordedRequest request = server.takeRequest();
            assertEquals(OAUTH2_CALLBACK_PATH, request.getPath());
            assertEquals("{\"state\":\"abc\",\"code\":\"provider-code\"}", request.getBody().readUtf8());
        }
    }

    @Test
    void ssoCompleteHandoffPostsJustTheCode() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(sessionResponse());
            server.start();

            try (AxiamClient client = client(server)) {
                SsoCompleteResult result = client.ssoCompleteHandoff("handoff-code");
                assertNotNull(result);
                assertEquals("12121212-3434-5656-7878-909090909090", result.sessionId());
            }

            RecordedRequest request = server.takeRequest();
            assertEquals(HANDOFF_PATH, request.getPath());
            assertEquals("{\"code\":\"handoff-code\"}", request.getBody().readUtf8());
        }
    }

    /**
     * &sect;12.1 note 12. Unknown, expired and already-redeemed all answer the
     * same {@code 401}, on purpose. The code is spent either way, so a retry
     * cannot succeed and would only widen the window in which it sits in a log.
     */
    @Test
    void aHandoff401IsTerminalAndIsNotRetried() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(401, "{\"message\":\"unauthorized\"}"));
            server.start();

            try (AxiamClient client = client(server)) {
                assertThrows(AuthError.class,
                        () -> client.ssoCompleteHandoff("spent-or-expired-or-never-existed"));
            }

            assertEquals(1, server.getRequestCount(),
                    "the redemption must not be retried: the code is gone either way");
        }
    }

    /**
     * The two values a caller codes against: it reads the code out of
     * {@code ?axiam_handoff=} and has 60 seconds to spend it.
     */
    @Test
    void theHandoffParameterAndTtlAreWhatTheContractSays() {
        assertEquals("axiam_handoff", FederationProviderList.HANDOFF_QUERY_PARAM);
        assertEquals(60L, FederationProviderList.HANDOFF_CODE_TTL_SECONDS);
    }

    /**
     * &sect;12.2's Java note permits {@code *Async} companions on the same
     * client object. All four have one, and each delegates to the synchronous
     * method rather than duplicating it.
     */
    @Test
    void theAsyncCompanionsExistAndDelegate() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(200, "{\"providers\":[]}"));
            server.enqueue(json(200, "{\"authorize_url\":\"https://gh/x\",\"state\":\"s\",\"expires_in_secs\":600}"));
            server.enqueue(sessionResponse());
            server.enqueue(sessionResponse());
            server.start();

            try (AxiamClient client = client(server)) {
                assertTrue(client.ssoProvidersAsync().get().providers().isEmpty());
                assertEquals("s", client.ssoStartOauth2Async(CONFIG_ID, REDIRECT_URI).get().state());
                assertEquals(900, client.ssoCompleteOauth2Async("s", "c").get().expiresIn());
                assertEquals(900, client.ssoCompleteHandoffAsync("h").get().expiresIn());
            }
        }
    }
}
