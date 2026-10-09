package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.oidc.ClientRegistration;
import io.axiam.sdk.testutil.Redaction;
import io.axiam.sdk.testutil.RouteServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static io.axiam.sdk.testutil.RouteServer.json;
import static io.axiam.sdk.testutil.RouteServer.status;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RFC 7592 client configuration &mdash; CONTRACT.md &sect;28.12.6's five required
 * tests (spread over eight methods, as the reference port does).
 *
 * <p>Every token is generated at run time: a literal would be a credential in
 * the repository, and the redaction test needs a value no fixture shares.
 */
class ClientRegistrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final UUID TENANT = UUID.randomUUID();
    private static final String CLIENT = "dcr-client-1";
    private static final String PATH = "/oauth2/register/" + CLIENT;

    private RouteServer server;

    @BeforeEach
    void start() throws Exception {
        server = new RouteServer();
    }

    @AfterEach
    void stop() throws Exception {
        server.close();
    }

    private static String freshToken() {
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "").substring(0, 11);
    }

    private String registrationUri() {
        return server.base() + PATH + "?tenant_id=" + TENANT;
    }

    private ObjectNode registrationBody() {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("client_id", CLIENT);
        body.put("client_id_issued_at", 1_700_000_000L);
        body.put("client_name", "Agent");
        body.putArray("redirect_uris").add("https://agent.example.test/cb");
        body.putArray("grant_types").add("authorization_code");
        body.putArray("response_types").add("code");
        body.put("token_endpoint_auth_method", "private_key_jwt");
        body.put("scope", "openid");
        body.put("registration_client_uri", registrationUri());
        body.put("jwks_uri", "https://agent.example.test/jwks");
        return body;
    }

    private AxiamClient client() {
        return AxiamClient.builder(server.base(), TENANT.toString()).build();
    }

    /** A client holding a real session (cookies, access token, CSRF token). */
    private AxiamClient loggedInClient() {
        server.mountLogin(TENANT);
        AxiamClient client = client();
        client.login("admin@example.test", UUID.randomUUID().toString());
        return client;
    }

    // ── 1. Origin refusal ────────────────────────────────────────────────

    @Test
    void aUriAtAnotherOriginIsRefusedLocallyAndNothingIsSent() {
        RouteServer.Route reads = server.on("GET", PATH, json(200, registrationBody().toString()));
        RouteServer.Route deletes = server.on("DELETE", PATH, status(204));
        RouteServer.Route puts = server.on("PUT", PATH, json(200, registrationBody().toString()));
        Sensitive token = Sensitive.of(freshToken());
        String otherHost = "localhost".equals(server.host()) ? "127.0.0.1" : "localhost";
        List<String> refused = List.of(
                "http://" + otherHost + ":" + server.port() + PATH,
                "http://" + server.host() + ":" + (server.port() + 1) + PATH,
                "ftp://" + server.host() + ":" + server.port() + PATH,
                "/oauth2/register/" + CLIENT,
                "::not a uri::");
        try (AxiamClient client = client()) {
            for (String uri : refused) {
                assertThrows(ValidationError.class, () -> client.readClientRegistration(uri, token));
                assertThrows(ValidationError.class, () -> client.deleteClientRegistration(uri, token));
                assertThrows(ValidationError.class, () -> client.updateClientRegistration(uri, token,
                        ClientRegistration.builder(CLIENT).build()));
            }
        }
        // http against an https base URL.
        try (AxiamClient https = AxiamClient.builder("https://iam.example.test", TENANT.toString()).build()) {
            assertThrows(ValidationError.class,
                    () -> https.readClientRegistration("http://iam.example.test/oauth2/register/x", token));
        }
        // An http base URL that is not loopback cannot reach an http URI either.
        try (AxiamClient plain = AxiamClient.builder("http://iam.internal:8080", TENANT.toString()).build()) {
            assertThrows(ValidationError.class,
                    () -> plain.readClientRegistration("http://iam.internal:8080/oauth2/register/x", token));
        }
        assertEquals(0, reads.calls() + deletes.calls() + puts.calls());
        assertTrue(server.unmatched().isEmpty(), "no request may reach the server");
    }

    // ── 2. Header only ───────────────────────────────────────────────────

    @Test
    void readAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim() throws Exception {
        RouteServer.Route reads = server.on("GET", PATH, json(200, registrationBody().toString()));
        RouteServer.Route deletes = server.on("DELETE", PATH, status(204));
        String token = freshToken();
        try (AxiamClient client = loggedInClient()) {
            String sessionAccess = server.lastAccessToken();
            ClientRegistration read = client.readClientRegistration(registrationUri(), Sensitive.of(token));
            assertEquals(CLIENT, read.clientId());
            assertNull(read.registrationAccessToken());
            client.deleteClientRegistrationAsync(registrationUri(), Sensitive.of(token)).get();

            for (RouteServer.Seen seen : List.of(reads.last(), deletes.last())) {
                assertEquals("Bearer " + token, seen.headers().get("Authorization"),
                        "the registration token, and only it, is the bearer");
                assertNull(seen.headers().get("Cookie"), "no session cookie");
                assertNull(seen.headers().get("X-CSRF-Token"), "no session CSRF header");
                assertFalse(seen.headers().toString().contains(sessionAccess), "never the SDK's access token");
                assertEquals("", seen.body(), "no body");
                assertEquals(java.util.Map.of("tenant_id", TENANT.toString()), seen.query(),
                        "the URI's own query, verbatim, and the token never in it");
            }
        }
    }

    // ── 3. Update body ───────────────────────────────────────────────────

    @Test
    void updateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken() throws Exception {
        String rotated = freshToken();
        ObjectNode answer = registrationBody();
        answer.put("registration_access_token", rotated);
        RouteServer.Route puts = server.on("PUT", PATH, json(200, answer.toString()));

        ObjectNode fromRead = registrationBody();
        fromRead.put("registration_access_token", freshToken());
        fromRead.put("client_secret", freshToken());
        fromRead.put("client_secret_expires_at", 0);
        fromRead.put("backchannel_token_delivery_mode", "poll");
        ClientRegistration metadata = ClientRegistration.fromJson(fromRead)
                .toBuilder().clientName("Agent v2").build();

        try (AxiamClient client = client()) {
            ClientRegistration updated = client.updateClientRegistrationAsync(
                    registrationUri(), Sensitive.of(freshToken()), metadata).get();
            assertTrue(rotated.equals(updated.registrationAccessToken().expose()),
                    "the rotated token is returned");
        }
        assertEquals(1, puts.calls());
        JsonNode sent = MAPPER.readTree(puts.last().body());
        for (String gone : List.of("registration_access_token", "registration_client_uri",
                "client_secret_expires_at", "client_id_issued_at", "client_secret")) {
            assertFalse(sent.has(gone), "a server-stated member must not be sent");
        }
        assertEquals(CLIENT, sent.path("client_id").asText());
        assertEquals("Agent v2", sent.path("client_name").asText());
        assertEquals("https://agent.example.test/jwks", sent.path("jwks_uri").asText());
        assertEquals("poll", sent.path("backchannel_token_delivery_mode").asText(), "unknown members round-trip");
        assertTrue(puts.last().headers().get("Content-Type").startsWith("application/json"));
    }

    @Test
    void anUpdateOrDeleteAnswered503IsNotRetriedAndAReadIs() {
        RouteServer.Route puts = server.on("PUT", PATH, status(503));
        RouteServer.Route deletes = server.on("DELETE", PATH, status(503));
        RouteServer.Route reads = server.on("GET", PATH, status(503));
        Sensitive token = Sensitive.of(freshToken());
        try (AxiamClient client = client()) {
            assertInstanceOf(NetworkError.class, assertThrows(RuntimeException.class,
                    () -> client.updateClientRegistration(registrationUri(), token,
                            ClientRegistration.fromJson(registrationBody()))));
            assertThrows(NetworkError.class, () -> client.deleteClientRegistration(registrationUri(), token));
            assertThrows(NetworkError.class, () -> client.readClientRegistration(registrationUri(), token));
        }
        assertEquals(1, puts.calls(), "update: exactly one request");
        assertEquals(1, deletes.calls(), "delete: exactly one request");
        assertTrue(reads.calls() > 1, "the read MAY be retried per §16");
    }

    @Test
    void aReadIsNotRetriedOnABodiless400() {
        RouteServer.Route reads = server.on("GET", PATH, status(400));
        try (AxiamClient client = client()) {
            java.util.concurrent.CompletionException e = assertThrows(java.util.concurrent.CompletionException.class,
                    () -> client.readClientRegistrationAsync(registrationUri(), Sensitive.of(freshToken())).join());
            assertInstanceOf(NetworkError.class, e.getCause());
        }
        assertEquals(1, reads.calls(), "a 4xx other than 408/429 is never retried");
    }

    // ── 4. Errors ────────────────────────────────────────────────────────

    @Test
    void a401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing() {
        RouteServer.Route refreshes = server.on("POST", "/api/v1/auth/refresh", status(500));
        server.on("GET", PATH, status(401)
                .setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"error\":\"invalid_token\",\"error_description\":\"no\"}"));
        try (AxiamClient client = loggedInClient()) {
            OAuthProtocolError e = assertThrows(OAuthProtocolError.class,
                    () -> client.readClientRegistration(registrationUri(), Sensitive.of(freshToken())));
            assertEquals("invalid_token", e.error());
        }
        assertEquals(0, refreshes.calls(), "§9 is not entered");
    }

    @Test
    void a400InvalidClientMetadataIsAnOAuthProtocolError() {
        server.on("PUT", PATH, json(400, "{\"error\":\"invalid_client_metadata\",\"error_description\":\"scope\"}"));
        try (AxiamClient client = client()) {
            OAuthProtocolError e = assertThrows(OAuthProtocolError.class,
                    () -> client.updateClientRegistration(registrationUri(), Sensitive.of(freshToken()),
                            ClientRegistration.fromJson(registrationBody())));
            assertEquals("invalid_client_metadata", e.error());
            assertEquals("scope", e.errorDescription());
        }
    }

    // ── 5. Redaction ─────────────────────────────────────────────────────

    @Test
    void neitherTheTokenNorTheSecretReachesAnyRendering() throws Exception {
        String token = freshToken();
        String secret = freshToken();
        ObjectNode body = registrationBody();
        body.put("registration_access_token", token);
        body.put("client_secret", secret);
        ClientRegistration registration = ClientRegistration.fromJson(body);
        String printed = registration.toString();
        String serialized = MAPPER.writeValueAsString(registration);
        for (String rendering : List.of(printed, serialized, registration.updateBody().toString())) {
            Redaction.assertNoFragment("registration rendering", rendering, token);
            Redaction.assertNoFragment("registration rendering", rendering, secret);
        }

        // An error raised by an operation given the token: a 401 whose body has
        // no error_description, and a local refusal.
        server.on("GET", PATH, json(401, "{\"error\":\"invalid_token\"}"));
        try (AxiamClient client = client()) {
            OAuthProtocolError e = assertThrows(OAuthProtocolError.class,
                    () -> client.readClientRegistration(registrationUri(), Sensitive.of(token)));
            assertNull(e.errorDescription(), "error_description is optional");
            Redaction.assertNoFragment("error", e + " " + e.getMessage(), token);
            ValidationError refused = assertThrows(ValidationError.class,
                    () -> client.readClientRegistration("https://elsewhere.example.test/r", Sensitive.of(token)));
            Redaction.assertNoFragment("refusal", refused + " " + refused.getMessage(), token);
            assertFalse(refused.getMessage().contains("elsewhere"), "the refusal names no part of the URI");
        }
    }

    /**
     * &sect;28.12.2 rule 4 as clarified by &sect;34.2 P12.4: the replacement is built from what
     * the read carried. A list the read lacked is not sent (never as {@code []}), a list the
     * read carried empty is sent empty, and a member of an unexpected shape is sent as read.
     */
    @Test
    void theReplacementCarriesOnlyWhatTheReadCarriedAndAsItWasRead() {
        ObjectNode lacking = registrationBody();
        lacking.remove(List.of("redirect_uris", "grant_types", "response_types"));
        ObjectNode sent = ClientRegistration.fromJson(lacking).updateBody();
        for (String list : List.of("redirect_uris", "grant_types", "response_types")) {
            assertFalse(sent.has(list), list + ": the read did not carry it, so it is not sent");
        }

        ObjectNode odd = registrationBody();
        odd.putArray("redirect_uris");
        odd.putArray("grant_types").add("client_credentials").add(7);
        odd.put("response_types", "code");
        ClientRegistration read = ClientRegistration.fromJson(odd);
        ObjectNode replacement = read.updateBody();
        assertEquals(odd.get("redirect_uris"), replacement.get("redirect_uris"), "an empty list stays empty");
        assertEquals(odd.get("grant_types"), replacement.get("grant_types"), "no item is dropped");
        assertEquals(odd.get("response_types"), replacement.get("response_types"), "kept as read");

        // A list the caller sets replaces what was read.
        ObjectNode changed = read.toBuilder().grantTypes(List.of("authorization_code")).build().updateBody();
        assertEquals(List.of("authorization_code"),
                MAPPER.convertValue(changed.get("grant_types"), List.class));
    }

    @Test
    void decodingIsTolerantAndRefusesWhatIsNotARegistration() {
        ObjectNode odd = registrationBody();
        odd.put("client_id_issued_at", "not-a-number");
        odd.putNull("jwks");
        odd.putObject("jwks_extra").put("k", 1);
        ClientRegistration r = ClientRegistration.fromJson(odd);
        assertEquals("not-a-number", r.extra().get("client_id_issued_at").asText(), "kept, not dropped");
        assertNull(r.jwks());
        assertFalse(r.updateBody().has("client_id_issued_at"), "a mistyped server-stated member is still dropped");
        ClientRegistration built = r.toBuilder().redirectUris(List.of("https://a/cb")).grantTypes(List.of("x"))
                .responseTypes(List.of("code")).tokenEndpointAuthMethod("none").scope("openid")
                .jwks(MAPPER.createObjectNode()).jwksUri(null).clientName(null)
                .extra("jwks_extra", null).extra("other", MAPPER.getNodeFactory().textNode("v")).build();
        assertEquals(List.of("https://a/cb"), built.redirectUris());
        assertFalse(built.extra().containsKey("jwks_extra"));
        assertTrue(built.updateBody().has("jwks"));
        assertThrows(NetworkError.class, () -> ClientRegistration.fromJson(MAPPER.createArrayNode()));
        assertThrows(NetworkError.class, () -> ClientRegistration.fromJson(MAPPER.createObjectNode()));
    }
}
