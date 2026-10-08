package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.oidc.CibaClock;
import io.axiam.sdk.oidc.CibaInitiateRequest;
import io.axiam.sdk.oidc.CibaInitiateResponse;
import io.axiam.sdk.oidc.CibaRequestSigner;
import io.axiam.sdk.oidc.CibaSigningAlg;
import io.axiam.sdk.oidc.CibaUserHint;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;
import io.axiam.sdk.testutil.Redaction;
import io.axiam.sdk.testutil.RouteServer;
import io.axiam.sdk.testutil.TestCerts;

import okhttp3.mockwebserver.MockResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static io.axiam.sdk.testutil.RouteServer.json;
import static io.axiam.sdk.testutil.RouteServer.status;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CIBA &mdash; CONTRACT.md &sect;33.8's sixteen required tests (nine initiation and
 * polling, four ping, three signed request), {@code t01}&ndash;{@code t16} as in
 * the reference port.
 *
 * <p>No credential, key or token literal: the client secret, the
 * {@code auth_req_id}, the notification token and every signing key are
 * generated at run time.
 */
class CibaTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
    private static final UUID TENANT = UUID.randomUUID();
    private static final String CLIENT_ID = "ciba-client";

    @TempDir
    Path tempDir;

    private RouteServer server;
    private final List<AxiamClient> clients = new ArrayList<>();

    @BeforeEach
    void start() throws Exception {
        server = new RouteServer();
    }

    @AfterEach
    void stop() throws Exception {
        clients.forEach(AxiamClient::close);
        server.close();
    }

    private static String random() {
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
    }

    private ObjectNode discovery(String bcAuthorize) {
        ObjectNode doc;
        try {
            doc = (ObjectNode) MAPPER.readTree(OidcTestSupport.discoveryResponse(server.base()).getBody().readUtf8());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        if (bcAuthorize != null) {
            doc.put("backchannel_authentication_endpoint", bcAuthorize);
        }
        doc.putArray("backchannel_token_delivery_modes_supported").add("poll").add("ping");
        doc.put("backchannel_user_code_parameter_supported", false);
        doc.putArray("backchannel_authentication_request_signing_alg_values_supported")
                .add("PS256").add("ES256").add("EdDSA");
        return doc;
    }

    /** The discovery document, decoded by the SDK itself. */
    private OidcConfiguration configuration() {
        server.on("GET", "/.well-known/openid-configuration",
                json(200, discovery(server.base() + "/oauth2/bc-authorize").toString()));
        AxiamClient discoverer = AxiamClient.builder(server.base(), TENANT.toString()).build();
        clients.add(discoverer);
        return discoverer.oidcDiscover();
    }

    /** A confidential client with a run-time secret. */
    private AxiamClient client(String secret) {
        AxiamClient c = AxiamClient.builder(server.base(), TENANT.toString())
                .oidcClientId(CLIENT_ID).oidcClientSecret(secret).build();
        clients.add(c);
        return c;
    }

    private CibaInitiateRequest.Builder request(OidcConfiguration config) {
        return CibaInitiateRequest.builder("openid profile", CibaUserHint.loginHint("ada")).configuration(config);
    }

    private static MockResponse oauthError(int status, String code) {
        return json(status, "{\"error\":\"" + code + "\",\"error_description\":\"" + code + " here\"}");
    }

    private static MockResponse initiated(String authReqId, Integer interval) {
        return json(200, "{\"auth_req_id\":\"" + authReqId + "\",\"expires_in\":120"
                + (interval == null ? "" : ",\"interval\":" + interval) + "}");
    }

    /** A 200 token response carrying a valid ID token, with the JWKS mounted. */
    private MockResponse tokensWithIdToken(OidcConfiguration config) throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("ciba-" + UUID.randomUUID());
        server.on("GET", "/oauth2/jwks", OidcTestSupport.jwksResponse(key.toPublicJWK()));
        String idToken = OidcTestSupport.signEdDsa(key,
                OidcTestSupport.validIdTokenClaims(config.issuer(), CLIENT_ID, null));
        return json(200, "{\"access_token\":\"" + random() + "\",\"token_type\":\"Bearer\",\"expires_in\":900,"
                + "\"scope\":\"openid profile\",\"id_token\":\"" + idToken + "\"}");
    }

    /** A clock that never sleeps: sleep advances it and records the wait. */
    static final class TestClock implements CibaClock {
        final Instant start = Instant.now();
        private Duration offset = Duration.ZERO;
        final List<Long> sleeps = Collections.synchronizedList(new ArrayList<>());

        synchronized Duration elapsed() {
            return offset;
        }

        @Override
        public synchronized Instant now() {
            return start.plus(offset);
        }

        @Override
        public synchronized void sleep(Duration d) {
            offset = offset.plus(d);
            sleeps.add(d.toSeconds());
        }
    }

    /** Token endpoint answered from {@code script} (last repeats), recording the clock at each request. */
    private RouteServer.Route tokenScript(TestClock clock, List<Long> at, MockResponse... script) {
        return server.onEach("POST", "/oauth2/token", i -> {
            if (clock != null) {
                at.add(clock.elapsed().toSeconds());
            }
            return script[Math.min(i, script.length - 1)];
        });
    }

    // ── 1. Redaction ─────────────────────────────────────────────────────

    @Test
    void t01TheValuesAreOnTheWireAndInNoRendering() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        String notification = random();
        String authReqId = random();
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", initiated(authReqId, 5),
                oauthError(400, "invalid_binding_message"));
        CibaInitiateRequest req = request(config).pingMode(Sensitive.of(notification)).bindingMessage("W4SCT").build();
        Redaction.assertNoFragment("request rendering", req.toString(), notification);
        CibaInitiateResponse response = client.cibaInitiate(req);
        Redaction.assertNoFragment("response rendering",
                response + " " + MAPPER.writeValueAsString(response), authReqId);
        assertTrue(authReqId.equals(response.authReqId().expose()), "the auth_req_id is returned");
        assertTrue(notification.equals(bc.last().form().get("client_notification_token")),
                "the notification token is on the wire");

        OAuthProtocolError e = assertThrows(OAuthProtocolError.class, () -> client.cibaInitiate(req));
        assertEquals("invalid_binding_message", e.error());
        assertEquals("invalid_binding_message here", e.errorDescription());
        Redaction.assertNoFragment("error", e + " " + e.getMessage(), notification);
    }

    // ── 2. Client authentication is mandatory ────────────────────────────

    @Test
    void t02NoCredentialIsRefusedLocallyAndOneIsSentWithTenantInTheQuery() throws Exception {
        OidcConfiguration config = configuration();
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", initiated(random(), null));
        RouteServer.Route token = tokenScript(null, null, oauthError(400, "authorization_pending"));

        AxiamClient anonymous = AxiamClient.builder(server.base(), TENANT.toString()).oidcClientId(CLIENT_ID).build();
        clients.add(anonymous);
        assertThrows(AuthError.class, () -> anonymous.cibaInitiate(request(config).build()));
        assertThrows(AuthError.class, () -> anonymous.cibaPoll(Sensitive.of(random()), null, config));
        assertEquals(0, bc.calls() + token.calls(), "no request without a credential");

        String secret = random();
        AxiamClient client = client(secret);
        client.cibaInitiate(request(config).build());
        assertThrows(OAuthProtocolError.class, () -> client.cibaPoll(Sensitive.of(random()), null, config));
        for (RouteServer.Seen seen : List.of(bc.last(), token.last())) {
            assertEquals(CLIENT_ID, seen.form().get("client_id"));
            assertTrue(secret.equals(seen.form().get("client_secret")), "client_secret_post is sent");
            assertFalse(seen.form().containsKey("tenant_id"), "never a body field");
            assertEquals(TENANT.toString(), seen.query().get("tenant_id"));
            assertNotNull(seen.headers().get("X-Tenant-Id"));
        }

        // A tls_client_auth client: the certificate is the credential.
        TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "ciba-" + UUID.randomUUID());
        AxiamClient mtls = AxiamClient.builder(server.base(), TENANT.toString()).oidcClientId(CLIENT_ID)
                .clientCertificate(id.certPem(), id.keyPem()).build();
        clients.add(mtls);
        mtls.cibaInitiate(request(config).build());
        assertEquals(CLIENT_ID, bc.last().form().get("client_id"));
        assertFalse(bc.last().form().containsKey("client_secret"));
    }

    // ── 3. The initiate request ──────────────────────────────────────────

    @Test
    void t03ExactlyTheMembersSetAreSent() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", initiated(random(), null));

        client.cibaInitiateAsync(request(config).build()).get();
        assertEquals(List.of("client_id", "client_secret", "login_hint", "scope"),
                bc.last().form().keySet().stream().sorted().toList());

        String token = random();
        client.cibaInitiate(CibaInitiateRequest.builder("openid profile", CibaUserHint.idTokenHint("an.id.token"))
                .configuration(config).bindingMessage("W4SCT").requestedExpiry(120)
                .acrValues("urn:axiam:acr:mfa").resource("https://api.example.test")
                .pingMode(Sensitive.of(token)).tenantId(TENANT).build());
        Map<String, String> form = bc.last().form();
        assertEquals(List.of("acr_values", "binding_message", "client_id", "client_notification_token",
                "client_secret", "id_token_hint", "requested_expiry", "resource", "scope"),
                form.keySet().stream().sorted().toList());
        assertEquals("120", form.get("requested_expiry"));
        assertTrue(token.equals(form.get("client_notification_token")), "the notification token is sent");
        for (String forbidden : List.of("login_hint_token", "user_code", "request_uri", "request")) {
            assertFalse(form.containsKey(forbidden));
        }
        // login_hint_token, user_code and request_uri have no setter, and
        // CibaUserHint is a sealed single hint: both at once cannot be written.
        assertEquals(List.of("LoginHint", "IdTokenHint"), Arrays.stream(CibaUserHint.class.getPermittedSubclasses())
                .map(Class::getSimpleName).toList());
        assertFalse(Arrays.stream(CibaInitiateRequest.Builder.class.getMethods())
                .anyMatch(m -> m.getName().matches("(?i).*(usercode|loginhinttoken|requesturi).*")));
        // A ping request with an empty, or no, token is refused before any request.
        int before = bc.calls();
        assertThrows(ValidationError.class,
                () -> client.cibaInitiate(request(config).pingMode(Sensitive.of("")).build()));
        assertThrows(ValidationError.class, () -> client.cibaInitiate(request(config).pingMode(null).build()));
        assertEquals(before, bc.calls());
        assertTrue(request(config).build().toString().contains("mode=poll"));
    }

    // ── 4. No retry on initiate ──────────────────────────────────────────

    @Test
    void t04InitiateIsSentOnceOn503429AndADroppedConnection() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", status(503));
        assertThrows(NetworkError.class, () -> client.cibaInitiate(request(config).build()));
        assertEquals(1, bc.calls(), "503: exactly one request");

        RouteServer.Route limited = server.on("POST", "/oauth2/bc-authorize", oauthError(429, "rate_limit_exceeded"));
        OAuthProtocolError e = assertThrows(OAuthProtocolError.class, () -> client.cibaInitiate(request(config).build()));
        assertEquals("rate_limit_exceeded", e.error());
        assertEquals(1, limited.calls(), "429: exactly one request");

        // A listener that accepts and hangs up.
        AtomicInteger accepts = new AtomicInteger();
        try (ServerSocket listener = new ServerSocket(0)) {
            Thread acceptor = new Thread(() -> {
                while (!listener.isClosed()) {
                    try (Socket socket = listener.accept()) {
                        accepts.incrementAndGet();
                    } catch (IOException ignored) {
                        return;
                    }
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            ObjectNode doc = discovery("http://127.0.0.1:" + listener.getLocalPort() + "/oauth2/bc-authorize");
            server.on("GET", "/.well-known/openid-configuration", json(200, doc.toString()));
            AxiamClient fresh = client(random());
            OidcConfiguration dropping = fresh.oidcDiscover();
            assertThrows(NetworkError.class, () -> fresh.cibaInitiate(request(dropping).build()));
            Thread.sleep(100);
            assertEquals(1, accepts.get(), "one connection, no retry");
        }
    }

    // ── 5. Poll outcomes ─────────────────────────────────────────────────

    @Test
    void t05PendingLoopsSlowDownPersistsAndTheTerminalAnswersAreDistinct() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        TestClock clock = new TestClock();
        String id = random();
        RouteServer.Route token = tokenScript(clock, new ArrayList<>(), oauthError(400, "slow_down"),
                oauthError(400, "slow_down"), oauthError(400, "authorization_pending"), tokensWithIdToken(config));
        OidcTokenSet set = client.cibaAwait(new CibaInitiateResponse(Sensitive.of(id), 600, 5, clock.start),
                null, config, clock);
        assertNotNull(set.idClaims());
        assertEquals(List.of(5L, 10L, 15L, 15L), clock.sleeps, "+5 s twice, and pending lowers nothing");
        for (RouteServer.Seen seen : token.seen()) {
            assertEquals(AxiamClient.CIBA_GRANT_TYPE, seen.form().get("grant_type"));
            assertTrue(id.equals(seen.form().get("auth_req_id")), "the auth_req_id is sent");
        }

        for (String code : List.of("access_denied", "expired_token", "invalid_grant", "a_code_nobody_defined")) {
            RouteServer.Route terminal = server.on("POST", "/oauth2/token", oauthError(400, code));
            TestClock c = new TestClock();
            OAuthProtocolError e = assertThrows(OAuthProtocolError.class, () -> client.cibaAwait(
                    new CibaInitiateResponse(Sensitive.of(random()), 600, 5, c.start), null, config, c));
            assertEquals(code, e.error());
            assertEquals("access_denied".equals(code), e.isAccessDenied());
            assertEquals("expired_token".equals(code), e.isExpiredToken());
            assertEquals(1, terminal.calls(), "a terminal answer ends the loop after one request");
        }
    }

    // ── 6. The first poll waits ──────────────────────────────────────────

    @Test
    void t06TheFirstPollWaitsTheIntervalOrFiveSeconds() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        for (Integer interval : new Integer[] {7, null}) {
            long expected = interval == null ? 5 : interval;
            server.on("POST", "/oauth2/bc-authorize", initiated(random(), interval));
            TestClock clock = new TestClock();
            List<Long> at = new ArrayList<>();
            tokenScript(clock, at, oauthError(400, "access_denied"));
            CibaInitiateResponse response = client.cibaInitiate(request(config).build());
            assertEquals(expected, response.interval());
            CibaInitiateResponse anchored = new CibaInitiateResponse(response.authReqId(), response.expiresIn(),
                    response.interval(), clock.start);
            assertThrows(OAuthProtocolError.class, () -> client.cibaAwait(anchored, null, config, clock));
            assertEquals(List.of(expected), at, "the first poll is sent after one interval, not before");
        }
    }

    // ── 7. Deadline ──────────────────────────────────────────────────────

    @Test
    void t07NoRequestAfterExpiresInAndExpiredTokenIsRaisedLocally() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        TestClock clock = new TestClock();
        List<Long> at = new ArrayList<>();
        tokenScript(clock, at, oauthError(400, "authorization_pending"));
        OAuthProtocolError e = assertThrows(OAuthProtocolError.class, () -> client.cibaAwait(
                new CibaInitiateResponse(Sensitive.of(random()), 12, 5, clock.start), null, config, clock));
        assertTrue(e.isExpiredToken());
        assertEquals(List.of(5L, 10L), at, "nothing at 15 s, past the 12 s deadline");
    }

    // ── 8. Transient failure is not terminal ─────────────────────────────

    @Test
    void t08A500AndA429MidLoopAreSurvived() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        TestClock clock = new TestClock();
        RouteServer.Route token = tokenScript(clock, new ArrayList<>(), oauthError(400, "authorization_pending"),
                status(500), oauthError(429, "rate_limit_exceeded"), tokensWithIdToken(config));
        OidcTokenSet set = client.cibaAwait(new CibaInitiateResponse(Sensitive.of(random()), 600, 5, clock.start),
                null, config, clock);
        assertFalse(set.accessToken().expose().isEmpty());
        assertNotNull(set.idToken());
        assertNotNull(set.idClaims());
        assertEquals(4, token.calls());

        // A failure that outlives §16 within one poll is still not terminal.
        AxiamClient noRetry = AxiamClient.builder(server.base(), TENANT.toString()).oidcClientId(CLIENT_ID)
                .oidcClientSecret(random()).retryDisabled().build();
        clients.add(noRetry);
        TestClock c = new TestClock();
        RouteServer.Route flaky = tokenScript(c, new ArrayList<>(), status(503), tokensWithIdToken(config));
        noRetry.cibaAwait(new CibaInitiateResponse(Sensitive.of(random()), 600, 5, c.start), null, config, c);
        assertEquals(2, flaky.calls());
        assertEquals(List.of(5L, 5L), c.sleeps, "a transient failure counts as one interval");
    }

    // ── 9. Single use ────────────────────────────────────────────────────

    @Test
    void t09ASecondRedemptionIsInvalidGrantAndNotRetried() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        RouteServer.Route token = server.on("POST", "/oauth2/token", tokensWithIdToken(config),
                oauthError(400, "invalid_grant"));
        Sensitive id = Sensitive.of(random());
        client.cibaPollAsync(id, null, config).get();
        OAuthProtocolError e = assertThrows(OAuthProtocolError.class, () -> client.cibaPoll(id, null, config));
        assertEquals("invalid_grant", e.error());
        assertEquals(2, token.calls(), "no retry of the second");
    }

    // ── 10–13. The ping ──────────────────────────────────────────────────

    private static List<Map.Entry<String, String>> ping(String... authorization) {
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleImmutableEntry<>("content-type", "application/json"));
        for (String a : authorization) {
            headers.add(new AbstractMap.SimpleImmutableEntry<>("Authorization", a));
        }
        return headers;
    }

    private static byte[] body(String json) {
        return json.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void t10AValidPingReturnsItsAuthReqIdInAnySchemeCase() {
        AxiamClient client = client(random());
        String token = random();
        String id = random();
        for (String scheme : List.of("Bearer", "bearer", "BEARER")) {
            Sensitive got = client.cibaHandlePing(ping(scheme + " " + token),
                    body("{\"auth_req_id\":\"" + id + "\"}"), Sensitive.of(token));
            assertTrue(id.equals(got.expose()), "the ping's auth_req_id is returned");
            Redaction.assertNoFragment("result rendering", got.toString(), id);
        }
        Sensitive viaMap = client.cibaHandlePing(Map.of("authorization", List.of("Bearer " + token)),
                body("{\"auth_req_id\":\"" + id + "\"}"), Sensitive.of(token));
        assertTrue(id.equals(viaMap.expose()), "the multi-valued map form agrees");
    }

    @Test
    void t11AWrongAbsentEmptyDuplicateOrBasicAuthorizationIsRefused() throws Exception {
        AxiamClient client = client(random());
        String token = random();
        char last = token.charAt(token.length() - 1);
        String lastDiffers = token.substring(0, token.length() - 1) + (last == 'a' ? 'b' : 'a');
        byte[] ok = body("{\"auth_req_id\":\"" + random() + "\"}");
        Sensitive expected = Sensitive.of(token);
        List<String[]> cases = List.of(
                new String[] {"Bearer " + random()},
                new String[] {},
                new String[] {""},
                new String[] {"Bearer "},
                new String[] {"Bearer " + token, "Bearer " + token},
                new String[] {"Basic " + token},
                new String[] {"Bearer " + lastDiffers},
                new String[] {"Bearer  " + token});
        for (String[] c : cases) {
            AuthError e = assertThrows(AuthError.class, () -> client.cibaHandlePing(ping(c), ok, expected));
            Redaction.assertNoFragment("refusal", e + " " + e.getMessage(), token);
        }
        assertThrows(AuthError.class, () -> client.cibaHandlePing(ping("Bearer x"), ok, Sensitive.of("")));
        // The comparison is MessageDigest.isEqual: Java has no timing harness
        // here, so §33.8 test 11 is asserted structurally on the source.
        String source = Files.readString(Path.of("src/main/java/io/axiam/sdk/AxiamClient.java"));
        String ping = source.substring(source.indexOf("public Sensitive cibaHandlePing(List"));
        assertTrue(ping.contains("java.security.MessageDigest.isEqual(presented, expected)"));
    }

    @Test
    void t12AMalformedBodyIsAValidationErrorAndExtrasAreIgnored() {
        AxiamClient client = client(random());
        String token = random();
        Sensitive expected = Sensitive.of(token);
        for (String bad : List.of("not json", "{}", "{\"auth_req_id\":\"\"}", "{\"auth_req_id\":42}",
                "[\"auth_req_id\"]", "")) {
            assertThrows(ValidationError.class,
                    () -> client.cibaHandlePing(ping("Bearer " + token), body(bad), expected));
        }
        String id = random();
        Sensitive got = client.cibaHandlePing(ping("Bearer " + token),
                body("{\"auth_req_id\":\"" + id + "\",\"status\":\"approved\",\"access_token\":\"x\"}"), expected);
        assertTrue(id.equals(got.expose()), "extras are ignored");
    }

    @Test
    void t13ThePingHelperMakesNoNetworkCall() {
        AxiamClient client = client(random());
        String token = random();
        client.cibaHandlePing(ping("Bearer " + token), body("{\"auth_req_id\":\"" + random() + "\"}"),
                Sensitive.of(token));
        assertEquals(0, server.requestCount(), "the transport was never touched");
    }

    // ── 14–16. The signed form ───────────────────────────────────────────

    private static String pem(byte[] pkcs8) {
        return "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pkcs8)
                + "\n-----END PRIVATE KEY-----\n";
    }

    private static KeyPair keyPair(String algorithm) throws Exception {
        if ("EC".equals(algorithm)) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
        if ("RSA".equals(algorithm)) {
            g.initialize(2048);
        }
        return g.generateKeyPair();
    }

    private static OctetKeyPair ed25519Public(KeyPair pair) {
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] x = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x)).build();
    }

    private static JsonNode part(String jws, int index) throws IOException {
        return MAPPER.readTree(Base64.getUrlDecoder().decode(jws.split("\\.")[index]));
    }

    @Test
    void t14TheSignedRequestIsOneMemberWithTheRegisteredAlgAndFreshJti() throws Exception {
        OidcConfiguration config = configuration();
        String secret = random();
        AxiamClient client = client(secret);
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", initiated(random(), null));
        KeyPair ed = keyPair("Ed25519");
        CibaRequestSigner signer = CibaRequestSigner.fromPem(CibaSigningAlg.EDDSA,
                Sensitive.of(pem(ed.getPrivate().getEncoded())), "client-key-1");
        assertEquals(CibaSigningAlg.EDDSA, signer.alg());
        assertEquals("client-key-1", signer.kid());
        String notification = random();
        CibaInitiateRequest req = request(config).bindingMessage("W4SCT").requestedExpiry(90)
                .pingMode(Sensitive.of(notification)).signer(signer).build();
        client.cibaInitiate(req);
        client.cibaInitiate(req);

        List<String> jtis = new ArrayList<>();
        for (RouteServer.Seen seen : bc.seen()) {
            assertEquals(List.of("client_id", "client_secret", "request"),
                    seen.form().keySet().stream().sorted().toList(), "nothing beside request");
            assertTrue(secret.equals(seen.form().get("client_secret")), "client authentication is sent");
            String jws = seen.form().get("request");
            JsonNode header = part(jws, 0);
            assertEquals("EdDSA", header.path("alg").asText());
            assertEquals("client-key-1", header.path("kid").asText());
            assertTrue(JWSObject.parse(jws).verify(new Ed25519Verifier(ed25519Public(ed))), "the caller's key signed it");
            JsonNode claims = part(jws, 1);
            assertEquals(CLIENT_ID, claims.path("iss").asText());
            assertEquals(config.issuer(), claims.path("aud").asText());
            long exp = claims.path("exp").asLong();
            long nbf = claims.path("nbf").asLong();
            assertTrue(claims.path("iat").isIntegralNumber() && exp - nbf <= 3600 && exp > nbf);
            assertEquals("ada", claims.path("login_hint").asText());
            assertEquals("W4SCT", claims.path("binding_message").asText());
            assertEquals(90, claims.path("requested_expiry").asInt());
            assertTrue(claims.path("requested_expiry").isNumber(), "a number inside the JWT");
            assertTrue(notification.equals(claims.path("client_notification_token").asText()), "inside the JWT");
            assertTrue(claims.path("jti").asText().length() >= 32);
            jtis.add(claims.path("jti").asText());
        }
        assertNotEquals(jtis.get(0), jtis.get(1), "a fresh jti per request");

        // ES256 and PS256 sign under their own algorithm only.
        KeyPair ec = keyPair("EC");
        client.cibaInitiate(request(config).signer(CibaRequestSigner.of(CibaSigningAlg.ES256, ec.getPrivate(), null))
                .build());
        String es = bc.last().form().get("request");
        assertEquals("ES256", part(es, 0).path("alg").asText());
        assertFalse(part(es, 0).has("kid"));
        assertTrue(JWSObject.parse(es).verify(new ECDSAVerifier((ECPublicKey) ec.getPublic())));
        KeyPair rsa = keyPair("RSA");
        client.cibaInitiate(request(config).signer(CibaRequestSigner.fromPem(CibaSigningAlg.PS256,
                Sensitive.of(pem(rsa.getPrivate().getEncoded())), null)).build());
        String ps = bc.last().form().get("request");
        assertEquals("PS256", part(ps, 0).path("alg").asText());
        assertTrue(JWSObject.parse(ps).verify(new RSASSAVerifier((RSAPublicKey) rsa.getPublic())));
    }

    @Test
    void t15NoKeyOrAKeyForAnotherAlgIsRefusedBeforeAnyRequest() throws Exception {
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", initiated(random(), null));
        KeyPair ed = keyPair("Ed25519");
        KeyPair ec = keyPair("EC");
        String edPem = pem(ed.getPrivate().getEncoded());
        String ecPem = pem(ec.getPrivate().getEncoded());
        for (Object[] c : List.of(
                new Object[] {CibaSigningAlg.EDDSA, ""},
                new Object[] {CibaSigningAlg.EDDSA, "-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----"},
                new Object[] {CibaSigningAlg.ES256, edPem},
                new Object[] {CibaSigningAlg.PS256, ecPem},
                new Object[] {CibaSigningAlg.EDDSA, ecPem})) {
            assertThrows(ValidationError.class, () -> CibaRequestSigner.fromPem((CibaSigningAlg) c[0],
                    Sensitive.of((String) c[1]), null));
        }
        for (Object[] c : List.of(
                new Object[] {CibaSigningAlg.EDDSA, ec.getPrivate()},
                new Object[] {CibaSigningAlg.ES256, ed.getPrivate()},
                new Object[] {CibaSigningAlg.PS256, ed.getPrivate()},
                new Object[] {CibaSigningAlg.ES256, keyPair("RSA").getPrivate()})) {
            assertThrows(ValidationError.class, () -> CibaRequestSigner.of((CibaSigningAlg) c[0],
                    (java.security.PrivateKey) c[1], null));
        }
        // A P-384 key is an EC key that cannot sign ES256: the probe refuses it.
        KeyPairGenerator p384 = KeyPairGenerator.getInstance("EC");
        p384.initialize(new ECGenParameterSpec("secp384r1"));
        assertThrows(ValidationError.class,
                () -> CibaRequestSigner.of(CibaSigningAlg.ES256, p384.generateKeyPair().getPrivate(), null));
        // The algorithm and the key are the constructor's two required
        // arguments, so "no algorithm" cannot be written; and with a signer
        // set, every member travels inside request — there is no channel for a
        // form parameter beside it (t14 asserts the form).
        assertThrows(NullPointerException.class, () -> CibaRequestSigner.of(null, ed.getPrivate(), null));
        assertEquals(0, bc.calls());
    }

    @Test
    void t16TheKeyAndTheRequestAppearInNoRendering() throws Exception {
        OidcConfiguration config = configuration();
        AxiamClient client = client(random());
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", oauthError(400, "invalid_request"));
        KeyPair ed = keyPair("Ed25519");
        String pem = pem(ed.getPrivate().getEncoded());
        String keyBody = pem.lines().filter(l -> !l.startsWith("-----")).reduce("", String::concat);
        CibaRequestSigner signer = CibaRequestSigner.fromPem(CibaSigningAlg.EDDSA, Sensitive.of(pem), null);
        CibaInitiateRequest req = request(config).signer(signer).build();
        OAuthProtocolError e = assertThrows(OAuthProtocolError.class, () -> client.cibaInitiate(req));
        String request = bc.last().form().get("request");
        for (String rendering : List.of(signer.toString(), req.toString(), e + " " + e.getMessage())) {
            Redaction.assertNoFragment("rendering", rendering, keyBody);
            Redaction.assertNoFragment("rendering", rendering, request);
        }
        Sensitive signed = signer.sign(CLIENT_ID, config.issuer(), req.members());
        Redaction.assertNoFragment("wrapped request", signed.toString(), signed.expose());
    }

    // ── Discovery and the seventh alias ──────────────────────────────────

    @Test
    void aServerWithoutCibaIsReportedAndTheDiscoveryMembersDecode() throws Exception {
        OidcConfiguration config = configuration();
        assertEquals(server.base() + "/oauth2/bc-authorize", config.backchannel_authentication_endpoint());
        assertEquals(List.of("poll", "ping"), config.backchannel_token_delivery_modes_supported());
        assertEquals(Boolean.FALSE, config.backchannel_user_code_parameter_supported());
        assertEquals(List.of("PS256", "ES256", "EdDSA"),
                config.backchannel_authentication_request_signing_alg_values_supported());

        server.on("GET", "/.well-known/openid-configuration",
                OidcTestSupport.discoveryResponse(server.base()));
        AxiamClient client = client(random());
        OidcConfiguration none = client.oidcDiscover();
        assertNull(none.backchannel_authentication_endpoint());
        assertNull(none.backchannel_user_code_parameter_supported());
        RouteServer.Route bc = server.on("POST", "/oauth2/bc-authorize", initiated(random(), null));
        AuthError e = assertThrows(AuthError.class, () -> client.cibaInitiate(request(none).build()));
        assertTrue(e.getMessage().contains("does not support CIBA"));
        assertEquals(0, bc.calls(), "never a synthesised URL");
    }

    @Test
    void theDefaultFormsDiscoverAndUseTheConfiguredTenant() throws Exception {
        configuration();
        AxiamClient client = client(random());
        server.on("POST", "/oauth2/bc-authorize", initiated(random(), 1));
        CibaInitiateResponse r = client.cibaInitiate(
                CibaInitiateRequest.builder("openid", CibaUserHint.loginHint("ada")).build());
        RouteServer.Route token = server.on("POST", "/oauth2/token", tokensWithIdToken(client.oidcDiscover()));
        assertNotNull(client.cibaPoll(r.authReqId()));
        CibaInitiateResponse quick = new CibaInitiateResponse(r.authReqId(), 30, 1, Instant.now());
        assertNotNull(client.cibaAwaitAsync(quick).get());
        assertEquals(2, token.calls());
        assertEquals(TENANT.toString(), token.last().query().get("tenant_id"));
    }
}
