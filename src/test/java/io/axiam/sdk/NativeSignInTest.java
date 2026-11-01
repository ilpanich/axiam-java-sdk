package io.axiam.sdk;

import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.oidc.ProviderNonce;
import io.axiam.sdk.telemetry.TelemetryEvent;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;

import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;37 (contract 1.65): native sign-in with a provider ID token.
 * One test per name in &sect;37.9, against a mocked server.
 */
class NativeSignInTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String GRANT = "urn:axiam:params:oauth:grant-type:provider-id-token";
    /** The &sect;37.4 fixed vector: SHA-256 of the ASCII string, lower-case hex. */
    private static final String VECTOR_RAW = "n-0S6_WzA2Mj";
    private static final String VECTOR_HASH = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19";
    private static final String PROVIDER_TOKEN = "eyJhbGciOiJSUzI1NiJ9.PROVIDER-PAYLOAD-FIXTURE.PROVIDER-SIG-FIXTURE";
    private static final String GENERIC_INVALID_GRANT =
            "{\"error\":\"invalid_grant\",\"error_description\":\"the provider ID token is not acceptable\"}";

    // ---------------------------------------------------------------- helpers

    private static AxiamClient publicClient(String base) {
        return AxiamClient.builder(base, TENANT_ID).oidcClientId("native-app").build();
    }

    private static AxiamClient confidentialClient(String base) {
        return AxiamClient.builder(base, TENANT_ID).oidcClientId("native-app").oidcClientSecret("relay-secret").build();
    }

    /** Fetches discovery and consumes that request, so a test counts only the sign-in's own requests. */
    private static OidcConfiguration discover(MockWebServer server, AxiamClient client) throws Exception {
        server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
        OidcConfiguration config = client.oidcDiscover();
        server.takeRequest();
        return config;
    }

    private static Map<String, String> form(RecordedRequest request) {
        Map<String, String> fields = new LinkedHashMap<>();
        String body = request.getBody().readUtf8();
        if (body.isEmpty()) {
            return fields;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            fields.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return fields;
    }

    private static MockResponse json(int status, String body) {
        return new MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body);
    }

    private static String stackTrace(Throwable t) {
        StringWriter out = new StringWriter();
        t.printStackTrace(new PrintWriter(out));
        return out.toString();
    }

    private static String stripSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static OidcTokenSet signIn(AxiamClient client, OidcConfiguration config) {
        return client.loginWithProviderIdToken("corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW),
                null, null, null, config);
    }

    // ------------------------------------------------------------------ 1

    @Test
    void requestBodyExact() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                server.enqueue(OidcTestSupport.tokenResponse("access-1", null, null));
                server.enqueue(OidcTestSupport.tokenResponse("access-2", null, null));

                client.loginWithProviderIdToken("corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW),
                        List.of("profile", "email"), "https://api.example.com", null, config);
                RecordedRequest full = server.takeRequest();
                assertEquals("POST", full.getMethod());
                HttpUrl url = full.getRequestUrl();
                assertEquals("/oauth2/token", url.encodedPath());
                assertEquals(TENANT_ID, url.queryParameter("tenant_id"));
                assertEquals("application/x-www-form-urlencoded", full.getHeader("Content-Type"));
                assertNull(full.getHeader("Authorization"));
                assertNull(full.getHeader("Cookie"));
                assertNull(full.getHeader("X-CSRF-Token"));
                assertEquals(TENANT_ID, full.getHeader("X-Tenant-ID"), "§5 rule 2 still applies");
                Map<String, String> fields = form(full);
                assertEquals(Set.of("grant_type", "client_id", "provider", "id_token", "nonce", "scope", "resource"),
                        fields.keySet(), "the full key set, and no tenant_id in the body");
                assertEquals(GRANT, fields.get("grant_type"));
                assertEquals("native-app", fields.get("client_id"));
                assertEquals("profile email", fields.get("scope"));
                assertEquals("https://api.example.com", fields.get("resource"));

                // No scopes, no resource: neither key, and no `openid` added (rule 7). Discovery is cached.
                client.loginWithProviderIdToken("corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW));
                RecordedRequest bare = server.takeRequest();
                Map<String, String> bareFields = form(bare);
                assertEquals(Set.of("grant_type", "client_id", "provider", "id_token", "nonce"), bareFields.keySet());
                assertFalse(bareFields.containsKey("scope"));
            }
        }
    }

    // ------------------------------------------------------------------ 2

    @Test
    void rawNonceSentNotHash() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                // A fixture provider token whose own payload carries the hash as its nonce claim.
                String providerToken = OidcTestSupport.signEdDsa(key,
                        OidcTestSupport.validIdTokenClaims("https://accounts.example", "native-app", VECTOR_HASH));
                server.enqueue(OidcTestSupport.tokenResponse("access", null, null));

                client.loginWithProviderIdToken("corp-okta", Sensitive.of(providerToken), Sensitive.of(VECTOR_RAW),
                        null, null, null, config);

                RecordedRequest request = server.takeRequest();
                String body = request.getBody().readUtf8();
                Map<String, String> fields = new LinkedHashMap<>();
                for (String pair : body.split("&")) {
                    int eq = pair.indexOf('=');
                    fields.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                }
                assertEquals(VECTOR_RAW, fields.get("nonce"));
                assertFalse(body.toLowerCase().contains(VECTOR_HASH), "the hash is never sent");
                assertEquals(providerToken, fields.get("id_token"), "the token itself goes up unread");
            }
        }
    }

    // ------------------------------------------------------------------ 3

    @Test
    void providerSentVerbatim() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                String uuid = UUID.randomUUID().toString();
                int before = server.getRequestCount();
                for (String provider : List.of(uuid, "Corp-Okta", "google")) {
                    server.enqueue(OidcTestSupport.tokenResponse("access", null, null));
                    client.loginWithProviderIdToken(provider, Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW),
                            null, null, null, config);
                    assertEquals(provider, form(server.takeRequest()).get("provider"));
                }
                assertEquals(3, server.getRequestCount() - before,
                        "one request per sign-in: no sso_providers lookup, no discovery fetch");
            }
        }
    }

    // ------------------------------------------------------------------ 4

    @Test
    void publicClientSendsClientIdOnly() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                server.enqueue(OidcTestSupport.tokenResponse("access", null, null));

                signIn(client, config);

                RecordedRequest request = server.takeRequest();
                Map<String, String> fields = form(request);
                assertEquals("native-app", fields.get("client_id"));
                assertFalse(fields.containsKey("client_secret"));
                assertFalse(fields.containsKey("client_assertion"));
                assertNull(request.getHeader("Authorization"));
            }
        }
    }

    @Test
    void confidentialClientSendsItsCredential() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = confidentialClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                server.enqueue(OidcTestSupport.tokenResponse("access", null, null));

                signIn(client, config);

                RecordedRequest request = server.takeRequest();
                assertEquals("relay-secret", form(request).get("client_secret"));
                assertNull(request.getHeader("Authorization"), "never an HTTP Basic header");
            }
        }
    }

    // ------------------------------------------------------------------ 5

    @Test
    void emptyInputsRefusedLocally() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                int before = server.getRequestCount();

                assertThrows(ValidationError.class, () -> client.loginWithProviderIdToken(
                        "", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW), null, null, null, config));
                assertThrows(ValidationError.class, () -> client.loginWithProviderIdToken(
                        "corp-okta", Sensitive.of(""), Sensitive.of(VECTOR_RAW), null, null, null, config));
                assertThrows(ValidationError.class, () -> client.loginWithProviderIdToken(
                        "corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(""), null, null, null, config));
                assertThrows(ValidationError.class, () -> client.loginWithProviderIdToken(
                        "corp-okta", "", VECTOR_RAW, null));

                assertEquals(0, server.getRequestCount() - before);
            }
            // A slug-only client (§12.3 rule 4): the taxonomy error, client-side, no wire call at all.
            try (AxiamClient slugOnly = AxiamClient.builder(server.url("/").toString(), "acme-tenant")
                    .oidcClientId("native-app").build()) {
                int before = server.getRequestCount();
                assertThrows(AuthError.class, () -> slugOnly.loginWithProviderIdToken(
                        "corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW)));
                assertEquals(0, server.getRequestCount() - before, "not even discovery");
            }
        }
    }

    // ------------------------------------------------------------------ 6

    @Test
    void genericInvalidGrantMapped() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                server.enqueue(json(400, GENERIC_INVALID_GRANT));
                int before = server.getRequestCount();

                OAuthProtocolError error = assertThrows(OAuthProtocolError.class, () -> signIn(client, config));

                assertEquals("invalid_grant", error.error());
                assertEquals("the provider ID token is not acceptable", error.errorDescription());
                assertEquals("invalid_grant: the provider ID token is not acceptable", error.getMessage());
                assertEquals(1, server.getRequestCount() - before,
                        "one request: no retry, no regenerated nonce, no refresh-guard entry");
            }
        }
    }

    // ------------------------------------------------------------------ 7

    @Test
    void consentRequiredMapped() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                server.enqueue(json(400, "{\"error\":\"consent_required\",\"error_description\":\"consent\"}"));
                int before = server.getRequestCount();

                OAuthProtocolError error = assertThrows(OAuthProtocolError.class, () -> signIn(client, config));

                assertEquals("consent_required", error.error());
                assertEquals(1, server.getRequestCount() - before, "no fallback to another grant");
            }
        }
    }

    // ------------------------------------------------------------------ 8

    @Test
    void clientAndScopeRefusalsSurfaced() throws Exception {
        record Case(int status, String error, boolean wwwAuthenticate) { }
        for (Case c : List.of(new Case(400, "unauthorized_client", false), new Case(401, "invalid_client", true),
                new Case(400, "invalid_scope", false), new Case(400, "invalid_target", false))) {
            try (MockWebServer server = new MockWebServer()) {
                server.start();
                try (AxiamClient client = publicClient(server.url("/").toString())) {
                    OidcConfiguration config = discover(server, client);
                    MockResponse response = json(c.status(),
                            "{\"error\":\"" + c.error() + "\",\"error_description\":\"" + c.error() + " text\"}");
                    if (c.wwwAuthenticate()) {
                        response.setHeader("WWW-Authenticate", "Basic realm=\"axiam\"");
                    }
                    server.enqueue(response);
                    int before = server.getRequestCount();

                    OAuthProtocolError error = assertThrows(OAuthProtocolError.class, () -> client.loginWithProviderIdToken(
                            "corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW),
                            List.of("openid", "address"), null, null, config));

                    assertEquals(c.error(), error.error());
                    assertEquals(1, server.getRequestCount() - before,
                            c.error() + ": one request, not narrowed and re-sent, no §9 refresh on the 401");
                }
            }
        }
    }

    // ------------------------------------------------------------------ 9

    @Test
    void rateLimitWithRetryAfterMapped() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);
                server.enqueue(json(429, "{\"error\":\"rate_limit_exceeded\"}").setHeader("Retry-After", "7"));
                int before = server.getRequestCount();

                OAuthProtocolError error = assertThrows(OAuthProtocolError.class, () -> signIn(client, config));

                assertEquals("rate_limit_exceeded", error.error());
                assertEquals(7, error.retryAfterSeconds());
                assertEquals(1, server.getRequestCount() - before);
            }
        }
    }

    // ----------------------------------------------------------------- 10

    @Test
    void serverErrorNotRetried() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = publicClient(server.url("/").toString())) {
                OidcConfiguration config = discover(server, client);

                server.enqueue(json(500, "{\"error\":\"server_error\",\"error_description\":\"datastore\"}"));
                int before = server.getRequestCount();
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class, () -> signIn(client, config));
                assertEquals("server_error", error.error());
                assertEquals(1, server.getRequestCount() - before);

                server.enqueue(new MockResponse().setResponseCode(500));
                before = server.getRequestCount();
                assertThrows(NetworkError.class, () -> signIn(client, config));
                assertEquals(1, server.getRequestCount() - before, "a 500 with no body: NetworkError, one request");

                server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST));
                before = server.getRequestCount();
                assertThrows(NetworkError.class, () -> signIn(client, config));
                assertEquals(1, server.getRequestCount() - before,
                        "a transport failure after the request left: NetworkError, never re-sent");
            }
        }
    }

    // ----------------------------------------------------------------- 11

    @Test
    void resultIsTheOrdinaryTokenSet() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.start();
            try (AxiamClient client = publicClient(base)) {
                OidcConfiguration config = discover(server, client);
                String axiamIdToken = OidcTestSupport.signEdDsa(key,
                        OidcTestSupport.validIdTokenClaims(stripSlash(base), "native-app", VECTOR_RAW));
                server.enqueue(json(200, "{\"access_token\":\"acc\",\"token_type\":\"DPoP\",\"expires_in\":900,"
                        + "\"refresh_token\":\"ref\",\"id_token\":\"" + axiamIdToken + "\","
                        + "\"scope\":\"openid profile\"}"));
                server.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));

                OidcTokenSet tokens = client.loginWithProviderIdToken("corp-okta", Sensitive.of(PROVIDER_TOKEN),
                        Sensitive.of(VECTOR_RAW), List.of("openid", "profile"), null, null, config);

                assertEquals("DPoP", tokens.tokenType(), "read, not assumed");
                assertEquals("acc", tokens.accessToken().expose());
                assertEquals("ref", tokens.refreshToken().expose());
                assertEquals("openid profile", tokens.scope());
                assertNotNull(tokens.idClaims(), "validated under §12.4 with the raw nonce as the expected one");
                assertEquals(VECTOR_RAW, tokens.idClaims().nonce());
                server.takeRequest(); // the token request
                server.takeRequest(); // the JWKS fetch

                // Adoption posture (as loginClientCredentials): the set is returned and NOT adopted, so the
                // client's next request carries no credential derived from it.
                server.enqueue(json(200, "{\"allowed\":true}"));
                try {
                    client.checkAccess("read", "documents/1");
                } catch (RuntimeException ignored) {
                    // the mock's answer is beside the point; only the request's headers matter
                }
                RecordedRequest after = server.takeRequest();
                assertNull(after.getHeader("Authorization"), "the result is not adopted as the client's credential");

                // A mismatching nonce claim is the nonce_mismatch AuthError.
                String wrongNonce = OidcTestSupport.signEdDsa(key,
                        OidcTestSupport.validIdTokenClaims(stripSlash(base), "native-app", VECTOR_HASH));
                server.enqueue(json(200, "{\"access_token\":\"acc\",\"token_type\":\"Bearer\",\"expires_in\":900,"
                        + "\"id_token\":\"" + wrongNonce + "\"}"));
                AuthError mismatch = assertThrows(AuthError.class, () -> client.loginWithProviderIdToken(
                        "corp-okta", Sensitive.of(PROVIDER_TOKEN), Sensitive.of(VECTOR_RAW),
                        List.of("openid"), null, null, config));
                assertEquals("nonce_mismatch", mismatch.reason());

                // Without refresh_token and id_token, both are absent.
                server.enqueue(OidcTestSupport.tokenResponse("only-access", null, null));
                OidcTokenSet bare = signIn(client, config);
                assertNull(bare.refreshToken());
                assertNull(bare.idToken());
                assertNull(bare.idClaims());
            }
        }
    }

    // ----------------------------------------------------------------- 12

    /** Collects every java.util.logging record at the most verbose level. */
    private static final class Capture extends Handler {
        final List<String> lines = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            StringBuilder line = new StringBuilder(String.valueOf(record.getMessage()));
            if (record.getParameters() != null) {
                for (Object p : record.getParameters()) {
                    line.append(' ').append(p);
                }
            }
            if (record.getThrown() != null) {
                line.append(' ').append(stackTrace(record.getThrown()));
            }
            lines.add(line.toString());
        }

        @Override
        public void flush() { }

        @Override
        public void close() { }
    }

    @Test
    void noSecretInLogsOrErrors() throws Exception {
        final String idToken = PROVIDER_TOKEN;
        final String nonce = "RAW-NONCE-FIXTURE-0123456789abcdef";
        Logger root = Logger.getLogger("");
        Level previous = root.getLevel();
        Capture capture = new Capture();
        capture.setLevel(Level.ALL);
        root.setLevel(Level.ALL);
        root.addHandler(capture);
        List<String> telemetry = new ArrayList<>();
        List<Throwable> errors = new ArrayList<>();
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("native-app")
                    .telemetryHook((TelemetryEvent e) -> telemetry.add(String.valueOf(e)))
                    .build()) {
                OidcConfiguration config = discover(server, client);

                server.enqueue(OidcTestSupport.tokenResponse("access", null, null));
                OidcTokenSet ok = client.loginWithProviderIdToken("corp-okta", Sensitive.of(idToken),
                        Sensitive.of(nonce), null, null, null, config);
                telemetry.add(ok.toString());

                // Test 5: empty inputs, each with the other fixture present.
                try {
                    client.loginWithProviderIdToken("", Sensitive.of(idToken), Sensitive.of(nonce), null, null, null, config);
                } catch (RuntimeException e) {
                    errors.add(e);
                }
                try {
                    client.loginWithProviderIdToken("corp-okta", Sensitive.of(idToken), Sensitive.of(""), null, null, null, config);
                } catch (RuntimeException e) {
                    errors.add(e);
                }
                // Tests 6 to 10.
                List<MockResponse> failures = List.of(
                        json(400, GENERIC_INVALID_GRANT),
                        json(400, "{\"error\":\"consent_required\",\"error_description\":\"c\"}"),
                        json(400, "{\"error\":\"unauthorized_client\",\"error_description\":\"u\"}"),
                        json(401, "{\"error\":\"invalid_client\",\"error_description\":\"i\"}")
                                .setHeader("WWW-Authenticate", "Basic"),
                        json(400, "{\"error\":\"invalid_scope\",\"error_description\":\"s\"}"),
                        json(400, "{\"error\":\"invalid_target\",\"error_description\":\"t\"}"),
                        json(429, "{\"error\":\"rate_limit_exceeded\"}").setHeader("Retry-After", "7"),
                        json(500, "{\"error\":\"server_error\",\"error_description\":\"d\"}"),
                        new MockResponse().setResponseCode(500),
                        new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST));
                for (MockResponse failure : failures) {
                    server.enqueue(failure);
                    try {
                        client.loginWithProviderIdToken("corp-okta", Sensitive.of(idToken), Sensitive.of(nonce),
                                null, null, null, config);
                    } catch (RuntimeException e) {
                        errors.add(e);
                    }
                }
                assertEquals(12, errors.size());
            }
        } finally {
            root.removeHandler(capture);
            root.setLevel(previous);
        }

        List<String> haystack = new ArrayList<>(capture.lines);
        haystack.addAll(telemetry);
        for (Throwable t : errors) {
            haystack.add(String.valueOf(t.getMessage()));
            haystack.add(t.toString());
            haystack.add(stackTrace(t));
            for (Throwable c = t.getCause(); c != null; c = c.getCause()) {
                haystack.add(String.valueOf(c.getMessage()));
            }
            if (t instanceof ValidationError v) {
                haystack.add(String.valueOf(v.fields()));
            }
        }
        ProviderNonce pair = AxiamClient.nativeNonce();
        haystack.add(pair.toString());
        haystack.add(pair.raw().toString());
        for (String text : haystack) {
            assertFalse(text.contains(idToken), "the provider ID token appeared in: " + text);
            assertFalse(text.contains(nonce), "the raw nonce appeared in: " + text);
            assertFalse(text.contains(pair.raw().expose()), "ProviderNonce.raw appeared in: " + text);
        }
    }

    // ----------------------------------------------------------------- 13

    @Test
    void nativeNoncePair() throws Exception {
        // The fixed vector tests the hashing step only.
        assertEquals(VECTOR_HASH, ProviderNonce.hash(VECTOR_RAW));

        ProviderNonce a = AxiamClient.nativeNonce();
        ProviderNonce b = AxiamClient.nativeNonce();
        String raw = a.raw().expose();
        assertTrue(raw.matches("[A-Za-z0-9_-]+"), "base64url, no padding: " + raw);
        assertFalse(raw.contains("="));
        assertTrue(Base64.getUrlDecoder().decode(raw).length >= 32);
        assertTrue(a.hashed().matches("[0-9a-f]{64}"), "64 lower-case hex characters");
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(raw.getBytes(StandardCharsets.UTF_8))), a.hashed());
        assertNotEquals(raw, b.raw().expose(), "each call returns a fresh pair");
        assertNotEquals(a.hashed(), b.hashed());
        assertEquals("[SENSITIVE]", a.raw().toString(), "raw is wrapped");
        assertEquals(String.class, a.hashed().getClass(), "hashed is a plain string");
        assertFalse(a.toString().contains(raw));
    }
}
