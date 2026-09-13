package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.webauthn.WebauthnChallenge;
import io.axiam.sdk.webauthn.WebauthnCredential;
import io.axiam.sdk.webauthn.WebauthnFailure;
import io.axiam.sdk.webauthn.WebauthnLoginResult;
import io.axiam.sdk.webauthn.WebauthnWorkspace;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * &sect;24 WebAuthn relying-party layer — the CONTRACT.md &sect;24.8 test set.
 *
 * <p>Two assertions are worth reading twice:
 *
 * <ul>
 *   <li>{@code registerStartDoesNotRetry503} asserts on the <strong>request
 *       count</strong>, not the exception type, because &sect;24.4 rule 2
 *       regresses the moment someone tidies a retry predicate — and a type
 *       assertion would still pass.
 *   <li>{@code stateTokenIsNeverParsed} hands the SDK a state token that is not
 *       a JWT at all. If anything decoded one, this is where it would fail.
 * </ul>
 */
class AxiamClientWebauthnTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String TENANT_SLUG = "acme";
    private static final String ORG_SLUG = "globex";
    private static final String STATE_TOKEN = "state-token-fixture-value-do-not-log";
    private static final String CHALLENGE_TOKEN = "challenge-token-fixture-do-not-log";
    private static final String ACCESS_TOKEN = "access-token-fixture-do-not-log";
    private static final String REFRESH_TOKEN = "refresh-token-fixture-do-not-log";
    private static final String SETUP_TOKEN = "setup-token-fixture-do-not-log";

    /**
     * Deliberately "unusual but valid": every optional field populated, so the
     * pass-through assertion has something to catch an over-eager
     * implementation dropping. A minimal fixture would prove nothing.
     */
    private static final String CREATION_CHALLENGE = """
            {"publicKey":{
              "challenge":"Y2hhbGxlbmdlLWJ5dGVz",
              "rp":{"id":"axiam.test","name":"AXIAM Test"},
              "user":{"id":"dXNlci1oYW5kbGU","name":"alice","displayName":"Alice"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},
                                  {"type":"public-key","alg":-257}],
              "timeout":60000,
              "excludeCredentials":[{"id":"ZXhpc3Rpbmc","type":"public-key","transports":["usb","nfc"]}],
              "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,
                                        "userVerification":"required"},
              "attestation":"direct",
              "extensions":{"credProps":true}
            }}""";

    private static final String MINIMAL_CREATION_CHALLENGE = """
            {"publicKey":{
              "challenge":"bWluaW1hbA",
              "rp":{"name":"AXIAM Test"},
              "user":{"id":"dQ","name":"bob","displayName":"Bob"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7}]
            }}""";

    private static final String DISCOVERABLE_CHALLENGE = """
            {"publicKey":{
              "challenge":"ZGlzY292ZXJhYmxl",
              "rpId":"axiam.test",
              "allowCredentials":[],
              "userVerification":"required"
            }}""";

    /** Carries an unknown key the SDK must forward rather than strip. */
    private static final String REGISTRATION_RESPONSE = """
            {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
             "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                         "attestationObject":"o2NmbXRkbm9uZQ",
                         "transports":["internal"],
                         "vendorSpecific":"must-survive"},
             "type":"public-key","clientExtensionResults":{"credProps":{"rk":true}}}""";

    private static final String AUTHENTICATION_RESPONSE = """
            {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
             "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                         "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                         "userHandle":"dXNlci1oYW5kbGU"},
             "type":"public-key","clientExtensionResults":{}}""";

    private static AxiamClient client(String base) {
        return AxiamClient.builder(base, TENANT_SLUG).orgSlug(ORG_SLUG).build();
    }

    private static MockResponse challengeResponse(String challenge) {
        return json(200, "{\"challenge\":" + challenge + ",\"state_token\":\"" + STATE_TOKEN + "\"}");
    }

    private static MockResponse credentialResponse() {
        return json(201, "{\"id\":\"" + UUID.randomUUID() + "\",\"credential_id\":\"bmV3LWNyZWQ\","
                + "\"name\":\"Alice's laptop\",\"credential_type\":\"passkey\","
                + "\"created_at\":\"2026-08-22T10:00:00Z\"}");
    }

    /**
     * The token body a completed passkey sign-in returns, alongside the cookie
     * triple contract 1.28 added. Before that fix the browser had no session at
     * all after a ceremony the server had already accepted.
     */
    private static MockResponse loginResponse() {
        return json(200, "{\"access_token\":\"" + ACCESS_TOKEN + "\",\"refresh_token\":\""
                + REFRESH_TOKEN + "\",\"session_id\":\"" + UUID.randomUUID()
                + "\",\"expires_in\":900}")
                .addHeader("Set-Cookie", "axiam_access=access-cookie; Path=/")
                .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
                .addHeader("X-CSRF-Token", "csrf-tok");
    }

    private static MockResponse json(int code, String body) {
        return new MockResponse()
                .setResponseCode(code)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    /**
     * A completed-login response shaped for {@code webauthnSetupRegisterFinish}
     * specifically: unlike {@link #loginResponse()} (consumed only as a
     * {@link WebauthnLoginResult}, which never decodes the access token),
     * {@code setupRegisterFinish} runs through the SAME {@code authenticatedFrom}
     * path {@code login()}/{@code mfaSetupConfirm} do, which decodes
     * {@code sub}/{@code tenant_id} out of the access cookie to build the
     * {@link AxiamUser} — so the fixture needs a structurally valid token, not
     * an opaque literal.
     */
    private static MockResponse setupFinishLoginResponse(String accessToken) {
        return json(200, "{\"session_id\":\"" + UUID.randomUUID() + "\",\"expires_in\":900}")
                .addHeader("Set-Cookie", "axiam_access=" + accessToken + "; Path=/")
                .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
                .addHeader("X-CSRF-Token", "csrf-tok");
    }

    /** Seed the access cookie — what the SDK reads as "signed in" (§24.1). */
    private static void signIn(MockWebServer server, AxiamClient client) throws Exception {
        server.enqueue(json(200, "{\"session_id\":\"" + UUID.randomUUID() + "\",\"expires_in\":900}")
                .addHeader("Set-Cookie", "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/")
                .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
                .addHeader("X-CSRF-Token", "csrf-tok"));
        client.login("alice@example.com", "pw");
        server.takeRequest();
    }

    // -----------------------------------------------------------------------
    // §24.0 — options and responses pass through untouched
    // -----------------------------------------------------------------------

    @Test
    void optionsPassThroughStructurallyUnchanged() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(challengeResponse(CREATION_CHALLENGE));

                WebauthnChallenge challenge = client.webauthnRegisterStart();

                // Structural equality, not a spot-check of three fields: the
                // failure mode this guards is an SDK that quietly drops the one
                // option it did not recognize.
                assertEquals(MAPPER.readTree(CREATION_CHALLENGE), challenge.challenge());
            }
        }
    }

    @Test
    void synthesizesNoFieldTheServerOmitted() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(challengeResponse(MINIMAL_CREATION_CHALLENGE));

                WebauthnChallenge challenge = client.webauthnRegisterStart();
                JsonNode options = MAPPER.readTree(challenge.requestJson());

                for (String key : new String[] {
                        "authenticatorSelection", "timeout", "excludeCredentials", "attestation" }) {
                    assertNull(options.get(key), "SDK synthesized " + key);
                }
            }
        }
    }

    @Test
    void authenticatorResponseIsSentBackVerbatim() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(credentialResponse());

                client.webauthnRegisterFinish(
                        Sensitive.of(STATE_TOKEN), "laptop", REGISTRATION_RESPONSE);

                JsonNode sent = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(MAPPER.readTree(REGISTRATION_RESPONSE), sent.get("response"));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.1 — preconditions and workspace resolution
    // -----------------------------------------------------------------------

    @Test
    void registerWithoutASessionMakesNoWireCall() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                assertThrows(AuthError.class, client::webauthnRegisterStart);
                assertThrows(AuthError.class, () -> client.webauthnRegisterFinish(
                        Sensitive.of(STATE_TOKEN), "x", REGISTRATION_RESPONSE));

                // Asserted on the transport, not on the exception type alone.
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    @Test
    void discoverableWorkspaceComesFromTheClientInSlugForm() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(challengeResponse(DISCOVERABLE_CHALLENGE));
                client.webauthnDiscoverableStart(null);

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(ORG_SLUG, body.path("org_slug").asText());
                assertEquals(TENANT_SLUG, body.path("tenant_slug").asText());
                // §24.2: a discoverable ceremony has no prior step to have
                // minted a challenge token.
                assertNull(body.get("challenge_token"));
            }
        }
    }

    @Test
    void discoverableWorkspaceCanBeOverridden() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                UUID orgId = UUID.randomUUID();
                server.enqueue(challengeResponse(DISCOVERABLE_CHALLENGE));

                client.webauthnDiscoverableStart(
                        new WebauthnWorkspace(orgId, null, null, "other"));

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(orgId.toString(), body.path("org_id").asText());
                assertEquals("other", body.path("tenant_slug").asText());
            }
        }
    }

    @Test
    void discoverableWithoutAnOrgRaisesClientSide() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_SLUG).build()) {
                AuthError error = assertThrows(AuthError.class,
                        () -> client.webauthnDiscoverableStart(null));
                assertTrue(error.getMessage().contains("organization"));
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.2 — two distinct flows
    // -----------------------------------------------------------------------

    @Test
    void secondFactorStartSendsOnlyTheChallengeToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(challengeResponse(DISCOVERABLE_CHALLENGE));
                client.webauthnAuthenticateStart(Sensitive.of(CHALLENGE_TOKEN));

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/webauthn/authenticate/start", request.getPath());
                JsonNode body = MAPPER.readTree(request.getBody().readUtf8());
                assertEquals(CHALLENGE_TOKEN, body.path("challenge_token").asText());
                assertEquals(1, body.size());
            }
        }
    }

    @Test
    void discoverableFinishReachesItsOwnEndpoint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(loginResponse());
                client.webauthnDiscoverableFinish(Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE);

                assertEquals("/api/v1/auth/webauthn/authenticate/discoverable/finish",
                        server.takeRequest().getPath());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.3 — credential adoption
    // -----------------------------------------------------------------------

    @Test
    void aCompletedSignInReturnsTheTokenSet() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(loginResponse());

                WebauthnLoginResult result = client.webauthnAuthenticateFinish(
                        Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE);

                assertEquals(ACCESS_TOKEN, result.accessToken().expose());
                assertEquals(REFRESH_TOKEN, result.refreshToken().expose());
                assertEquals(900L, result.expiresIn());
            }
        }
    }

    @Test
    void registerFinishReturnsTheCredential() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(credentialResponse());

                WebauthnCredential credential = client.webauthnRegisterFinish(
                        Sensitive.of(STATE_TOKEN), "Alice's laptop", REGISTRATION_RESPONSE);

                assertEquals("bmV3LWNyZWQ", credential.credentialId());
                assertEquals("passkey", credential.credentialType());
                assertNull(credential.lastUsedAt(),
                        "a never-used credential should have no lastUsedAt");
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.1 (contract 1.45) — the session-less setup/register pair
    //
    // Unlike register/*, this pair takes NO session: the setup token in the
    // body is the only credential, and an SDK MUST NOT attach its own
    // session credential even when one is configured (§24.1, §24.8).
    // -----------------------------------------------------------------------

    @Test
    void setupRegisterStartReachesItsOwnEndpointWithTheSetupTokenInTheBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(challengeResponse(MINIMAL_CREATION_CHALLENGE));

                WebauthnChallenge challenge = client.webauthnSetupRegisterStart(Sensitive.of(SETUP_TOKEN));

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/webauthn/setup/register/start", request.getPath());
                assertEquals(SETUP_TOKEN,
                        MAPPER.readTree(request.getBody().readUtf8()).path("setup_token").asText());
                assertEquals(STATE_TOKEN, challenge.stateToken().expose());
            }
        }
    }

    @Test
    void setupRegisterCallsCarryNoSessionCredentialEvenWhenOneIsConfigured() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // A session IS configured — the very case §24.8 asks to guard
                // against: an already-signed-in caller must not have that
                // session's credential ride along with a setup token.
                signIn(server, client);

                server.enqueue(challengeResponse(MINIMAL_CREATION_CHALLENGE));
                client.webauthnSetupRegisterStart(Sensitive.of(SETUP_TOKEN));
                RecordedRequest startRequest = server.takeRequest();
                assertNull(startRequest.getHeader("Authorization"),
                        "setup/register/start must not carry the session's Authorization header");
                assertTrue(isBlank(startRequest.getHeader("Cookie")),
                        "setup/register/start must not carry the session's cookie, got: "
                                + startRequest.getHeader("Cookie"));

                server.enqueue(setupFinishLoginResponse(OidcTestTokens.unsignedAccessToken()));
                client.webauthnSetupRegisterFinish(Sensitive.of(SETUP_TOKEN), Sensitive.of(STATE_TOKEN),
                        "Alice's phone", REGISTRATION_RESPONSE);
                RecordedRequest finishRequest = server.takeRequest();
                assertNull(finishRequest.getHeader("Authorization"),
                        "setup/register/finish must not carry the session's Authorization header");
                assertTrue(isBlank(finishRequest.getHeader("Cookie")),
                        "setup/register/finish must not carry the session's cookie, got: "
                                + finishRequest.getHeader("Cookie"));
            }
        }
    }

    @Test
    void setupRegisterFinishAdoptsCredentialsExactlyAsMfaSetupConfirmDoes() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                String accessToken = OidcTestTokens.unsignedAccessToken();
                server.enqueue(setupFinishLoginResponse(accessToken));

                LoginResult result = client.webauthnSetupRegisterFinish(Sensitive.of(SETUP_TOKEN),
                        Sensitive.of(STATE_TOKEN), "Alice's phone", REGISTRATION_RESPONSE);

                RecordedRequest finishRequest = server.takeRequest();
                assertEquals("/api/v1/auth/webauthn/setup/register/finish", finishRequest.getPath());

                // §25.2 rule 2: this IS the completion of a login, adopted
                // exactly as mfaSetupConfirm/login adopt one — not handed back
                // for the caller to install.
                assertFalse(result.mfaRequired());
                assertFalse(result.mfaSetupRequired());

                // A cookie-jar SDK additionally captures the CSRF token, and a
                // state-changing call made immediately afterwards carries it —
                // the same assertion §24.3 requires of webauthnAuthenticateFinish
                // (§24.8's adoption test).
                server.enqueue(json(200, "{}"));
                client.mfaEnroll();
                RecordedRequest afterward = server.takeRequest();
                assertEquals("Bearer " + accessToken, afterward.getHeader("Authorization"),
                        "the client must be authenticated after setup/register/finish, "
                                + "exactly as after login()");
                assertEquals("csrf-tok", afterward.getHeader("X-CSRF-Token"),
                        "the captured CSRF token must be echoed on the very next state-changing call");
            }
        }
    }

    @Test
    void setupRegisterStartDoesNotRetry503() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                int before = server.getRequestCount();
                server.enqueue(json(503, "{\"message\":\"FIDO metadata unavailable\"}"));

                assertThrows(RuntimeException.class,
                        () -> client.webauthnSetupRegisterStart(Sensitive.of(SETUP_TOKEN)));

                // §24.4 rule 2, same as registerStartDoesNotRetry503.
                assertEquals(1, server.getRequestCount() - before,
                        "the 503 must not be retried");
            }
        }
    }

    @Test
    void setupRegisterStart401MeansTheTokenIsInvalidExpiredOrWrongPurpose() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(401, "{\"message\":\"invalid or expired setup token\"}"));
                assertThrows(AuthError.class,
                        () -> client.webauthnSetupRegisterStart(Sensitive.of("not-a-real-token")));
            }
        }
    }

    @Test
    void a401OnSetupRegisterIsNeverRetriedWithTheSessionsCredential() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // A session IS configured, so AuthAuthenticator's reactive 401
                // handler has a credential it COULD reach for. It must not: the
                // setup token — not this client's own session — is what a 401
                // here is complaining about (§24.1), and "fixing" it by
                // retrying with the session's Authorization header would
                // attach exactly the credential this pair must never carry.
                signIn(server, client);
                int before = server.getRequestCount();
                server.enqueue(json(401, "{\"message\":\"invalid or expired setup token\"}"));

                assertThrows(AuthError.class,
                        () -> client.webauthnSetupRegisterStart(Sensitive.of("not-a-real-token")));

                assertEquals(1, server.getRequestCount() - before,
                        "a 401 here must not trigger AuthAuthenticator's reactive refresh-and-retry");
            }
        }
    }

    @Test
    void setupRegisterStart400MeansTheAccountAlreadyHasAFactor() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(400, "{\"message\":\"account already has a factor\"}"));
                // A setup token adds the FIRST factor, never a second — the same
                // rule mfaSetupEnroll enforces.
                assertThrows(RuntimeException.class,
                        () -> client.webauthnSetupRegisterStart(Sensitive.of(SETUP_TOKEN)));
            }
        }
    }

    @Test
    void setupRegisterFinish403SurfacesThePolicyMessageVerbatim() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(403, "{\"message\":\"this security key is not FIDO certified\"}"));

                AuthzError error = assertThrows(AuthzError.class,
                        () -> client.webauthnSetupRegisterFinish(Sensitive.of(SETUP_TOKEN),
                                Sensitive.of(STATE_TOKEN), "key", REGISTRATION_RESPONSE));
                // §24.4 rule 1, same as webauthnRegisterFinish's 403.
                assertTrue(error.getMessage().contains("FIDO certified")
                                || String.valueOf(error.getCause()).contains("FIDO certified"),
                        "the attestation policy message was lost: " + error.getMessage());
            }
        }
    }

    @Test
    void setupRegisterTokensAreNeverParsed() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // Neither the setup token nor the state token is a JWT or
                // anything base64-shaped. If either were decoded, this fails.
                String notAJwt = "this-is-not-a-jwt-and-never-will-be";
                server.enqueue(setupFinishLoginResponse(OidcTestTokens.unsignedAccessToken()));

                client.webauthnSetupRegisterFinish(Sensitive.of(notAJwt), Sensitive.of(notAJwt),
                        "key", REGISTRATION_RESPONSE);

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(notAJwt, body.path("setup_token").asText());
                assertEquals(notAJwt, body.path("state_token").asText());
            }
        }
    }

    /** {@code null} or blank — the shape an absent/suppressed header takes. */
    private static boolean isBlank(String header) {
        return header == null || header.isBlank();
    }

    // -----------------------------------------------------------------------
    // §24.4 — error taxonomy
    // -----------------------------------------------------------------------

    @Test
    void registerStartDoesNotRetry503() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                int before = server.getRequestCount();
                server.enqueue(json(503, "{\"message\":\"FIDO metadata unavailable\"}"));

                assertThrows(RuntimeException.class, client::webauthnRegisterStart);

                // §24.4 rule 2. Asserted on the request count: a 503 here is a
                // server CONFIGURATION state, retrying changes nothing, and this
                // regresses silently the moment the retry predicate is tidied.
                assertEquals(1, server.getRequestCount() - before,
                        "the 503 must not be retried");
            }
        }
    }

    @Test
    void a403IsAnAuthorizationErrorCarryingThePolicyMessage() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(json(403, "{\"message\":\"this security key is not FIDO certified\"}"));

                AuthzError error = assertThrows(AuthzError.class,
                        () -> client.webauthnRegisterFinish(
                                Sensitive.of(STATE_TOKEN), "key", REGISTRATION_RESPONSE));
                // §24.4 rule 1: the policy message is the only way the person
                // holding the key learns a different one would work.
                assertTrue(error.getMessage().contains("FIDO certified")
                                || String.valueOf(error.getCause()).contains("FIDO certified"),
                        "the attestation policy message was lost: " + error.getMessage());
            }
        }
    }

    @Test
    void aFailedAssertionIsAnAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(401, "{\"message\":\"assertion failed\"}"));
                assertThrows(AuthError.class, () -> client.webauthnAuthenticateFinish(
                        Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.5 — the state token is opaque, and Sensitive
    // -----------------------------------------------------------------------

    @Test
    void stateTokenIsNeverParsed() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // Not a JWT, not three dot-separated segments, not base64
                // anything. If the SDK decoded state tokens at all, this would
                // fail — exactly the assertion §24.8 asks for.
                String notAJwt = "this-is-not-a-jwt-and-never-will-be";
                server.enqueue(loginResponse());

                client.webauthnAuthenticateFinish(Sensitive.of(notAJwt), AUTHENTICATION_RESPONSE);

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(notAJwt, body.path("state_token").asText());
            }
        }
    }

    @Test
    void secretsNeverRender() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(challengeResponse(CREATION_CHALLENGE));
                server.enqueue(loginResponse());

                WebauthnChallenge challenge = client.webauthnRegisterStart();
                WebauthnLoginResult login = client.webauthnAuthenticateFinish(
                        Sensitive.of(STATE_TOKEN), AUTHENTICATION_RESPONSE);

                String rendered = challenge + "|" + login + "|" + challenge.stateToken()
                        + "|" + login.accessToken() + "|" + login.refreshToken();
                for (String secret : new String[] { STATE_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN }) {
                    assertFalse(rendered.contains(secret), secret + " leaked into a toString");
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.6a — the JSON bridge
    // -----------------------------------------------------------------------

    @Test
    void requestJsonRoundTripsAndDropsTheWrapper() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                signIn(server, client);
                server.enqueue(challengeResponse(CREATION_CHALLENGE));

                WebauthnChallenge challenge = client.webauthnRegisterStart();
                JsonNode parsed = MAPPER.readTree(challenge.requestJson());

                // The string an Android app hands to
                // CreatePublicKeyCredentialRequest, and a browser to
                // PublicKeyCredential.parseCreationOptionsFromJSON.
                assertNull(parsed.get("publicKey"));
                assertEquals(MAPPER.readTree(CREATION_CHALLENGE).get("publicKey"), parsed);
            }
        }
    }

    @Test
    void aMalformedResponseStringIsRefusedBeforeAnyWireCall() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                assertThrows(AuthError.class, () -> client.webauthnAuthenticateFinish(
                        Sensitive.of(STATE_TOKEN), "{not json"));
                assertEquals(0, server.getRequestCount());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §24.6b rule 5 — the classification, with no authenticator in sight
    // -----------------------------------------------------------------------

    @Test
    void classificationMapsTheFiveOutcomes() {
        assertEquals(WebauthnFailure.CANCELLED, WebauthnFailure.classify("NotAllowedError"));
        assertEquals(WebauthnFailure.ALREADY_REGISTERED, WebauthnFailure.classify("InvalidStateError"));
        assertEquals(WebauthnFailure.TIMEOUT, WebauthnFailure.classify("AbortError"));
        assertEquals(WebauthnFailure.UNSUPPORTED, WebauthnFailure.classify("NotSupportedError"));
        assertEquals(WebauthnFailure.UNSUPPORTED, WebauthnFailure.classify("SecurityError"));
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify("SomethingElseError"));
        // An Android CreateCredentialException or an ASAuthorizationError code
        // relayed to a Java service as a bare name (§24.6b rule 5's last line).
        assertEquals(WebauthnFailure.CANCELLED, WebauthnFailure.classify("canceled"));
        assertEquals(WebauthnFailure.UNKNOWN, WebauthnFailure.classify(""));
    }

    @Test
    void alreadyRegisteredIsDistinguishableFromCancelled() {
        assertNotEquals(WebauthnFailure.classify("InvalidStateError"),
                WebauthnFailure.classify("NotAllowedError"));
        // The only classification whose remedy is a different device.
        assertTrue(WebauthnFailure.ALREADY_REGISTERED.message().contains("different device"));
        // The same name covers a silent timeout, and the spec will not say
        // which, so the copy must not accuse the user.
        assertTrue(WebauthnFailure.CANCELLED.message().contains("cancelled or timed out"));
    }
}
