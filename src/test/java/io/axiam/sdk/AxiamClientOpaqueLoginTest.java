package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.opaque.FakeOpaqueNative;
import io.axiam.sdk.opaque.OpaqueEnrollment;
import io.axiam.sdk.opaque.OpaqueTestSupport;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code loginOpaque} / {@code opaqueEnrollment} end to end (CONTRACT.md
 * &sect;23).
 *
 * <p>The protocol is {@code libaxiam_opaque_ffi}'s and is covered by
 * {@code OpaqueBindingTest}. What is tested here is the part the SDK owns:
 * what goes on the wire — and, more importantly, what does <em>not</em> —
 * which failures are {@link AuthError} and which are {@link NetworkError}, and
 * that a failed credential check never reaches {@code login/finish}.
 */
class AxiamClientOpaqueLoginTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String USER = "alice";

    /**
     * Minted per run rather than written down: nothing here depends on the
     * value, and a literal that reads like a credential is a finding for every
     * secret scanner that looks at this repository.
     */
    private static char[] password(String label) {
        byte[] entropy = new byte[8];
        RANDOM.nextBytes(entropy);
        return (label + "-" + HexFormat.of().formatHex(entropy)).toCharArray();
    }

    private static final char[] PASSWORD = password("correct");

    /**
     * The hex KE2 and RegistrationResponse the fake server answers with. Hex
     * because that is what the wire carries; the binding hands them to the
     * library verbatim, and the fake library echoes them back inside its own
     * payload, which is how these tests see that nothing was rewritten in
     * between.
     */
    private static final String WIRE_KE2 = "6b6532";
    private static final String WIRE_REGISTRATION_RESPONSE = "726573703a";

    private FakeOpaqueNative lib;

    @BeforeEach
    void installFake() {
        lib = OpaqueTestSupport.installFake();
    }

    @AfterEach
    void restoreLoader() {
        OpaqueTestSupport.reset();
    }

    /**
     * A server that answers the three OPAQUE endpoints — plus
     * {@code /auth/login}, the §23.4 rule 7 fallback target — and records what
     * it saw.
     */
    private static final class FakeOpaqueServer extends Dispatcher {

        final List<String> loginStartBodies = new ArrayList<>();
        final List<String> loginFinishBodies = new ArrayList<>();
        final List<String> registerStartBodies = new ArrayList<>();
        /** Bodies seen at {@code POST /api/v1/auth/login} — the plaintext path. */
        final List<String> passwordLoginBodies = new ArrayList<>();

        int loginStartStatus = 200;
        int loginFinishStatus = 200;
        int registerStartStatus = 200;
        int passwordLoginStatus = 200;
        boolean mfaRequired;
        boolean omitKe2;
        String ksf = "argon2id";

        /**
         * The {@code mode} the {@code login/start} response carries
         * (&sect;23.5). {@code null} means the field is <em>absent</em>, which
         * is what a server older than contract 1.29 sends and which §23.4
         * rule 7 reads as {@code required}.
         */
        String mode;

        @Override
        public MockResponse dispatch(RecordedRequest request) {
            String body = request.getBody().readUtf8();
            String path = request.getPath() == null ? "" : request.getPath();
            if (path.endsWith("/auth/opaque/login/start")) {
                loginStartBodies.add(body);
                return loginStart();
            }
            if (path.endsWith("/auth/opaque/login/finish")) {
                loginFinishBodies.add(body);
                return loginFinish();
            }
            if (path.endsWith("/auth/opaque/register/start")) {
                registerStartBodies.add(body);
                return registerStart();
            }
            if (path.endsWith("/auth/login")) {
                passwordLoginBodies.add(body);
                return passwordLogin();
            }
            return new MockResponse().setResponseCode(404);
        }

        private String ksfFields() {
            if ("scrypt".equals(ksf)) {
                return "\"ksf\":\"scrypt\",\"log_n\":15,\"r\":8,\"p\":1";
            }
            return "\"ksf\":\"" + ksf + "\",\"memory_kib\":19456,\"iterations\":2,\"parallelism\":1";
        }

        private MockResponse loginStart() {
            if (loginStartStatus != 200) {
                return new MockResponse().setResponseCode(loginStartStatus);
            }
            String ke2 = omitKe2 ? "" : "\"ke2\":\"" + WIRE_KE2 + "\",";
            String modeField = mode == null ? "" : "\"mode\":\"" + mode + "\",";
            return new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"opaque_session\":\"handle-42\","
                            + modeField + ke2 + ksfFields() + "}");
        }

        /** {@code POST /api/v1/auth/login} — the §23.4 rule 7 fallback target. */
        private MockResponse passwordLogin() {
            if (passwordLoginStatus != 200) {
                return new MockResponse().setResponseCode(passwordLoginStatus);
            }
            return new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/")
                    .addHeader("Set-Cookie", "axiam_refresh=refresh-tok; Path=/")
                    .setBody("{\"session_id\":\"55555555-5555-5555-5555-555555555555\","
                            + "\"expires_in\":900}");
        }

        private MockResponse loginFinish() {
            if (loginFinishStatus != 200) {
                return new MockResponse().setResponseCode(loginFinishStatus);
            }
            MockResponse response = new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/")
                    .addHeader("Set-Cookie", "axiam_refresh=refresh-tok; Path=/");
            if (mfaRequired) {
                return response.setResponseCode(202)
                        .setBody("{\"challenge_token\":\"mfa-challenge\","
                                + "\"available_methods\":[\"totp\"]}");
            }
            return response.setResponseCode(200).setBody(
                    "{\"session_id\":\"55555555-5555-5555-5555-555555555555\",\"expires_in\":900}");
        }

        private MockResponse registerStart() {
            if (registerStartStatus != 200) {
                return new MockResponse().setResponseCode(registerStartStatus);
            }
            return new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"opaque_session\":\"reg-handle\","
                            + "\"registration_response\":\"" + WIRE_REGISTRATION_RESPONSE + "\","
                            + ksfFields() + "}");
        }
    }

    private static String fakeAccessToken() {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"" + TENANT_ID + "\","
                + "\"org_id\":\"44444444-4444-4444-4444-444444444444\","
                + "\"jti\":\"22222222-2222-2222-2222-222222222222\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 900) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static JsonNode parse(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private interface Body {
        void run(MockWebServer server, AxiamClient client) throws Exception;
    }

    private static void withClient(FakeOpaqueServer fake, Body body) throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                body.run(server, client);
            }
        }
    }

    // -----------------------------------------------------------------
    // What crosses the wire
    // -----------------------------------------------------------------

    @Test
    @DisplayName("login/start carries KE1 and no password field")
    void loginStartCarriesNoPassword() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        withClient(fake, (server, client) -> client.loginOpaque(USER, PASSWORD.clone()));

        JsonNode body = parse(fake.loginStartBodies.get(0));
        // The entire point of the exchange. A body that still carried a
        // password would be SRP's failure mode with extra steps.
        assertTrue(body.path("password").isMissingNode());
        assertEquals(USER, body.path("username_or_email").asText());
        assertEquals(TENANT_ID, body.path("tenant_slug").asText());
        assertEquals("ke1:" + new String(PASSWORD),
                OpaqueTestSupport.decode(body.path("ke1").asText()));
    }

    @Test
    @DisplayName("register/start names no account at all")
    void registerStartNamesNoAccount() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        withClient(fake, (server, client) -> {
            OpaqueEnrollment enrollment = client.opaqueEnrollment(PASSWORD.clone());
            assertEquals("reg-handle", enrollment.opaqueSession());
            assertTrue(OpaqueTestSupport.decode(enrollment.registrationRecord())
                    .startsWith("record:" + new String(PASSWORD) + ":" + WIRE_REGISTRATION_RESPONSE + ":"));
        });

        JsonNode body = parse(fake.registerStartBodies.get(0));
        assertTrue(body.path("password").isMissingNode());
        // No username either: a record binds to a credential identifier the
        // server chooses, which is why a later rename cannot invalidate one.
        assertTrue(body.path("username_or_email").isMissingNode());
        assertEquals(TENANT_ID, body.path("tenant_slug").asText());
        assertEquals("req:" + new String(PASSWORD),
                OpaqueTestSupport.decode(body.path("registration_request").asText()));
    }

    @Test
    @DisplayName("login/finish echoes the session handle the server issued")
    void loginFinishEchoesTheServerHandle() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        withClient(fake, (server, client) -> client.loginOpaque(USER, PASSWORD.clone()));

        JsonNode body = parse(fake.loginFinishBodies.get(0));
        assertEquals("handle-42", body.path("opaque_session").asText());
        assertTrue(OpaqueTestSupport.decode(body.path("ke3").asText())
                .startsWith("ke3:" + new String(PASSWORD) + ":" + WIRE_KE2 + ":"));
    }

    @Test
    @DisplayName("the key-stretching function the server named is the one used")
    void theServerNamedKsfIsTheOneUsed() throws Exception {
        // §23.4 rule 2: never local defaults. A credential enrolled under one
        // cost keeps working after a tenant raises its policy, so a client that
        // guessed would fail against a record that is perfectly good.
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.ksf = "scrypt";
        withClient(fake, (server, client) -> client.loginOpaque(USER, PASSWORD.clone()));

        // The fake encodes the handle it was given; scrypt handles start 0xb.
        String ke3 = OpaqueTestSupport.decode(parse(fake.loginFinishBodies.get(0))
                .path("ke3").asText());
        assertTrue(ke3.endsWith(":" + Long.toHexString(0xB0000L + 15 + 8 + 1)), ke3);
    }

    // -----------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a successful login returns what login() returns")
    void successReturnsTheSameShapeAsLogin() throws Exception {
        withClient(new FakeOpaqueServer(), (server, client) -> {
            assertTrue(client.opaqueAvailable());
            LoginResult result = client.loginOpaque(USER, PASSWORD.clone());
            assertFalse(result.mfaRequired());
            assertNotNull(result.user());
            assertEquals("11111111-1111-1111-1111-111111111111", result.user().userId());
        });
    }

    @Test
    @DisplayName("the mfa_required branch survives the OPAQUE path")
    void mfaRequiredSurvives() throws Exception {
        // One result handler must serve both login paths, so the second phase
        // has to arrive here exactly as it does from login().
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mfaRequired = true;
        withClient(fake, (server, client) -> {
            LoginResult result = client.loginOpaque(USER, PASSWORD.clone());
            assertTrue(result.mfaRequired());
            assertNotNull(result.challengeToken());
        });
    }

    @Test
    @DisplayName("the async twin returns the same result")
    void asyncTwinMatches() throws Exception {
        withClient(new FakeOpaqueServer(), (server, client) -> {
            LoginResult result = client.loginOpaqueAsync(USER, PASSWORD.clone()).join();
            assertFalse(result.mfaRequired());
        });
    }

    // -----------------------------------------------------------------
    // Failures -- which exception, and why it matters
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a disabled tenant is a NetworkError a caller can fall back from")
    void disabledTenantIsANetworkError() throws Exception {
        // A 404 is a property of the tenant, not of the credentials. As an
        // AuthError it would be shown as "invalid password" and send a user to
        // reset a working one, while stopping a fallback to login().
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.loginStartStatus = 404;
        withClient(fake, (server, client) -> {
            NetworkError error = assertThrows(NetworkError.class,
                    () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(error.getMessage().contains("opaque_mode is disabled"));
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("enrolment reports a disabled tenant the same way")
    void disabledTenantAtEnrolment() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.registerStartStatus = 404;
        withClient(fake, (server, client) -> {
            NetworkError error = assertThrows(NetworkError.class,
                    () -> client.opaqueEnrollment(PASSWORD.clone()));
            assertTrue(error.getMessage().contains("opaque_mode is disabled"));
        });
    }

    @Test
    @DisplayName("a 401 at login/start is an AuthError")
    void unauthorizedAtStartIsAnAuthError() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.loginStartStatus = 401;
        withClient(fake, (server, client) ->
                assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone())));
    }

    @Test
    @DisplayName("a wrong password never reaches login/finish")
    void wrongPasswordNeverReachesFinish() throws Exception {
        // §23.4 rule 7. The envelope failing to open IS the authentication
        // check; sending anything afterwards would ask the server to decide
        // something the client has already decided.
        lib.fail("login_finish");
        FakeOpaqueServer fake = new FakeOpaqueServer();
        withClient(fake, (server, client) -> {
            assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    // -----------------------------------------------------------------
    // §23.4 rule 7 -- what `mode` decides, and only `mode`
    // -----------------------------------------------------------------

    @Test
    @DisplayName("optional: a failed KE2 falls back to /auth/login and returns its success")
    void optionalModeFallsBackToPasswordLogin() throws Exception {
        // Under `optional` an account with no registration record is the
        // ORDINARY case -- every account has none the moment an operator
        // enables OPAQUE. Treating the failed exchange as final would lock out
        // every user of a tenant mid-migration, which is the state `optional`
        // exists to serve.
        lib.fail("login_finish");
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = "optional";
        withClient(fake, (server, client) -> {
            LoginResult result = client.loginOpaque(USER, PASSWORD.clone());
            assertFalse(result.mfaRequired());
            assertNotNull(result.user());
            assertEquals("11111111-1111-1111-1111-111111111111", result.user().userId());

            // The retry is the SDK's own plaintext path, with the same
            // credentials -- not a second hand-rolled request.
            assertEquals(1, fake.passwordLoginBodies.size());
            JsonNode retry = parse(fake.passwordLoginBodies.get(0));
            assertEquals(USER, retry.path("username_or_email").asText());
            assertEquals(new String(PASSWORD), retry.path("password").asText());
            assertEquals(TENANT_ID, retry.path("tenant_slug").asText());

            // Rule 7's absolute: KE3 is never sent once KE2 fails to open.
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("optional: when the fallback also fails, its error is the one reported")
    void optionalModeReportsTheFallbackFailure() throws Exception {
        // The OPAQUE attempt is not reported separately: a wrong password, an
        // unknown identity and a missing record are indistinguishable, so
        // saying which occurred would be a claim the SDK cannot make.
        lib.fail("login_finish");
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = "optional";
        fake.passwordLoginStatus = 401;
        withClient(fake, (server, client) -> {
            assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertEquals(1, fake.passwordLoginBodies.size());
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("required: a failed KE2 is final and never touches /auth/login")
    void requiredModeDoesNotFallBack() throws Exception {
        // `required` answers 403 opaque_required for EVERY principal, so a
        // retry would put a plaintext password on the wire for nothing.
        lib.fail("login_finish");
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = "required";
        withClient(fake, (server, client) -> {
            assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(fake.passwordLoginBodies.isEmpty());
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("no mode field at all reads as required")
    void absentModeReadsAsRequired() throws Exception {
        // A server older than contract 1.29 sends no `mode`. Absence must fail
        // closed: the alternative sends a plaintext password to an endpoint
        // nobody said would accept it.
        lib.fail("login_finish");
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = null;
        withClient(fake, (server, client) -> {
            assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(fake.passwordLoginBodies.isEmpty());
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("an unrecognised mode reads as required")
    void unknownModeReadsAsRequired() throws Exception {
        lib.fail("login_finish");
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = "enforced-someday";
        withClient(fake, (server, client) -> {
            assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(fake.passwordLoginBodies.isEmpty());
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("optional does not fall back when the exchange succeeds")
    void optionalModeDoesNotFallBackOnSuccess() throws Exception {
        // The fallback is keyed to a failed KE2, not to the mode. A tenant on
        // `optional` whose users ARE enrolled must never see a second request.
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = "optional";
        withClient(fake, (server, client) -> {
            LoginResult result = client.loginOpaque(USER, PASSWORD.clone());
            assertFalse(result.mfaRequired());
            assertEquals(1, fake.loginFinishBodies.size());
            assertTrue(fake.passwordLoginBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("optional does not fall back when login/finish itself refuses")
    void optionalModeDoesNotFallBackOnAFinishRefusal() throws Exception {
        // A 401 AFTER a KE2 that opened perfectly well is not a failed
        // credential check -- the client already authenticated the server --
        // so it must not reach the plaintext path.
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.mode = "optional";
        fake.loginFinishStatus = 401;
        withClient(fake, (server, client) -> {
            assertThrows(AuthError.class, () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(fake.passwordLoginBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("the async twin falls back under optional and does not under required")
    void asyncTwinHonoursMode() throws Exception {
        lib.fail("login_finish");

        FakeOpaqueServer optional = new FakeOpaqueServer();
        optional.mode = "optional";
        withClient(optional, (server, client) -> {
            LoginResult result = client.loginOpaqueAsync(USER, PASSWORD.clone()).join();
            assertFalse(result.mfaRequired());
            assertNotNull(result.user());
            assertEquals(1, optional.passwordLoginBodies.size());
            assertTrue(optional.loginFinishBodies.isEmpty());
        });

        FakeOpaqueServer required = new FakeOpaqueServer();
        required.mode = "required";
        withClient(required, (server, client) -> {
            CompletionException raised = assertThrows(CompletionException.class,
                    () -> client.loginOpaqueAsync(USER, PASSWORD.clone()).join());
            assertInstanceOf(AuthError.class, raised.getCause());
            assertTrue(required.passwordLoginBodies.isEmpty());
            assertTrue(required.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("an unsupported KSF is a configuration error, not a bad password")
    void unsupportedKsfIsAConfigurationError() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.ksf = "bcrypt";
        withClient(fake, (server, client) -> {
            NetworkError error = assertThrows(NetworkError.class,
                    () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(error.getMessage().contains("bcrypt"));
            assertTrue(fake.loginFinishBodies.isEmpty());
        });
    }

    @Test
    @DisplayName("a start response without ke2 is a malformed response, not a credential failure")
    void missingKe2IsAMalformedResponse() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.omitKe2 = true;
        withClient(fake, (server, client) -> {
            NetworkError error = assertThrows(NetworkError.class,
                    () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(error.getMessage().contains("no `ke2`"));
        });
    }

    @Test
    @DisplayName("a 5xx at login/finish is a NetworkError")
    void serverErrorAtFinishIsANetworkError() throws Exception {
        FakeOpaqueServer fake = new FakeOpaqueServer();
        fake.loginFinishStatus = 503;
        withClient(fake, (server, client) ->
                assertThrows(NetworkError.class, () -> client.loginOpaque(USER, PASSWORD.clone())));
    }

    @Test
    @DisplayName("an absent library is reported before any request is sent")
    void absentLibraryIsReportedBeforeAnyRequest() throws Exception {
        OpaqueTestSupport.installAbsent();
        FakeOpaqueServer fake = new FakeOpaqueServer();
        withClient(fake, (server, client) -> {
            assertFalse(client.opaqueAvailable());
            NetworkError error = assertThrows(NetworkError.class,
                    () -> client.loginOpaque(USER, PASSWORD.clone()));
            assertTrue(error.getMessage().contains("libaxiam_opaque_ffi"));
            assertEquals(0, server.getRequestCount());
        });
    }
}
