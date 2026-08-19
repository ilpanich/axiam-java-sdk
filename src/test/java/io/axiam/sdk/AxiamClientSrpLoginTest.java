package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.srp.Srp;
import io.axiam.sdk.srp.SrpEnrollment;
import io.axiam.sdk.srp.SrpGroup;
import io.axiam.sdk.srp.SrpKdfParams;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code loginSrp} end-to-end against a fake server that performs REAL SRP
 * arithmetic (CONTRACT.md &sect;23.7 rules 5, 7 and 8).
 *
 * <p>A fake that echoed canned values would pass whatever the client computed.
 * This one holds a verifier, derives its own {@code S} from it and answers
 * with the {@code M2} that follows — so a client that gets {@code u},
 * {@code PAD()} or the identity wrong fails here rather than in production.
 */
class AxiamClientSrpLoginTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String IDENTITY = "alice";
    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    /** The server half of one enrolled account. */
    private static final class FakeSrpServer extends Dispatcher {

        private final SrpGroup group;
        // PBKDF2 at a low iteration count: the KDF's cost is not what these
        // tests measure, and Argon2id at production memory would dominate them.
        private final SrpKdfParams kdf = new SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000, 0, 0);
        private final byte[] salt = new byte[32];
        private final BigInteger verifier;

        private BigInteger bPriv;
        private BigInteger bPub;
        private BigInteger aPub;

        boolean corruptServerProof;
        boolean mfaRequired;
        /** When set, answered on the first challenge so the client restarts. */
        SrpGroup namedGroup;

        final List<String> bodies = new ArrayList<>();

        FakeSrpServer(SrpGroup group) {
            this.group = group;
            java.util.Arrays.fill(salt, (byte) 0xa3);
            byte[] x = Srp.deriveX(IDENTITY, PASSWORD, salt, kdf);
            this.verifier = group.generator()
                    .modPow(new BigInteger(1, x).mod(group.modulus()), group.modulus());
        }

        @Override
        public MockResponse dispatch(RecordedRequest request) {
            String body = request.getBody().readUtf8();
            bodies.add(body);
            String path = request.getPath() == null ? "" : request.getPath();
            if (path.endsWith("/auth/srp/challenge")) {
                return challenge(body);
            }
            if (path.endsWith("/auth/srp/verify")) {
                return verify(body);
            }
            return new MockResponse().setResponseCode(404);
        }

        private MockResponse challenge(String body) {
            JsonNode parsed = parse(body);
            assertTrue(parsed.path("password").isMissingNode(),
                    "the challenge request must not carry a password field");
            aPub = new BigInteger(1, HEX.parseHex(parsed.path("client_public").asText()));

            if (namedGroup != null && namedGroup != group) {
                // Name a different group and answer in it; the client is
                // expected to restart rather than continue with the A it sent.
                SrpGroup named = namedGroup;
                namedGroup = null;
                return challengeBody(named, BigInteger.ONE);
            }
            bPriv = new BigInteger(1, "2".repeat(64).getBytes(StandardCharsets.US_ASCII));
            bPub = Srp.multiplier(group).multiply(verifier)
                    .add(group.generator().modPow(bPriv, group.modulus()))
                    .mod(group.modulus());
            return challengeBody(group, bPub);
        }

        private MockResponse challengeBody(SrpGroup named, BigInteger publicValue) {
            return new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"srp_session\":\"opaque-session-token\",\"identity\":\"" + IDENTITY + "\","
                            + "\"salt\":\"" + HEX.formatHex(salt) + "\",\"group\":\"" + named.wireName() + "\","
                            + "\"kdf\":\"" + kdf.kdf() + "\",\"iterations\":" + kdf.iterations() + ","
                            + "\"b_pub\":\"" + HEX.formatHex(Srp.pad(publicValue, named.byteLength())) + "\"}");
        }

        private MockResponse verify(String body) {
            JsonNode parsed = parse(body);
            assertEquals("opaque-session-token", parsed.path("srp_session").asText(),
                    "srp_session must be echoed verbatim");

            // S = (A * v^u)^b mod N — the server's own derivation.
            BigInteger u = Srp.hashToInt(Srp.pad(aPub, group.byteLength()), Srp.pad(bPub, group.byteLength()));
            BigInteger s = aPub.multiply(verifier.modPow(u, group.modulus())).mod(group.modulus())
                    .modPow(bPriv, group.modulus());
            byte[] sessionKey = Srp.hash(Srp.pad(s, group.byteLength()));
            byte[] m1 = HEX.parseHex(parsed.path("client_proof").asText());
            String proof = Srp.toHex(Srp.hash(Srp.pad(aPub, group.byteLength()), m1, sessionKey));
            if (corruptServerProof) {
                proof = "0".repeat(proof.length());
            }

            // Cookies are set exactly as on /auth/login (§23.5) — including on
            // the corrupt-proof path, so the test can assert they are discarded.
            MockResponse response = new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/")
                    .addHeader("Set-Cookie", "axiam_refresh=refresh-tok; Path=/");
            if (mfaRequired) {
                return response.setResponseCode(202).setBody(
                        "{\"challenge_token\":\"mfa-challenge\",\"available_methods\":[\"totp\"],"
                                + "\"server_proof\":\"" + proof + "\"}");
            }
            return response.setResponseCode(200).setBody(
                    "{\"session_id\":\"55555555-5555-5555-5555-555555555555\",\"expires_in\":900,"
                            + "\"server_proof\":\"" + proof + "\"}");
        }

        private static JsonNode parse(String body) {
            try {
                return MAPPER.readTree(body);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
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
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    // -----------------------------------------------------------------------

    /** The happy path against real arithmetic on both sides. */
    @Test
    void loginSrpEstablishesASessionAgainstAServerThatOnlyHoldsAVerifier() throws Exception {
        FakeSrpServer fake = new FakeSrpServer(SrpGroup.RFC5054_2048);
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                assertTrue(client.srpAvailable());
                LoginResult result = client.loginSrp(IDENTITY, PASSWORD.clone());
                assertFalse(result.mfaRequired());
                assertNotNull(result.user());
                assertEquals("11111111-1111-1111-1111-111111111111", result.user().userId());
            }
        }
    }

    /**
     * &sect;23.1's hard requirement that both login paths return the same
     * result type: an application switching a tenant to SRP must not need a
     * second result handler.
     */
    @Test
    void loginSrpReturnsTheSameMfaBranchAsLogin() throws Exception {
        FakeSrpServer fake = new FakeSrpServer(SrpGroup.RFC5054_2048);
        fake.mfaRequired = true;
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                LoginResult result = client.loginSrp(IDENTITY, PASSWORD.clone());
                assertTrue(result.mfaRequired(), "a 202 must surface as mfaRequired, not as an exception");
                assertNotNull(result.challengeToken());
                assertEquals("mfa-challenge", result.challengeToken().expose());
                assertNull(result.user());
            }
        }
    }

    /**
     * {@code A} is computed before the server has named a group, so a tenant on
     * a narrower group must work rather than fail.
     */
    @Test
    void loginSrpRestartsWhenTheServerNamesAnotherGroup() throws Exception {
        FakeSrpServer fake = new FakeSrpServer(SrpGroup.RFC5054_2048);
        fake.namedGroup = SrpGroup.RFC5054_2048; // differs from the 4096 opening guess
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                assertFalse(client.loginSrp(IDENTITY, PASSWORD.clone()).mfaRequired());
            }
        }
    }

    /**
     * &sect;23.7 rule 5. The assertion is on the ABSENCE of a session, not
     * merely on a thrown message: skipping {@code M2} keeps the half of SRP
     * that authenticates the client and throws away the half that
     * authenticates the server.
     */
    @Test
    void aWrongServerProofYieldsAuthErrorAndNoSession() throws Exception {
        FakeSrpServer fake = new FakeSrpServer(SrpGroup.RFC5054_2048);
        fake.corruptServerProof = true;
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                assertThrows(AuthError.class, () -> client.loginSrp(IDENTITY, PASSWORD.clone()));
                // The cookies the rogue server set must not survive: an
                // endpoint that cannot prove it holds the verifier is not the
                // server it claims to be.
                assertNull(client.session().cachedAccessToken(),
                        "the access cookie from an unverified server was kept");
            }
        }
    }

    /**
     * A 404 is a property of the tenant, so a caller can fall back to
     * {@code login()} without mistaking it for a bad password.
     */
    @Test
    void aTenantWithSrpDisabledIsNotACredentialFailure() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(404));
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                NetworkError error = assertThrows(NetworkError.class,
                        () -> client.loginSrp(IDENTITY, PASSWORD.clone()));
                assertTrue(error.getMessage().contains("srp_mode"), error.getMessage());
            }
        }
    }

    @Test
    void aWrongPasswordIsAnAuthError() throws Exception {
        FakeSrpServer fake = new FakeSrpServer(SrpGroup.RFC5054_2048);
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    String path = request.getPath() == null ? "" : request.getPath();
                    if (path.endsWith("/auth/srp/verify")) {
                        return new MockResponse().setResponseCode(401)
                                .setBody("{\"error\":\"authentication_failed\"}");
                    }
                    return fake.dispatch(request);
                }
            });
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                assertThrows(AuthError.class, () -> client.loginSrp(IDENTITY, "wrong".toCharArray()));
            }
        }
    }

    /**
     * &sect;23.7 rule 7 and &sect;23.3 rule 10. A user whose password is
     * perfectly good must never be shown "invalid username or password"
     * because the tenant moved to {@code srp_mode: required}.
     */
    @Test
    void srpRequiredIsAnAuthzErrorRatherThanAnAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(403)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"srp_required\",\"message\":\"this tenant requires SRP\"}"));
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                assertThrows(AuthzError.class, () -> client.login(IDENTITY, "hunter2"));
            }
        }
    }

    /**
     * &sect;23.7 rule 8: {@code A}, {@code M1}, {@code srp_session} and the
     * salt must reach no log record. This SDK's telemetry hook is the sink an
     * application would attach a metrics exporter to, so drive one and read it
     * back — {@code srp_session} in particular is bearer-equivalent while it
     * lives.
     */
    @Test
    void nothingSensitiveReachesTheTelemetrySink() throws Exception {
        FakeSrpServer fake = new FakeSrpServer(SrpGroup.RFC5054_2048);
        StringBuilder sink = new StringBuilder();
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .telemetryHook(event -> sink.append(event))
                    .build()) {
                client.loginSrp(IDENTITY, PASSWORD.clone());
            }
        }

        // Pull the exact values that crossed the wire out of the recorded
        // bodies rather than guessing at them, so this cannot pass by looking
        // for a string the client never produced.
        String logged = sink.toString();
        for (String body : fake.bodies) {
            JsonNode parsed = MAPPER.readTree(body);
            for (String key : List.of("client_public", "client_proof", "srp_session")) {
                String value = parsed.path(key).asText("");
                if (!value.isEmpty()) {
                    assertFalse(logged.contains(value), "§23.7 rule 8: " + key + " reached the telemetry sink");
                }
            }
        }
        assertFalse(logged.contains(HEX.formatHex(fake.salt)), "the salt reached the telemetry sink");
        assertFalse(logged.contains(new String(PASSWORD)), "the password reached the telemetry sink");
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment through the client API
    // -----------------------------------------------------------------------

    @Test
    void srpEnrollmentProducesAVerifierReproducibleFromItsOwnSalt() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.test", TENANT_ID).build()) {
            SrpKdfParams params = new SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000, 0, 0);
            SrpEnrollment first = client.srpEnrollment(IDENTITY, PASSWORD.clone(), null, params);

            assertEquals(SrpGroup.RFC5054_4096.wireName(), first.group(), "the default group");
            assertEquals(64, first.salt().length(), "the salt must be 32 bytes");
            assertEquals(0, first.memoryKib(), "pbkdf2 enrolment must not carry argon2 parameters");
            assertEquals(0, first.parallelism());

            byte[] x = Srp.deriveX(IDENTITY, PASSWORD.clone(), HEX.parseHex(first.salt()), params);
            assertEquals(first.verifier(), Srp.computeVerifier(SrpGroup.RFC5054_4096, x),
                    "the reported verifier is not g^x for the reported salt");

            // A reused salt would make every verifier in a tenant equally
            // attackable with one precomputation.
            SrpEnrollment second = client.srpEnrollment(IDENTITY, PASSWORD.clone(), null, params);
            assertFalse(first.salt().equals(second.salt()));

            // Argon2id enrolment carries its memory and lane costs, and the
            // JSON is the exact shape §23.5 defines.
            SrpEnrollment argon = client.srpEnrollment(IDENTITY, PASSWORD.clone(), SrpGroup.RFC5054_2048,
                    new SrpKdfParams(SrpKdfParams.ARGON2ID, 1, 8192, 1));
            JsonNode json = argon.toJson(MAPPER);
            assertEquals("rfc5054_2048", json.path("group").asText());
            assertEquals(8192, json.path("memory_kib").asInt());
            assertEquals(1, json.path("parallelism").asInt());
            assertTrue(json.has("salt") && json.has("verifier"));
        }
    }

    @Test
    void srpEnrollmentRefusesAKdfThisSdkDoesNotImplement() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.test", TENANT_ID).build()) {
            assertThrows(NetworkError.class, () -> client.srpEnrollment(
                    IDENTITY, PASSWORD.clone(), null, new SrpKdfParams("scrypt", 1, 0, 0)));
        }
    }
}
