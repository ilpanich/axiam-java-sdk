package io.axiam.sdk;

import io.axiam.sdk.account.MfaEnrollment;
import io.axiam.sdk.account.PasswordResetConfirmation;
import io.axiam.sdk.account.PasswordResetContext;
import io.axiam.sdk.account.PasswordResetRequest;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;25 — account lifecycle and MFA enrolment.
 *
 * <p>The assertions worth reading twice are the &sect;25.4 pair:
 * {@code requestPasswordResetIsSilentAboutWhetherTheAccountExists} pins the
 * account-enumeration guarantee to the SDK's <em>surface</em> rather than to
 * the server's behaviour, and
 * {@code resetContextSendsTheTokenAsAQueryParameterNotInThePath} exists because
 * building that URL by concatenation percent-escapes the {@code ?} into the
 * path — a bug that produces a 404 which reads exactly like an expired token.
 */
class AxiamClientAccountLifecycleTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String TENANT_SLUG = "acme";
    private static final String ORG_SLUG = "globex";
    private static final UUID TENANT_ID = UUID.fromString("6f8f5771-5090-4a26-b245-3988d9a1501b");
    private static final String SETUP_TOKEN = "setup-token-fixture-do-not-log";
    private static final String RESET_TOKEN = "reset-token-fixture-do-not-log";

    private static AxiamClient client(String base) {
        return AxiamClient.builder(base, TENANT_SLUG).orgSlug(ORG_SLUG).build();
    }

    private static MockResponse json(int code, String body) {
        return new MockResponse()
                .setResponseCode(code)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    private static MockResponse enrollmentResponse() {
        return json(200, "{\"secret_base32\":\"JBSWY3DPEHPK3PXP\","
                + "\"totp_uri\":\"otpauth://totp/AXIAM:alice?secret=JBSWY3DPEHPK3PXP&issuer=AXIAM\"}");
    }

    // -----------------------------------------------------------------------
    // §25.2 rule 1 — login gains a third outcome
    // -----------------------------------------------------------------------

    @Test
    void loginAnswers403MfaSetupRequiredAsTheThirdOutcome() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(403, "{\"mfa_setup_required\":true,"
                        + "\"setup_token\":\"" + SETUP_TOKEN + "\"}"));

                LoginResult result = client.login("alice@example.com", "pw");

                assertTrue(result.mfaSetupRequired(),
                        "a tenant that requires MFA on an account without it is not a failure");
                assertFalse(result.mfaRequired(), "the account has no factor to challenge yet");
                assertNull(result.user(), "there is no session, so there is no user");
                assertEquals(SETUP_TOKEN, java.util.Objects.requireNonNull(result.setupToken()).expose());
            }
        }
    }

    @Test
    void anOrdinary403IsStillAFailure() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // §25.2 rule 1 keys the third outcome on the error CODE, never
                // on the status alone: a plain 403 must keep throwing.
                server.enqueue(json(403, "{\"error\":\"authorization_denied\","
                        + "\"message\":\"tenant suspended\"}"));

                assertThrows(RuntimeException.class, () -> client.login("alice@example.com", "pw"));
            }
        }
    }

    @Test
    void theThreeOutcomesAreMutuallyExclusive() {
        LoginResult setup = LoginResult.mfaSetupRequired(Sensitive.of(SETUP_TOKEN));
        assertTrue(setup.mfaSetupRequired());
        assertFalse(setup.mfaRequired());
        assertNull(setup.user());

        // The 3-argument compat constructor keeps every pre-1.28 call site
        // compiling and answering false for the new flag (§25.2 rule 1: the
        // change is additive where the result is a flags record).
        LoginResult challenge = new LoginResult(true, Sensitive.of("challenge"), null);
        assertTrue(challenge.mfaRequired());
        assertFalse(challenge.mfaSetupRequired());
        assertNull(challenge.setupToken());
    }

    // -----------------------------------------------------------------------
    // §25.1 — voluntary enrolment
    // -----------------------------------------------------------------------

    @Test
    void mfaEnrollReturnsTheSecretAndItsUri() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(enrollmentResponse());

                MfaEnrollment enrollment = client.mfaEnroll();

                assertEquals("JBSWY3DPEHPK3PXP", enrollment.secretBase32().expose());
                assertTrue(enrollment.totpUri().expose().startsWith("otpauth://totp/"));

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/mfa/enroll", request.getPath());
                assertEquals("POST", request.getMethod());
            }
        }
    }

    @Test
    void bothHalvesOfAnEnrolmentAreSensitive() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(enrollmentResponse());

                MfaEnrollment enrollment = client.mfaEnroll();

                // §25.3: the otpauth URI CONTAINS the secret. Wrapping only the
                // bare secret and printing the URI leaks the same bytes — this
                // is the mistake the rule exists to name.
                assertFalse(enrollment.secretBase32().toString().contains("JBSWY3DPEHPK3PXP"));
                assertFalse(enrollment.totpUri().toString().contains("JBSWY3DPEHPK3PXP"));
            }
        }
    }

    @Test
    void mfaConfirmReportsWhetherTheFactorIsLive() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(200, "{\"mfa_enabled\":true}"));

                assertTrue(client.mfaConfirm("123456"));

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/mfa/confirm", request.getPath());
                assertEquals("123456", MAPPER.readTree(request.getBody().readUtf8())
                        .path("totp_code").asText());
            }
        }
    }

    @Test
    void aWrongCodeIsAnAuthError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(401, "{\"message\":\"invalid code\"}"));
                assertThrows(AuthError.class, () -> client.mfaConfirm("000000"));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §25.1 / §25.2 rule 2 — forced enrolment completes a login
    // -----------------------------------------------------------------------

    @Test
    void mfaSetupEnrollAuthenticatesWithTheSetupTokenAlone() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(enrollmentResponse());

                client.mfaSetupEnroll(Sensitive.of(SETUP_TOKEN));

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/mfa/setup/enroll", request.getPath());
                // There is no session yet — the setup token IS the credential.
                assertEquals(SETUP_TOKEN, MAPPER.readTree(request.getBody().readUtf8())
                        .path("setup_token").asText());
            }
        }
    }

    @Test
    void mfaSetupConfirmAdoptsTheSessionLikeALogin() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(200, "{\"session_id\":\"" + UUID.randomUUID() + "\",\"expires_in\":900}")
                        .addHeader("Set-Cookie",
                                "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/")
                        .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
                        .addHeader("X-CSRF-Token", "csrf-tok"));

                LoginResult result = client.mfaSetupConfirm(Sensitive.of(SETUP_TOKEN), "123456");

                // §25.2 rule 2: this IS the completion of a login, so the
                // credentials it returns are adopted exactly as login() adopts
                // them — not handed back for the caller to install.
                assertFalse(result.mfaRequired());
                assertFalse(result.mfaSetupRequired());
                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/mfa/setup/confirm", request.getPath());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §25.1 — email verification
    // -----------------------------------------------------------------------

    @Test
    void verifyEmailNeedsNoSessionAndCarriesTheTenantInTheBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(204));

                client.verifyEmail(Sensitive.of("verify-token"), TENANT_ID);

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/verify-email", request.getPath());
                JsonNode body = MAPPER.readTree(request.getBody().readUtf8());
                // Not ?tenant_id=: §12.1 rule 2's query convention is scoped to
                // /oauth2/*, and this endpoint is not one of those.
                assertEquals(TENANT_ID.toString(), body.path("tenant_id").asText());
                assertEquals("verify-token", body.path("token").asText());
            }
        }
    }

    @Test
    void resendVerificationAcceptsA202() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(202));

                client.resendVerification("alice@example.com", TENANT_ID);

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/resend-verification", request.getPath());
            }
        }
    }

    @Test
    void anExpiredVerificationTokenIsAnError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(400, "{\"message\":\"token expired\"}"));
                assertThrows(NetworkError.class,
                        () -> client.verifyEmail(Sensitive.of("stale"), TENANT_ID));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §25.7 — the two resends are two operations
    // -----------------------------------------------------------------------

    /**
     * The authenticated resend carries no address, and hits its own path.
     *
     * <p>The body assertion is the one that matters: a signature with no address
     * parameter proves nothing about what the SDK serializes, and an address on
     * this endpoint would let an authenticated session mail an arbitrary one.
     */
    @Test
    void resendOwnVerificationSendsNoAddress() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(200, "{\"sent\":true}"));

                client.resendOwnVerification();

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/users/me/resend-verification", request.getPath());
                JsonNode body = MAPPER.readTree(request.getBody().readUtf8());
                assertFalse(body.fieldNames().hasNext(),
                        "caller-supplied data went out: " + body);
            }
        }
    }

    /**
     * The two resends are distinct operations against distinct paths.
     *
     * <p>An SDK that aliased one to the other would reintroduce the exact defect
     * §25.7 exists to describe, and every other test here would still pass — so
     * this asserts on the path each one actually reached.
     */
    @Test
    void theTwoResendsReachDifferentEndpoints() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(200));
                server.enqueue(json(200, "{\"sent\":true}"));

                client.resendVerification("alice@example.com", TENANT_ID);
                client.resendOwnVerification();

                assertEquals("/api/v1/auth/resend-verification", server.takeRequest().getPath());
                assertEquals("/api/v1/users/me/resend-verification", server.takeRequest().getPath());
            }
        }
    }

    /**
     * A {@code 409} surfaces, and is not retried through the public endpoint.
     *
     * <p>The bug this operation exists to fix was a success return on a request
     * that achieved nothing, so "throws" is the assertion — and the request
     * count is what rules out the §25.7 rule 2 fallback, which would turn both
     * failures back into a normal return with an extra round-trip.
     */
    @Test
    void resendOwnVerificationSurfacesA409WithoutFallingBack() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(409));

                assertThrows(AuthzError.class, client::resendOwnVerification);

                assertEquals(1, server.getRequestCount(),
                        "a second request means a fallback to the enumeration-safe "
                                + "endpoint, which rebuilds the bug");
                assertEquals("/api/v1/users/me/resend-verification",
                        server.takeRequest().getPath());
            }
        }
    }

    /** A {@code 429} surfaces too, as the §2 mapping of a rate limit. */
    @Test
    void resendOwnVerificationSurfacesTheDailyLimit() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(429));

                assertThrows(NetworkError.class, client::resendOwnVerification);

                assertEquals(1, server.getRequestCount(),
                        "a second request means a fallback to the enumeration-safe endpoint");
                assertEquals("/api/v1/users/me/resend-verification",
                        server.takeRequest().getPath());
            }
        }
    }

    // -----------------------------------------------------------------------
    // §5.2 — organization-level principals
    // -----------------------------------------------------------------------

    /**
     * {@code organizationLevel} is carried through from the login response.
     *
     * <p>It is what an application checks <em>before</em> offering a tenant
     * switch: such a principal changes the tenant it acts on with a header on
     * the next request, and an ordinary one cannot, so offering the switch to
     * both turns a distinction the server made into a 403 the user discovers.
     *
     * <p>The absent case is the one that matters: a server older than contract
     * 1.31 omits the field, and {@code false} is the safe reading — the client
     * then offers no cross-tenant action rather than one that would fail.
     */
    @Test
    void loginReportsAnOrganizationLevelPrincipal() throws Exception {
        record Case(String userJson, boolean expected) { }
        Case[] cases = {
            new Case("{\"id\":\"u1\",\"organization_level\":true}", true),
            new Case("{\"id\":\"u1\",\"organization_level\":false}", false),
            new Case("{\"id\":\"u1\"}", false),
        };

        for (Case each : cases) {
            try (MockWebServer server = new MockWebServer()) {
                server.start();
                try (AxiamClient client = client(server.url("/").toString())) {
                    server.enqueue(json(200,
                            "{\"user\":" + each.userJson() + ",\"session_id\":\"s1\","
                                    + "\"expires_in\":900}")
                            .addHeader("Set-Cookie", "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/")
                            .addHeader("Set-Cookie", "axiam_refresh=r; Path=/"));

                    LoginResult result = client.login("alice@example.com", "correct horse");

                    assertEquals(each.expected(), result.organizationLevel(),
                            "organizationLevel for user " + each.userJson());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // §25.4 — password reset
    // -----------------------------------------------------------------------

    @Test
    void requestPasswordResetIsSilentAboutWhetherTheAccountExists() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // Both an existing and an unknown address answer 202 with an
                // empty body, and the SDK returns void — there is no field, no
                // boolean and no exception for a caller to build an
                // enumeration oracle out of (§25.4).
                server.enqueue(new MockResponse().setResponseCode(202));
                client.requestPasswordReset(new PasswordResetRequest("alice@example.com"));

                server.enqueue(new MockResponse().setResponseCode(202));
                client.requestPasswordReset(new PasswordResetRequest("nobody@example.com"));

                assertEquals(2, server.getRequestCount());
            }
        }
    }

    @Test
    void requestPasswordResetFillsTheWorkspaceFromTheClient() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(202));

                client.requestPasswordReset(new PasswordResetRequest("alice@example.com"));

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(ORG_SLUG, body.path("org_slug").asText());
                assertEquals(TENANT_SLUG, body.path("tenant_slug").asText());
            }
        }
    }

    @Test
    void anExplicitWorkspaceWinsOverTheClientConfiguration() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(202));

                client.requestPasswordReset(new PasswordResetRequest(
                        "alice@example.com", "other-org", TENANT_ID, null));

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals("other-org", body.path("org_slug").asText());
                assertEquals(TENANT_ID.toString(), body.path("tenant_id").asText());
                assertTrue(body.path("tenant_slug").isMissingNode(),
                        "a resolved tenant_id makes tenant_slug ambiguous, so it is omitted");
            }
        }
    }

    @Test
    void resetContextSendsTheTokenAsAQueryParameterNotInThePath() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(200, "{\"opaque\":null}"));

                client.passwordResetContext(Sensitive.of(RESET_TOKEN));

                RecordedRequest request = server.takeRequest();
                assertEquals("GET", request.getMethod());
                assertEquals("/api/v1/auth/reset/context?token=" + RESET_TOKEN, request.getPath());
            }
        }
    }

    @Test
    void aTenantWithoutOpaqueReportsNoPolicy() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(200, "{\"opaque\":null}"));

                PasswordResetContext context = client.passwordResetContext(Sensitive.of(RESET_TOKEN));

                assertNull(context.opaque(), "no policy means the plaintext path is allowed");
            }
        }
    }

    @Test
    void aTenantWithOpaqueHandsBackTheParametersUntouched() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                String opaque = "{\"mode\":\"required\",\"cipher_suite\":\"ristretto255-sha512\","
                        + "\"server_public_key\":\"c2VydmVyLXBr\",\"vendorSpecific\":\"must-survive\"}";
                server.enqueue(json(200, "{\"opaque\":" + opaque + "}"));

                PasswordResetContext context = client.passwordResetContext(Sensitive.of(RESET_TOKEN));

                // Structural equality: the SDK does not model, validate or
                // re-encode the §23 parameter block, it forwards it.
                assertEquals(MAPPER.readTree(opaque), context.opaque());
            }
        }
    }

    @Test
    void anUnknownExpiredOrConsumedTokenAllLookAlike() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                // §25.4 rule 3: the server refuses to distinguish these three,
                // and the SDK must not invent a distinction of its own.
                server.enqueue(json(404, "{}"));
                assertThrows(NetworkError.class,
                        () -> client.passwordResetContext(Sensitive.of(RESET_TOKEN)));
            }
        }
    }

    @Test
    void confirmSendsThePlaintextPasswordWhenTheTenantHasNoOpaque() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(204));

                client.confirmPasswordReset(new PasswordResetConfirmation(
                        Sensitive.of(RESET_TOKEN), Sensitive.of("new-password"), TENANT_ID));

                RecordedRequest request = server.takeRequest();
                assertEquals("/api/v1/auth/reset/confirm", request.getPath());
                JsonNode body = MAPPER.readTree(request.getBody().readUtf8());
                assertEquals("new-password", body.path("new_password").asText());
                assertTrue(body.path("opaque").isMissingNode());
            }
        }
    }

    @Test
    void confirmForwardsTheOpaqueRegistrationRecordVerbatim() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(new MockResponse().setResponseCode(204));
                JsonNode record = MAPPER.readTree(
                        "{\"registration_record\":\"cmVjb3Jk\",\"export_key_hint\":\"aGludA\"}");

                client.confirmPasswordReset(new PasswordResetConfirmation(
                        Sensitive.of(RESET_TOKEN), Sensitive.of("unused"), TENANT_ID, record));

                JsonNode body = MAPPER.readTree(server.takeRequest().getBody().readUtf8());
                assertEquals(record, body.path("opaque"));
            }
        }
    }

    @Test
    void aRejectedResetSurfacesTheError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(400, "{\"message\":\"password does not meet policy\"}"));

                assertThrows(NetworkError.class, () -> client.confirmPasswordReset(
                        new PasswordResetConfirmation(
                                Sensitive.of(RESET_TOKEN), Sensitive.of("x"), TENANT_ID)));
            }
        }
    }

    // -----------------------------------------------------------------------
    // async twins
    // -----------------------------------------------------------------------

    @Test
    void theAsyncTwinsReachTheSameEndpoints() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(enrollmentResponse());
                assertEquals("JBSWY3DPEHPK3PXP",
                        client.mfaEnrollAsync().join().secretBase32().expose());
                assertEquals("/api/v1/auth/mfa/enroll", server.takeRequest().getPath());

                server.enqueue(json(200, "{\"mfa_enabled\":true}"));
                assertTrue(client.mfaConfirmAsync("123456").join());
                assertEquals("/api/v1/auth/mfa/confirm", server.takeRequest().getPath());

                server.enqueue(enrollmentResponse());
                client.mfaSetupEnrollAsync(Sensitive.of(SETUP_TOKEN)).join();
                assertEquals("/api/v1/auth/mfa/setup/enroll", server.takeRequest().getPath());

                server.enqueue(new MockResponse().setResponseCode(204));
                client.verifyEmailAsync(Sensitive.of("t"), TENANT_ID).join();
                assertEquals("/api/v1/auth/verify-email", server.takeRequest().getPath());

                server.enqueue(new MockResponse().setResponseCode(202));
                client.resendVerificationAsync("alice@example.com", TENANT_ID).join();
                assertEquals("/api/v1/auth/resend-verification", server.takeRequest().getPath());

                server.enqueue(new MockResponse().setResponseCode(202));
                client.requestPasswordResetAsync(new PasswordResetRequest("alice@example.com")).join();
                assertEquals("/api/v1/auth/reset", server.takeRequest().getPath());

                server.enqueue(json(200, "{\"opaque\":null}"));
                client.passwordResetContextAsync(Sensitive.of(RESET_TOKEN)).join();
                assertTrue(server.takeRequest().getPath().startsWith("/api/v1/auth/reset/context?"));

                server.enqueue(new MockResponse().setResponseCode(204));
                client.confirmPasswordResetAsync(new PasswordResetConfirmation(
                        Sensitive.of(RESET_TOKEN), Sensitive.of("pw"), TENANT_ID)).join();
                assertEquals("/api/v1/auth/reset/confirm", server.takeRequest().getPath());
            }
        }
    }

    @Test
    void mfaSetupConfirmAsyncCompletesTheLogin() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                server.enqueue(json(200, "{\"session_id\":\"" + UUID.randomUUID() + "\",\"expires_in\":900}")
                        .addHeader("Set-Cookie",
                                "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/")
                        .addHeader("Set-Cookie", "axiam_refresh=refresh-cookie; Path=/")
                        .addHeader("X-CSRF-Token", "csrf-tok"));

                LoginResult result = client.mfaSetupConfirmAsync(Sensitive.of(SETUP_TOKEN), "123456").join();

                assertFalse(result.mfaSetupRequired());
                assertEquals("/api/v1/auth/mfa/setup/confirm", server.takeRequest().getPath());
            }
        }
    }

    @Test
    void everyOperationRefusesOnAClosedClient() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            AxiamClient client = client(server.url("/").toString());
            client.close();

            assertThrows(NetworkError.class, client::mfaEnroll);
            assertThrows(NetworkError.class, () -> client.mfaConfirm("1"));
            assertThrows(NetworkError.class,
                    () -> client.mfaSetupEnroll(Sensitive.of(SETUP_TOKEN)));
            assertThrows(NetworkError.class,
                    () -> client.mfaSetupConfirm(Sensitive.of(SETUP_TOKEN), "1"));
            assertThrows(NetworkError.class,
                    () -> client.verifyEmail(Sensitive.of("t"), TENANT_ID));
            assertThrows(NetworkError.class,
                    () -> client.resendVerification("a@b.c", TENANT_ID));
            assertThrows(NetworkError.class,
                    () -> client.requestPasswordReset(new PasswordResetRequest("a@b.c")));
            assertThrows(NetworkError.class,
                    () -> client.passwordResetContext(Sensitive.of(RESET_TOKEN)));
            assertThrows(NetworkError.class,
                    () -> client.confirmPasswordReset(new PasswordResetConfirmation(
                            Sensitive.of(RESET_TOKEN), Sensitive.of("pw"), TENANT_ID)));

            assertEquals(0, server.getRequestCount(), "a closed client makes no wire call");
        }
    }
}
