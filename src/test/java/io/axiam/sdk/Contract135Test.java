package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.management.models.AssignRoleToGroupRequest;
import io.axiam.sdk.management.models.AssignRoleToServiceAccountRequest;
import io.axiam.sdk.management.models.AssignRoleToUserRequest;
import io.axiam.sdk.management.models.UpdateWebhookRequest;
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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract 1.34 &sect;5.2.2 and contract 1.35 &sect;5.2.3 — the acting tenant vs
 * the principal tenant, and tenant-scoped role assignments.
 *
 * <p>Two of these rules are the kind an SDK breaks silently rather than loudly,
 * which is why they are pinned here rather than left to the generated surface
 * test:
 *
 * <ul>
 *   <li><strong>&sect;5.2.2 rule 2.</strong> A registration record for the
 *       caller's <em>own</em> password is sealed against the tenant the account
 *       lives in, not the one the client is pointed at. Get it wrong and the
 *       server answers "the OPAQUE session was issued for a different tenant" —
 *       but only for an organization-level principal that has switched tenant,
 *       so it passes every test written against an ordinary account.
 *   <li><strong>&sect;5.2.3 rule 1.</strong> {@code tenant_scope: []} is
 *       refused with 400. {@code @JsonInclude(NON_NULL)} does not prevent it:
 *       {@code List.of()} is the natural thing to pass for "no tenants named",
 *       and it is not null.
 * </ul>
 */
class Contract135Test {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String ACTING_TENANT = "33333333-3333-3333-3333-333333333333";
    private static final String PRINCIPAL_TENANT = "55555555-5555-5555-5555-555555555555";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";

    /**
     * Minted per run rather than written down: nothing here depends on the
     * value, and a literal that reads like a credential is a finding for every
     * secret scanner that looks at this repository.
     */
    private static String passwordText() {
        byte[] entropy = new byte[8];
        RANDOM.nextBytes(entropy);
        return "fixture-" + HexFormat.of().formatHex(entropy);
    }

    /** The same, as the {@code char[]} the OPAQUE surface takes. */
    private static char[] password() {
        return passwordText().toCharArray();
    }

    @BeforeEach
    void installFake() {
        OpaqueTestSupport.installFake();
    }

    @AfterEach
    void restoreLoader() {
        OpaqueTestSupport.reset();
    }

    /** A server answering {@code /auth/login} and {@code register/start}. */
    private static final class FakeServer extends Dispatcher {

        final List<String> registerStartBodies = new ArrayList<>();
        String userExtra = "";

        @Override
        public MockResponse dispatch(RecordedRequest request) {
            String path = request.getPath() == null ? "" : request.getPath();
            if (path.startsWith("/api/v1/auth/opaque/register/start")) {
                registerStartBodies.add(request.getBody().readUtf8());
                return new MockResponse()
                        .setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"opaque_session\":\"reg-handle\","
                                + "\"registration_response\":\"726573703a\","
                                + "\"ksf\":\"argon2id\",\"memory_kib\":8192,"
                                + "\"iterations\":1,\"parallelism\":1}");
            }
            if (path.startsWith("/api/v1/auth/login")) {
                return new MockResponse()
                        .setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/")
                        .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\","
                                + "\"username\":\"alice\",\"email\":\"alice@example.com\""
                                + userExtra + "},"
                                + "\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                                + "\"expires_in\":900}");
            }
            return new MockResponse().setResponseCode(404);
        }
    }

    private static String fakeAccessToken() {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"" + ACTING_TENANT + "\","
                + "\"org_id\":\"" + ORG_ID + "\","
                + "\"jti\":\"22222222-2222-2222-2222-222222222222\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 900) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private interface Body {
        void run(FakeServer fake, AxiamClient client) throws Exception;
    }

    private static void withClient(String userExtra, Body body) throws Exception {
        FakeServer fake = new FakeServer();
        fake.userExtra = userExtra;
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(fake);
            server.start();
            try (AxiamClient client =
                         AxiamClient.builder(server.url("/").toString(), "acme").build()) {
                body.run(fake, client);
            }
        }
    }

    private static JsonNode parse(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // -----------------------------------------------------------------
    // §5.2.2 — acting tenant vs principal tenant
    // -----------------------------------------------------------------

    @Test
    @DisplayName("§5.2.2 rule 1: an absent principal tenant reads as the acting tenant")
    void absentPrincipalTenantReadsAsActing() throws Exception {
        // A server older than contract 1.34 omits `principal_tenant_id` and
        // cannot switch the acting tenant either, so reading `tenant_id` there
        // is not a guess — it is the only value the field could have had.
        withClient(",\"tenant_id\":\"" + ACTING_TENANT + "\"", (fake, client) -> {
            LoginResult result = client.login("alice@example.com", passwordText());
            PrincipalScope scope = result.scope();
            assertNotNull(scope, "a server reporting tenant_id reports a scope");
            assertEquals(UUID.fromString(ACTING_TENANT), scope.principalTenantId());
        });
    }

    @Test
    @DisplayName("§5.2.2: a divergent principal tenant is reported separately")
    void divergentPrincipalTenantIsReported() throws Exception {
        String extra = ",\"tenant_id\":\"" + ACTING_TENANT + "\""
                + ",\"principal_tenant_id\":\"" + PRINCIPAL_TENANT + "\""
                + ",\"principal_tenant_slug\":\"organization\""
                + ",\"org_id\":\"" + ORG_ID + "\""
                + ",\"organization_level\":true";
        withClient(extra, (fake, client) -> {
            LoginResult result = client.login("alice@example.com", passwordText());
            PrincipalScope scope = result.scope();
            assertNotNull(scope);
            assertEquals(UUID.fromString(ACTING_TENANT), scope.actingTenantId());
            assertEquals(UUID.fromString(PRINCIPAL_TENANT), scope.principalTenantId());
            assertEquals("organization", scope.principalTenantSlug());
            // Rule 3: read the organization from the session rather than
            // resolving a slug through the `super-admin`-only endpoint.
            assertEquals(UUID.fromString(ORG_ID), scope.orgId());
            assertTrue(result.organizationLevel());
        });
    }

    @Test
    @DisplayName("§5.2.3: reachable_tenant_ids narrows a principal that still reports organization_level")
    void reachableTenantIdsNarrows() throws Exception {
        String reachable = "66666666-6666-6666-6666-666666666666";
        String extra = ",\"tenant_id\":\"" + ACTING_TENANT + "\""
                + ",\"organization_level\":true"
                + ",\"reachable_tenant_ids\":[\"" + reachable + "\"]";
        withClient(extra, (fake, client) -> {
            LoginResult result = client.login("alice@example.com", passwordText());
            PrincipalScope scope = result.scope();
            assertNotNull(scope);
            // A narrowed principal still reports organizationLevel: true, which
            // is exactly why gating on that flag alone offers tenants the
            // server refuses.
            assertTrue(result.organizationLevel());
            assertEquals(List.of(UUID.fromString(reachable)), scope.reachableTenantIds());
        });
    }

    @Test
    @DisplayName("§5.2.3: an absent reach is unrestricted, never an empty list")
    void absentReachIsNullNotEmpty() throws Exception {
        withClient(",\"tenant_id\":\"" + ACTING_TENANT + "\"", (fake, client) -> {
            LoginResult result = client.login("alice@example.com", passwordText());
            PrincipalScope scope = result.scope();
            assertNotNull(scope);
            // An empty list would read as "reaches nothing", the opposite of
            // what an omitted field means here.
            assertNull(scope.reachableTenantIds());
        });
    }

    // -----------------------------------------------------------------
    // §5.2.2 rule 2 — which tenant a registration record is sealed against
    // -----------------------------------------------------------------

    @Test
    @DisplayName("§5.2.2 rule 2: opaqueEnrollment seals against the acting tenant")
    void enrollmentSealsAgainstActingTenant() throws Exception {
        String extra = ",\"tenant_id\":\"" + ACTING_TENANT + "\""
                + ",\"principal_tenant_id\":\"" + PRINCIPAL_TENANT + "\"";
        withClient(extra, (fake, client) -> {
            client.login("alice@example.com", passwordText());
            client.opaqueEnrollment(password());

            JsonNode body = parse(fake.registerStartBodies.get(0));
            // Creating *another* account seals against the tenant it is created
            // in — the one this client was pointed at.
            assertEquals("acme", body.path("tenant_slug").asText());
            assertTrue(body.path("tenant_id").isMissingNode());
        });
    }

    @Test
    @DisplayName("§5.2.2 rule 2: opaqueEnrollmentForSelf seals against the principal tenant")
    void enrollmentForSelfSealsAgainstPrincipalTenant() throws Exception {
        String extra = ",\"tenant_id\":\"" + ACTING_TENANT + "\""
                + ",\"principal_tenant_id\":\"" + PRINCIPAL_TENANT + "\""
                + ",\"organization_level\":true";
        withClient(extra, (fake, client) -> {
            client.login("alice@example.com", passwordText());
            client.opaqueEnrollmentForSelf(password());

            JsonNode body = parse(fake.registerStartBodies.get(0));
            assertEquals(PRINCIPAL_TENANT, body.path("tenant_id").asText());
            // The acting tenant's slug must not travel alongside the principal
            // tenant's id, or it out-votes it server-side.
            assertTrue(body.path("tenant_slug").isMissingNode());
        });
    }

    @Test
    @DisplayName("§5.2.2 rule 2: enrolling for yourself before a login refuses rather than guessing")
    void enrollmentForSelfRefusesBeforeLogin() throws Exception {
        withClient("", (fake, client) -> {
            NetworkError error = assertThrows(NetworkError.class,
                    () -> client.opaqueEnrollmentForSelf(password()));
            assertTrue(error.getMessage().contains("principal tenant"),
                    "the error should name what is missing, got: " + error.getMessage());
        });
    }

    // -----------------------------------------------------------------
    // §5.2.3 rules 1 and 2 — tenant_scope on an assignment
    // -----------------------------------------------------------------

    @Test
    @DisplayName("§5.2.3 rule 1: an empty tenant_scope never reaches the wire")
    void emptyTenantScopeIsDropped() {
        // `[]` is refused with 400, and `List.of()` is the natural thing to
        // pass for "no tenants named", so both spellings of absent must travel
        // the same way: by not appearing.
        assertNull(new AssignRoleToUserRequest(null, List.of(), UUID.randomUUID()).tenantScope());
        assertNull(new AssignRoleToGroupRequest(UUID.randomUUID(), null, List.of()).tenantScope());
        assertNull(new AssignRoleToServiceAccountRequest(
                null, UUID.randomUUID(), List.of()).tenantScope());
    }

    @Test
    @DisplayName("§5.2.3 rule 2: a named tenant_scope is sent")
    void namedTenantScopeIsSent() throws Exception {
        // Dropping a scope the caller *did* name would turn a refusal they need
        // to see into a success that silently applied no restriction.
        UUID scoped = UUID.randomUUID();
        var body = new AssignRoleToUserRequest(null, List.of(scoped), UUID.randomUUID());

        assertEquals(List.of(scoped), body.tenantScope());
        assertTrue(MAPPER.writeValueAsString(body).contains(scoped.toString()));
    }

    @Test
    @DisplayName("§5.2.3: the empty-list rule is one field wide, not a blanket")
    void otherEmptyListsAreStillSent() throws Exception {
        // Elsewhere `[]` is meaningful — a replacement body clearing a list —
        // and dropping it would make "remove every entry" inexpressible.
        String json = MAPPER.writeValueAsString(
                UpdateWebhookRequest.builder().events(List.of()).build());

        assertFalse(json.contains("tenant_scope"));
        assertTrue(json.contains("\"events\":[]"),
                "clearing a webhook's event list must stay expressible, got: " + json);
    }
}
