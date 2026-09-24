package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.errors.NetworkError;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;27.6.1 — the manifest additions (contract 1.51): {@code
 * resources[].metadata}, the two-shape role binding, and {@code service_accounts}.
 */
class ManifestAdditionsTest extends ManagementTestBase {

    private static final ObjectMapper OM = new ObjectMapper();
    private static final UUID RESOURCE_ID = UUID.fromString("77777777-7777-4777-8777-777777777777");
    private static final UUID ROLE_ID = UUID.fromString("66666666-6666-4666-8666-666666666666");
    private static final UUID SA_ID = UUID.fromString("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    private static final String STAMPS =
            "\"created_at\":\"2026-08-26T00:00:00Z\",\"updated_at\":\"2026-08-26T00:00:00Z\"";

    private void mountEmptyTenant() {
        for (String path : List.of("resources", "permissions", "roles", "groups", "users",
                "service-accounts")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
    }

    private static JsonNode metadata(String json) throws Exception {
        return OM.readTree(json);
    }

    private static String resourceBody(UUID id, String name, JsonNode metadata) {
        return resourceBody(id, name, metadata, null);
    }

    private static String resourceBody(UUID id, String name, JsonNode metadata,
                                        @org.jspecify.annotations.Nullable UUID parent) {
        return "{\"id\":\"" + id + "\",\"name\":\"" + name + "\",\"resource_type\":\"collection\","
                + "\"parent_id\":" + (parent == null ? "null" : "\"" + parent + "\"")
                + ",\"metadata\":" + metadata + ",\"tenant_id\":\"" + TENANT_ID + "\","
                + STAMPS + "}";
    }

    private static String saBody(UUID id, String name, @org.jspecify.annotations.Nullable String description) {
        return "{\"id\":\"" + id + "\",\"client_id\":\"client-" + id + "\",\"name\":\"" + name + "\","
                + "\"description\":" + (description == null ? "null" : "\"" + description + "\"")
                + ",\"status\":\"Active\",\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}";
    }

    private static String saCreatedBody(UUID id, String name) {
        return "{\"id\":\"" + id + "\",\"client_id\":\"client-" + id + "\",\"client_secret\":"
                + "\"the-secret-value\",\"name\":\"" + name + "\",\"description\":null,"
                + "\"status\":\"Active\",\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}";
    }

    private static String roleUserAssignment(UUID userId, @org.jspecify.annotations.Nullable UUID resourceId,
                                              @org.jspecify.annotations.Nullable Boolean inherit) {
        String user = "{\"id\":\"" + userId + "\",\"username\":\"user0\",\"email\":\"user0@example.test\","
                + "\"email_verified\":true,\"failed_login_attempts\":0,\"is_locked\":false,"
                + "\"metadata\":{},\"mfa_enabled\":false,\"status\":\"Active\",\"tenant_id\":\""
                + TENANT_ID + "\"," + STAMPS + "}";
        return "{\"user\":" + user
                + ",\"resource_id\":" + (resourceId == null ? "null" : "\"" + resourceId + "\"")
                + (inherit == null ? "" : ",\"inherit\":" + inherit) + "}";
    }

    // ------------------------------------------------------------------
    // resources[].metadata
    // ------------------------------------------------------------------

    @Test
    void metadataRoundTripsApplyThenPlanIsNoChange() throws Exception {
        JsonNode meta = metadata("{\"env\":\"prod\"}");
        mount("GET", "/api/v1/resources", 200,
                pageOf(resourceBody(RESOURCE_ID, "documents", meta)));
        for (String path : List.of("permissions", "roles", "groups", "users")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));

        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .metadata("docs", meta)
                .build();

        ManagementPlan plan = client.management().manifest().plan(manifest);
        assertTrue(plan.isConverged(), "a stated metadata equal to the server's own is NoChange: "
                + plan.changes());
    }

    @Test
    void changingOneKeyOfMetadataYieldsAnUpdateCarryingTheWholeObject() throws Exception {
        mount("GET", "/api/v1/resources", 200,
                pageOf(resourceBody(RESOURCE_ID, "documents", metadata("{\"env\":\"prod\"}"))));
        for (String path : List.of("permissions", "roles", "groups", "users")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        Route update = mount("PUT", "/api/v1/resources/" + RESOURCE_ID, 200,
                resourceBody(RESOURCE_ID, "documents", metadata("{\"env\":\"staging\",\"owner\":\"team-x\"}")));

        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .metadata("docs", metadata("{\"env\":\"staging\",\"owner\":\"team-x\"}"))
                .build();

        ApplyReport report = client.management().manifest().apply(manifest);
        assertTrue(report.isComplete());
        assertEquals(ApplyReport.Status.UPDATED, report.steps().get(0).outcome().status());
        assertEquals(metadata("{\"env\":\"staging\",\"owner\":\"team-x\"}"),
                update.last().json().path("metadata"),
                "the update body carries the WHOLE object, never a key-by-key merge");
    }

    // ------------------------------------------------------------------
    // Two-shape role binding
    // ------------------------------------------------------------------

    @Test
    void aResourceScopedBindingWithInheritFalseSendsBothFields() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/resources", 200, pageOf(resourceBody(RESOURCE_ID, "documents", metadata("{}"))));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        for (String sub : List.of("permissions", "users", "groups")) {
            mount("GET", "/api/v1/roles/" + ROLE_ID + "/" + sub, 200, "[]");
        }
        mount("GET", "/api/v1/users", 200, pageOf(userBody(0)));
        Route assign = mount("POST", "/api/v1/roles/" + ROLE_ID + "/users", 204, "");

        UUID userId = UUID.fromString("00000000-1111-4111-8111-111111111111");
        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .role("editor", "Editor", "Edits")
                .user("alice", "user0", "user0@example.test", null)
                .assignRole("alice", ManagementManifest.RoleBinding.scoped("editor", "docs", false))
                .build();

        client.management().manifest().apply(manifest);

        JsonNode body = assign.last().json();
        assertEquals(RESOURCE_ID.toString(), body.path("resource_id").asText());
        assertFalse(body.path("inherit").asBoolean(true));
        assertTrue(assign.last().keys().contains("inherit"));
    }

    @Test
    void anInheritingScopedBindingSendsNoInheritKey() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/resources", 200, pageOf(resourceBody(RESOURCE_ID, "documents", metadata("{}"))));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        for (String sub : List.of("permissions", "users", "groups")) {
            mount("GET", "/api/v1/roles/" + ROLE_ID + "/" + sub, 200, "[]");
        }
        mount("GET", "/api/v1/users", 200, pageOf(userBody(0)));
        Route assign = mount("POST", "/api/v1/roles/" + ROLE_ID + "/users", 204, "");

        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .role("editor", "Editor", "Edits")
                .user("alice", "user0", "user0@example.test", null)
                .assignRole("alice", ManagementManifest.RoleBinding.scoped("editor", "docs"))
                .build();

        client.management().manifest().apply(manifest);

        assertFalse(assign.last().keys().contains("inherit"),
                "an inheriting binding's inherit key must be entirely absent (never sent as true)");
    }

    /** §27.6.1: a subject holds a role at most once — plain-and-scoped included. */
    @Test
    void bindingOneRoleTwiceToOneSubjectIsRejectedWithZeroWireCalls() throws Exception {
        int before = totalCalls();
        NetworkError e = assertThrows(NetworkError.class, () -> ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .role("editor", "Editor", "Edits")
                .user("alice", "user0", "user0@example.test", null)
                .assignRole("alice", "editor")
                .assignRole("alice", ManagementManifest.RoleBinding.scoped("editor", "docs"))
                .build());
        assertTrue(e.getMessage().contains("more than once"), e.getMessage());
        assertEquals(before, totalCalls());
    }

    /** §27.6.1 item 2 last bullet / C-12 item 6: refused before any request. */
    @Test
    void aGlobalRoleBoundWithInheritFalseIsRefusedClientSide() {
        NetworkError e = assertThrows(NetworkError.class, () -> ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .globalRole("admin", "Administrator", "Everything")
                .user("alice", "user0", "user0@example.test", null)
                .assignRole("alice", ManagementManifest.RoleBinding.scoped("admin", "docs", false))
                .build());
        assertTrue(e.getMessage().contains("declared global"), e.getMessage());
    }

    /** Changing a binding's resource is unassign-then-assign, restoring on a failed assign. */
    @Test
    void aFailedRebindRestoresThePreviousBinding() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/resources", 200,
                page(resourceBody(RESOURCE_ID, "documents", metadata("{}")),
                        resourceBody(ARCHIVE_ID, "archive", metadata("{}"), RESOURCE_ID)));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/resources/" + ARCHIVE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200, "[]");
        UUID userId = UUID.fromString("00000000-1111-4111-8111-111111111111");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200,
                "[" + roleUserAssignment(userId, RESOURCE_ID, null) + "]");
        mount("GET", "/api/v1/users", 200, pageOf(userBody(0)));
        mount("DELETE", "/api/v1/roles/" + ROLE_ID + "/users/" + userId, 204, "");
        Route assign = mount("POST", "/api/v1/roles/" + ROLE_ID + "/users", 409, "{\"message\":\"conflict\"}");

        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .childResource("archive", "archive", "collection", "docs")
                .role("editor", "Editor", "Edits")
                .user("alice", "user0", "user0@example.test", null)
                .assignRole("alice", ManagementManifest.RoleBinding.scoped("editor", "archive"))
                .build();

        ApplyReport report = client.management().manifest().apply(manifest);

        assertFalse(report.isComplete());
        ApplyReport.AppliedStep failed = report.failure().orElseThrow();
        assertEquals(ApplyReport.Status.FAILED, failed.outcome().status());
        // This fixture's assign route answers 409 unconditionally (this harness's
        // Route has one fixed response, not a queue), so BOTH the drifted assign
        // and the restoring re-assign fail — proving the restore is attempted at
        // all (two calls to the same route) and that `restored` reports it
        // correctly (false) even when the restore itself does not hold.
        assertEquals(Boolean.FALSE, failed.outcome().restored());
        assertEquals(2, assign.calls(), "the failing assign, then the attempted restore");
    }

    /**
     * CONTRACT.md &sect;27.6.1 item 2's definition of the plain shape as "no resource":
     * a server assignment that carries a {@code resource_id} is NOT the same binding as
     * a manifest that states the role plainly, even when both inherit — the plain form
     * unconditionally means "no resource", so this must plan as {@code Update}
     * (unassign, then assign with no {@code resource_id}), never {@code NoChange}.
     */
    @Test
    void aPlainBindingOverAScopedAssignmentIsAnUpdate() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/resources", 200,
                pageOf(resourceBody(RESOURCE_ID, "site-1", metadata("{}"))));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Resident", "Resident")));
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200, "[]");
        UUID userId = UUID.fromString("00000000-1111-4111-8111-111111111111");
        // The server's existing assignment carries a resource_id (scoped, inheriting) —
        // the desired manifest binding below is plain.
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200,
                "[" + roleUserAssignment(userId, RESOURCE_ID, true) + "]");
        mount("GET", "/api/v1/users", 200, pageOf(userBody(0)));

        ManagementManifest manifest = ManagementManifest.builder()
                .role("resident", "Resident", "Resident")
                .user("ann", "user0", "user0@example.test", null)
                .assignRole("ann", "resident")
                .build();

        ManagementPlan plan = client.management().manifest().plan(manifest);

        ManagementPlan.PlannedAction binding = plan.changes().stream()
                .filter(a -> a.target() == ManagementPlan.Target.USER_ROLE)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no USER_ROLE action in " + plan.changes()));
        assertEquals(ManagementPlan.Change.UPDATE, binding.change(),
                "a plain binding over a resource-scoped assignment must be an Update, "
                        + "not NoChange: " + plan.changes());
    }

    private static final UUID ARCHIVE_ID = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");

    private static String page(String... items) {
        return "{\"items\":[" + String.join(",", items) + "],\"total\":" + items.length
                + ",\"offset\":0,\"limit\":200}";
    }

    // ------------------------------------------------------------------
    // service_accounts
    // ------------------------------------------------------------------

    @Test
    void aCreatedServiceAccountsSecretSurvivesAndIsNotSentAgain() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/service-accounts", 200, pageOf(null));
        mount("POST", "/api/v1/service-accounts", 201, saCreatedBody(SA_ID, "ci-bot"));

        ManagementManifest manifest = ManagementManifest.builder()
                .serviceAccount("bot", "ci-bot", null)
                .build();

        ApplyReport report = client.management().manifest().apply(manifest);
        assertTrue(report.isComplete());
        List<io.axiam.sdk.management.models.ServiceAccountCreatedResponse> created =
                report.createdServiceAccounts();
        assertEquals(1, created.size());
        assertEquals("the-secret-value", created.get(0).clientSecret().expose());
    }

    /**
     * §27.5 rule 5: the created outcome survives even when a LATER action of the SAME
     * apply fails — here, the very next step: binding a role to the account {@code
     * apply} just minted (&sect;27.6 rule 5 orders a service account's own bindings
     * immediately after it, so this is the nearest possible "later action").
     */
    @Test
    void theCreatedSecretSurvivesALaterActionsFailure() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/service-accounts", 200, "[]");
        mount("GET", "/api/v1/service-accounts", 200, pageOf(null));
        mount("POST", "/api/v1/service-accounts", 201, saCreatedBody(SA_ID, "ci-bot"));
        mount("POST", "/api/v1/roles/" + ROLE_ID + "/service-accounts", 409,
                "{\"message\":\"conflict\"}");

        ManagementManifest manifest = ManagementManifest.builder()
                .role("editor", "Editor", "Edits")
                .serviceAccount("bot", "ci-bot", null)
                .assignServiceAccountRole("bot", ManagementManifest.RoleBinding.role("editor"))
                .build();

        ApplyReport report = client.management().manifest().apply(manifest);
        assertFalse(report.isComplete());
        assertEquals(1, report.createdServiceAccounts().size(),
                "the account's CREATED outcome survives even though the very next step — "
                        + "binding a role to it — failed");
    }

    @Test
    void aSecondApplyIsNoChangeAndNeverRotatesTheSecret() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/service-accounts", 200, pageOf(saBody(SA_ID, "ci-bot", null)));
        Route rotate = mount("POST", "/api/v1/service-accounts/" + SA_ID + "/rotate-secret", 200,
                "{\"client_secret\":\"should-never-be-called\"}");

        ManagementManifest manifest = ManagementManifest.builder()
                .serviceAccount("bot", "ci-bot", null)
                .build();

        ApplyReport report = client.management().manifest().apply(manifest);
        assertTrue(report.isComplete());
        assertEquals(0, report.changedCount());
        assertEquals(0, rotate.calls(), "apply MUST NEVER rotate a secret to reconcile");
    }

    @Test
    void anAmbiguousServiceAccountNameFailsPlanBeforeAnyWrite() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/service-accounts", 200,
                page(saBody(SA_ID, "ci-bot", null),
                        saBody(UUID.fromString("ffffffff-ffff-4fff-8fff-ffffffffffff"), "ci-bot", null)));
        Route create = mount("POST", "/api/v1/service-accounts", 201, saCreatedBody(SA_ID, "ci-bot"));

        ManagementManifest manifest = ManagementManifest.builder()
                .serviceAccount("bot", "ci-bot", null)
                .build();

        NetworkError e = assertThrows(NetworkError.class,
                () -> client.management().manifest().plan(manifest));
        assertTrue(e.getMessage().contains("matches 2 existing"), e.getMessage());
        assertEquals(0, create.calls());
    }

    // ------------------------------------------------------------------
    // Idempotence over all three additions at once (§27.6 rule 6)
    // ------------------------------------------------------------------

    @Test
    void planOnAnAlreadyAppliedManifestWithAllThreeAdditionsIsEmpty() throws Exception {
        JsonNode meta = metadata("{\"env\":\"prod\"}");
        mount("GET", "/api/v1/resources", 200, pageOf(resourceBody(RESOURCE_ID, "documents", meta)));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/permissions", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        UUID userId = UUID.fromString("00000000-1111-4111-8111-111111111111");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200,
                "[" + roleUserAssignment(userId, RESOURCE_ID, false) + "]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/service-accounts", 200, "[]");
        mount("GET", "/api/v1/users", 200, pageOf(userBody(0)));
        mount("GET", "/api/v1/groups", 200, pageOf(null));
        mount("GET", "/api/v1/service-accounts", 200, pageOf(saBody(SA_ID, "ci-bot", "desc")));

        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .metadata("docs", meta)
                .role("editor", "Editor", "Edits")
                .user("alice", "user0", "user0@example.test", null)
                .assignRole("alice", ManagementManifest.RoleBinding.scoped("editor", "docs", false))
                .serviceAccount("bot", "ci-bot", "desc")
                .build();

        ManagementPlan plan = client.management().manifest().plan(manifest);
        assertTrue(plan.isConverged(), "expected convergence, got: " + plan.changes());
    }
}
