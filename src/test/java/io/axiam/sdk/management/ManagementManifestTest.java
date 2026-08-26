package io.axiam.sdk.management;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.NetworkError;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT §27.6 — the declarative layer's reconciler.
 *
 * <p>The rules under test, in order: plan writes nothing and is stable across
 * runs; validation precedes every request; ordering is derived; drift is an
 * update and omission is never a deletion; apply converges, and stops at the
 * first failure while reporting what it did not attempt.
 */
class ManagementManifestTest extends ManagementTestBase {

    private static final UUID ROLE_ID = UUID.fromString("66666666-6666-4666-8666-666666666666");
    private static final UUID RESOURCE_ID = UUID.fromString("77777777-7777-4777-8777-777777777777");
    private static final UUID PERMISSION_ID = UUID.fromString("88888888-8888-4888-8888-888888888888");
    private static final UUID GROUP_ID = UUID.fromString("99999999-9999-4999-8999-999999999999");
    private static final UUID MEMBER_ID = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");

    private void mountEmptyTenant() {
        for (String path : List.of("resources", "permissions", "roles", "groups", "users")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
    }

    private ManagementManifest sampleManifest() {
        return ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .scope("docs", "draft", "draft", "Unpublished")
                .childResource("archive", "archive", "collection", "docs")
                .permission("read", "document:read", "Read")
                .role("editor", "Editor", "Edits documents")
                .grant("editor", "read", null, "draft")
                .group("staff", "Staff", "Everyone", "editor")
                .user("alice", "alice", "alice@example.test", Sensitive.of("correct-horse"))
                .assignRole("alice", "editor")
                .addToGroup("alice", "staff")
                .build();
    }

    /** §27.6 rule 1: every request a plan makes is a read. */
    @Test
    void planIssuesNoWrite() throws Exception {
        mountEmptyTenant();
        client.management().manifest().plan(sampleManifest());
        assertTrue(unmatched().isEmpty(),
                "plan reached a route it should not have: " + unmatched());
    }

    /** §27.6 rule 8: a plan that reorders between runs cannot be diffed. */
    @Test
    void planIsStableAcrossRuns() throws Exception {
        mountEmptyTenant();
        ManagementManifest manifest = sampleManifest();
        assertEquals(client.management().manifest().plan(manifest).actions(),
                client.management().manifest().plan(manifest).actions());
    }

    /** §27.6 rule 5: ordering is derived — parents and producers come first. */
    @Test
    void orderingIsDerived() throws Exception {
        mountEmptyTenant();
        ManagementPlan plan = client.management().manifest().plan(sampleManifest());

        List<String> resourceKeys = plan.actions().stream()
                .filter(a -> a.target() == ManagementPlan.Target.RESOURCE)
                .map(ManagementPlan.PlannedAction::key).toList();
        assertTrue(resourceKeys.indexOf("docs") < resourceKeys.indexOf("archive"),
                "a parent must precede its child, got " + resourceKeys);

        List<ManagementPlan.Target> targets = plan.actions().stream()
                .map(ManagementPlan.PlannedAction::target).toList();
        assertTrue(targets.indexOf(ManagementPlan.Target.PERMISSION)
                < targets.indexOf(ManagementPlan.Target.ROLE_GRANT));
        assertTrue(targets.indexOf(ManagementPlan.Target.ROLE)
                < targets.indexOf(ManagementPlan.Target.ROLE_GRANT));
        assertTrue(targets.indexOf(ManagementPlan.Target.GROUP)
                < targets.indexOf(ManagementPlan.Target.GROUP_ROLE));
        assertTrue(targets.indexOf(ManagementPlan.Target.USER)
                < targets.indexOf(ManagementPlan.Target.GROUP_MEMBER));
    }

    /** §27.6 rule 2: a dangling reference is refused before any request. */
    @Test
    void aDanglingReferenceIsRefusedBeforeCalling() throws Exception {
        mountEmptyTenant();
        int before = totalCalls();
        ManagementManifest manifest = new ManagementManifest(List.of(), List.of(),
                List.of(new ManagementManifest.RoleSpec("editor", "Editor", "Edits", false,
                        List.of(new ManagementManifest.GrantSpec("nope", null, List.of())))),
                List.of(), List.of());

        NetworkError thrown = assertThrows(NetworkError.class,
                () -> client.management().manifest().plan(manifest));
        assertTrue(thrown.getMessage().contains("which no permission declares"));
        assertEquals(before, totalCalls(), "validation must precede every request");
    }

    /** §27.6 rule 2: a resource cycle is refused rather than looped. */
    @Test
    void aResourceCycleIsRefusedRatherThanLooped() throws Exception {
        mountEmptyTenant();
        ManagementManifest manifest = new ManagementManifest(
                List.of(new ManagementManifest.ResourceSpec("a", "a", "c", "b", List.of()),
                        new ManagementManifest.ResourceSpec("b", "b", "c", "a", List.of())),
                List.of(), List.of(), List.of(), List.of());
        NetworkError thrown = assertThrows(NetworkError.class,
                () -> client.management().manifest().plan(manifest));
        assertTrue(thrown.getMessage().contains("cycle"));
    }

    /** Every problem is reported, not just the first. */
    @Test
    void everyProblemIsReportedNotJustTheFirst() throws Exception {
        mountEmptyTenant();
        ManagementManifest manifest = new ManagementManifest(List.of(), List.of(),
                List.of(new ManagementManifest.RoleSpec("r", "R", "R", false,
                        List.of(new ManagementManifest.GrantSpec("missing", null, List.of("nope"))))),
                List.of(new ManagementManifest.GroupSpec("g", "G", "G", List.of("absent"))),
                List.of());
        NetworkError thrown = assertThrows(NetworkError.class,
                () -> client.management().manifest().plan(manifest));
        assertTrue(thrown.getMessage().contains("3 problem(s)"),
                "want all three problems, got: " + thrown.getMessage());
    }

    /** §27.6 rule 1: a user that must be created needs a password, before any request. */
    @Test
    void aUserThatMustBeCreatedNeedsAPassword() throws Exception {
        mountEmptyTenant();
        ManagementManifest manifest = new ManagementManifest(List.of(), List.of(), List.of(),
                List.of(), List.of(new ManagementManifest.UserSpec(
                        "bob", "bob", "bob@example.test", null, List.of(), List.of())));
        NetworkError thrown = assertThrows(NetworkError.class,
                () -> client.management().manifest().plan(manifest));
        assertTrue(thrown.getMessage().contains("no initialPassword"));
    }

    /** The builder catches a forward reference the record form cannot. */
    @Test
    void theBuilderRefusesAForwardReference() {
        NetworkError thrown = assertThrows(NetworkError.class, () ->
                ManagementManifest.builder().scope("docs", "draft", "draft", "Unpublished").build());
        assertTrue(thrown.getMessage().contains("which no resource(...) call has declared yet"));
    }

    /**
     * Every builder call that names an earlier key checks it, not just the first.
     *
     * <p>A forward reference the builder lets through becomes a
     * {@code NullPointerException} deep inside apply, after part of the tenant
     * has already been written. Each of these four is a separate guard, and a
     * guard nobody exercises is a guard that gets deleted.
     */
    @Test
    void everyBuilderBackReferenceIsChecked() {
        assertTrue(assertThrows(NetworkError.class, () -> ManagementManifest.builder()
                .grant("editor", "read", null).build())
                .getMessage().contains("no role(...) call has declared yet"));
        assertTrue(assertThrows(NetworkError.class, () -> ManagementManifest.builder()
                .assignRole("alice", "editor").build())
                .getMessage().contains("no user(...) call has declared yet"));
        assertTrue(assertThrows(NetworkError.class, () -> ManagementManifest.builder()
                .addToGroup("alice", "staff").build())
                .getMessage().contains("no user(...) call has declared yet"));
    }

    /** A global role is a role that is global; the flag reaches the wire as one. */
    @Test
    void aGlobalRoleIsCreatedGlobal() throws Exception {
        mountEmptyTenant();
        mountCreates();
        Route created = route("POST", "/api/v1/roles");

        client.management().manifest().apply(ManagementManifest.builder()
                .globalRole("admin", "Administrator", "Everything, everywhere").build());

        assertTrue(created.last().json().path("is_global").asBoolean(),
                "a role declared global must be created global");
    }

    private void mountTenantWithOneRole(String description) {
        for (String path : List.of("resources", "permissions", "groups", "users")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", description)));
        for (String sub : List.of("permissions", "users", "groups")) {
            mount("GET", "/api/v1/roles/" + ROLE_ID + "/" + sub, 200, "[]");
        }
    }

    private static final ManagementManifest ONE_ROLE = new ManagementManifest(
            List.of(), List.of(),
            List.of(new ManagementManifest.RoleSpec("editor", "Editor", "Edits documents",
                    false, List.of())),
            List.of(), List.of());

    /** §27.6 rule 6: a converged tenant plans nothing. */
    @Test
    void aConvergedTenantPlansNothing() throws Exception {
        mountTenantWithOneRole("Edits documents");
        ManagementPlan plan = client.management().manifest().plan(ONE_ROLE);
        assertTrue(plan.isConverged(), "expected convergence, got " + plan.changes());
        assertFalse(plan.actions().isEmpty(), "a converged plan still reports its no-op steps");
    }

    /** §27.6 rule 3: a drifted field the manifest states is an update. */
    @Test
    void aDriftedFieldIsAnUpdate() throws Exception {
        mountTenantWithOneRole("something else");
        List<ManagementPlan.PlannedAction> changes =
                client.management().manifest().plan(ONE_ROLE).changes();
        assertEquals(1, changes.size());
        assertEquals(ManagementPlan.Change.UPDATE, changes.get(0).change());
        assertEquals(ManagementPlan.Target.ROLE, changes.get(0).target());
    }

    /** §27.6 rule 4: a role the manifest omits is never deleted. */
    @Test
    void aRoleTheManifestOmitsIsNeverDeleted() throws Exception {
        mountTenantWithOneRole("Edits documents");
        ManagementPlan plan = client.management().manifest().plan(ManagementManifest.empty());
        assertTrue(plan.actions().isEmpty(),
                "a manifest describes what should exist, not what should not");
    }

    private void mountCreates() {
        String stamps = "\"created_at\":\"2026-08-26T00:00:00Z\","
                + "\"updated_at\":\"2026-08-26T00:00:00Z\"";
        mount("POST", "/api/v1/resources", 201, "{\"id\":\"" + RESOURCE_ID
                + "\",\"name\":\"documents\",\"resource_type\":\"collection\",\"parent_id\":null,"
                + "\"metadata\":{},\"tenant_id\":\"" + TENANT_ID + "\"," + stamps + "}");
        mount("POST", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 201, "{\"id\":\"" + EXAMPLE_ID
                + "\",\"name\":\"draft\",\"description\":\"Unpublished\",\"resource_id\":\""
                + RESOURCE_ID + "\",\"tenant_id\":\"" + TENANT_ID + "\"," + stamps + "}");
        mount("POST", "/api/v1/permissions", 201, "{\"id\":\"" + PERMISSION_ID
                + "\",\"action\":\"document:read\",\"description\":\"Read\",\"tenant_id\":\""
                + TENANT_ID + "\"," + stamps + "}");
        mount("POST", "/api/v1/roles", 201, roleBody(ROLE_ID, "Editor", "Edits documents"));
        mount("POST", "/api/v1/groups", 201, "{\"id\":\"" + GROUP_ID
                + "\",\"name\":\"Staff\",\"description\":\"Everyone\",\"metadata\":{},"
                + "\"tenant_id\":\"" + TENANT_ID + "\"," + stamps + "}");
        mount("POST", "/api/v1/users", 201, "{\"id\":\"" + MEMBER_ID
                + "\",\"username\":\"alice\",\"email\":\"alice@example.test\","
                + "\"email_verified\":false,\"failed_login_attempts\":0,\"is_locked\":false,"
                + "\"metadata\":{},\"mfa_enabled\":false,\"status\":\"Active\",\"tenant_id\":\""
                + TENANT_ID + "\"," + stamps + "}");
        mount("POST", "/api/v1/roles/" + ROLE_ID + "/permissions", 204, "");
        mount("POST", "/api/v1/roles/" + ROLE_ID + "/users", 204, "");
        mount("POST", "/api/v1/roles/" + ROLE_ID + "/groups", 204, "");
        mount("POST", "/api/v1/groups/" + GROUP_ID + "/members", 204, "");
    }

    /** §27.6: apply creates everything and accounts for every step. */
    @Test
    void applyCreatesEverythingAndReportsEveryStep() throws Exception {
        mountEmptyTenant();
        mountCreates();

        ApplyReport report = client.management().manifest().apply(sampleManifest());

        assertTrue(report.isComplete(), () -> "apply stopped at " + report.failure());
        for (ApplyReport.AppliedStep step : report.steps()) {
            assertEquals(ApplyReport.Status.CREATED, step.outcome().status(),
                    "step " + step.action().summary() + " was " + step.outcome().status());
        }
        assertEquals(report.steps().size(), report.changedCount());
    }

    /** §27.6 rule 7: apply stops at the first failure and says what it never tried. */
    @Test
    void applyStopsAtTheFirstFailureAndSaysWhatWasNotAttempted() throws Exception {
        mountEmptyTenant();
        mountCreates();
        mount("POST", "/api/v1/permissions", 409, "{\"message\":\"already exists\"}");

        ApplyReport report = client.management().manifest().apply(sampleManifest());

        assertFalse(report.isComplete());
        assertTrue(report.failure().isPresent());
        assertEquals(ManagementPlan.Target.PERMISSION,
                report.failure().orElseThrow().action().target());

        boolean seenFailure = false;
        for (ApplyReport.AppliedStep step : report.steps()) {
            if (step.outcome().status() == ApplyReport.Status.FAILED) {
                seenFailure = true;
                continue;
            }
            if (seenFailure) {
                assertEquals(ApplyReport.Status.NOT_ATTEMPTED, step.outcome().status(),
                        "everything after the failure must be reported as never attempted");
            }
        }
        assertTrue(seenFailure);
    }

    /** Nothing declared means nothing planned and nothing sent. */
    @Test
    void applyingAnEmptyManifestIsClean() throws Exception {
        mountEmptyTenant();
        ApplyReport report = client.management().manifest().apply(ManagementManifest.empty());
        assertTrue(report.steps().isEmpty());
        assertTrue(report.isComplete());
        assertEquals(0, report.changedCount());
    }

    /** A config file mentioning a password is not a request to reset one. */
    @Test
    void aPasswordIsNeverSentForAUserThatAlreadyExists() throws Exception {
        for (String path : List.of("resources", "permissions", "roles", "groups")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
        mount("GET", "/api/v1/users", 200, pageOf("{\"id\":\"" + MEMBER_ID
                + "\",\"username\":\"alice\",\"email\":\"alice@example.test\","
                + "\"email_verified\":true,\"failed_login_attempts\":0,\"is_locked\":false,"
                + "\"metadata\":{},\"mfa_enabled\":false,\"status\":\"Active\",\"tenant_id\":\""
                + TENANT_ID + "\",\"created_at\":\"2026-08-26T00:00:00Z\","
                + "\"updated_at\":\"2026-08-26T00:00:00Z\"}"));
        Route created = mount("POST", "/api/v1/users", 201, "");

        ApplyReport report = client.management().manifest().apply(new ManagementManifest(
                List.of(), List.of(), List.of(), List.of(),
                List.of(new ManagementManifest.UserSpec("alice", "alice", "alice@example.test",
                        Sensitive.of("would-be-a-reset"), List.of(), List.of()))));

        assertEquals(0, created.calls());
        assertEquals(1, report.steps().size());
        assertEquals(ApplyReport.Status.UNCHANGED, report.steps().get(0).outcome().status());
    }

    /** A deny grant must travel as deny: AXIAM's RBAC is deny-override. */
    @Test
    void aDenyGrantTravelsAsDeny() throws Exception {
        mountEmptyTenant();
        mountCreates();
        Route grant = route("POST", "/api/v1/roles/" + ROLE_ID + "/permissions");

        client.management().manifest().apply(ManagementManifest.builder()
                .permission("purge", "document:purge", "Permanently delete")
                .role("editor", "Editor", "Edits documents")
                .grant("editor", "purge", "deny")
                .build());

        assertEquals("deny", grant.last().json().path("effect").asText());
    }

    private static final UUID ARCHIVE_ID = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final UUID SCOPE_ID = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc");

    /** Timestamps every mounted body carries; the reconciler reads none of them. */
    private static final String STAMPS = "\"created_at\":\"2026-08-26T00:00:00Z\","
            + "\"updated_at\":\"2026-08-26T00:00:00Z\"";

    private static String page(String... items) {
        return "{\"items\":[" + String.join(",", items) + "],\"total\":" + items.length
                + ",\"offset\":0,\"limit\":200}";
    }

    private static String resourceBody(UUID id, String name, String type, @Nullable UUID parent) {
        return "{\"id\":\"" + id + "\",\"name\":\"" + name + "\",\"resource_type\":\"" + type
                + "\",\"parent_id\":" + (parent == null ? "null" : "\"" + parent + "\"")
                + ",\"metadata\":{},\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}";
    }

    private static String permissionBody(String description) {
        return "{\"id\":\"" + PERMISSION_ID + "\",\"action\":\"document:read\",\"description\":\""
                + description + "\",\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}";
    }

    private static String groupBody(String description) {
        return "{\"id\":\"" + GROUP_ID + "\",\"name\":\"Staff\",\"description\":\"" + description
                + "\",\"metadata\":{},\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}";
    }

    private static String userBody(String email) {
        return "{\"id\":\"" + MEMBER_ID + "\",\"username\":\"alice\",\"email\":\"" + email
                + "\",\"email_verified\":true,\"failed_login_attempts\":0,\"is_locked\":false,"
                + "\"metadata\":{},\"mfa_enabled\":false,\"status\":\"Active\",\"tenant_id\":\""
                + TENANT_ID + "\"," + STAMPS + "}";
    }

    /**
     * Mounts a tenant that already holds every entity {@link #sampleManifest()}
     * declares, with the four drift-bearing fields supplied by the caller.
     *
     * <p>Passing the manifest's own values makes the tenant converged; passing
     * anything else makes it drifted. Both cases go through exactly the same
     * reads, which is the point: the reconciler must tell them apart from the
     * response bodies alone.
     */
    private void mountPopulatedTenant(String resourceType, String permissionDescription,
                                      String roleDescription, String groupDescription,
                                      String email) {
        mount("GET", "/api/v1/resources", 200, page(
                resourceBody(RESOURCE_ID, "documents", resourceType, null),
                resourceBody(ARCHIVE_ID, "archive", resourceType, RESOURCE_ID)));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200,
                "[{\"id\":\"" + SCOPE_ID + "\",\"name\":\"draft\",\"description\":\"Unpublished\","
                        + "\"resource_id\":\"" + RESOURCE_ID + "\",\"tenant_id\":\"" + TENANT_ID
                        + "\"," + STAMPS + "}]");
        mount("GET", "/api/v1/resources/" + ARCHIVE_ID + "/scopes", 200, "[]");
        mount("GET", "/api/v1/permissions", 200, page(permissionBody(permissionDescription)));
        mount("GET", "/api/v1/roles", 200, page(roleBody(ROLE_ID, "Editor", roleDescription)));
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200,
                "[{\"effect\":\"allow\",\"permission\":" + permissionBody(permissionDescription)
                        + ",\"scope_ids\":[\"" + SCOPE_ID + "\"],\"scopes\":[]}]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200,
                "[{\"user\":" + userBody(email) + ",\"resource_id\":null}]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200,
                "[{\"group\":" + groupBody(groupDescription) + ",\"resource_id\":null}]");
        mount("GET", "/api/v1/groups", 200, page(groupBody(groupDescription)));
        mount("GET", "/api/v1/groups/" + GROUP_ID + "/members", 200, page(userBody(email)));
        mount("GET", "/api/v1/users", 200, page(userBody(email)));
    }

    /**
     * §27.6 rule 6: applying a manifest a second time writes nothing.
     *
     * <p>The single most important property of the declarative layer, and the
     * one a create-from-empty test cannot show: every entity, grant, role
     * assignment and group membership already matches, so every step must
     * report UNCHANGED and no write route may be reached at all. A reconciler
     * that re-issued its creates would still "succeed" against a real server
     * for the entities, and would silently duplicate the grants.
     */
    @Test
    void aSecondApplyOfTheSameManifestWritesNothing() throws Exception {
        mountPopulatedTenant("collection", "Read", "Edits documents", "Everyone",
                "alice@example.test");
        mountCreates();

        ManagementPlan plan = client.management().manifest().plan(sampleManifest());
        assertTrue(plan.isConverged(), () -> "expected convergence, got " + plan.changes());

        ApplyReport report = client.management().manifest().apply(sampleManifest());
        assertTrue(report.isComplete(), () -> "apply stopped at " + report.failure());
        assertEquals(0, report.changedCount(), "a converged tenant must take no writes");
        for (ApplyReport.AppliedStep step : report.steps()) {
            assertEquals(ApplyReport.Status.UNCHANGED, step.outcome().status(),
                    "step " + step.action().summary() + " was " + step.outcome().status());
        }
    }

    /**
     * §27.6 rule 3: drift is an update in place, never a delete-and-recreate.
     *
     * <p>Every entity the manifest can update is drifted at once, so the case
     * fails if any one of the five update paths is missing, targets the wrong
     * identifier, or falls through to a create.
     */
    @Test
    void everyDriftedEntityIsUpdatedInPlace() throws Exception {
        mountPopulatedTenant("folder", "stale", "stale", "stale", "stale@example.test");
        mountCreates();
        Route resource = mount("PUT", "/api/v1/resources/" + RESOURCE_ID, 200,
                resourceBody(RESOURCE_ID, "documents", "collection", null));
        Route child = mount("PUT", "/api/v1/resources/" + ARCHIVE_ID, 200,
                resourceBody(ARCHIVE_ID, "archive", "collection", RESOURCE_ID));
        Route permission = mount("PUT", "/api/v1/permissions/" + PERMISSION_ID, 200,
                permissionBody("Read"));
        Route role = mount("PUT", "/api/v1/roles/" + ROLE_ID, 200,
                roleBody(ROLE_ID, "Editor", "Edits documents"));
        Route group = mount("PUT", "/api/v1/groups/" + GROUP_ID, 200, groupBody("Everyone"));
        Route user = mount("PUT", "/api/v1/users/" + MEMBER_ID, 200,
                userBody("alice@example.test"));

        ApplyReport report = client.management().manifest().apply(sampleManifest());

        assertTrue(report.isComplete(), () -> "apply stopped at " + report.failure());
        assertEquals(1, resource.calls());
        assertEquals(1, child.calls());
        assertEquals(1, permission.calls());
        assertEquals(1, role.calls());
        assertEquals(1, group.calls());
        assertEquals(1, user.calls());
        assertEquals(6, report.steps().stream()
                .filter(s -> s.outcome().status() == ApplyReport.Status.UPDATED).count(),
                "six entities drifted, so six updates");

        // §27.4 rule 5 end to end: an update carries the field that drifted and
        // nothing else, so reconciling a description cannot clear an email.
        assertEquals(List.of("resource_type"), resource.last().keys());
        assertEquals(List.of("description"), permission.last().keys());
        assertEquals(List.of("description", "is_global"), role.last().keys());
        assertEquals(List.of("description"), group.last().keys());
        assertEquals(List.of("email"), user.last().keys());
    }
}
