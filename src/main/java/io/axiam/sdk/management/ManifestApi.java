package io.axiam.sdk.management;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.management.models.AddMemberRequest;
import io.axiam.sdk.management.models.AssignRoleToGroupRequest;
import io.axiam.sdk.management.models.AssignRoleToUserRequest;
import io.axiam.sdk.management.models.CreateGroupRequest;
import io.axiam.sdk.management.models.CreatePermissionRequest;
import io.axiam.sdk.management.models.CreateResourceRequest;
import io.axiam.sdk.management.models.CreateRoleRequest;
import io.axiam.sdk.management.models.CreateScopeRequest;
import io.axiam.sdk.management.models.CreateUserRequest;
import io.axiam.sdk.management.models.Group;
import io.axiam.sdk.management.models.GrantPermissionRequest;
import io.axiam.sdk.management.models.Permission;
import io.axiam.sdk.management.models.PermissionEffect;
import io.axiam.sdk.management.models.Resource;
import io.axiam.sdk.management.models.Role;
import io.axiam.sdk.management.models.Scope;
import io.axiam.sdk.management.models.UpdateGroup;
import io.axiam.sdk.management.models.UpdatePermissionRequest;
import io.axiam.sdk.management.models.UpdateResourceRequest;
import io.axiam.sdk.management.models.UpdateRole;
import io.axiam.sdk.management.models.UpdateUserRequest;
import io.axiam.sdk.management.models.UserResponse;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Reconciling a manifest against a live tenant — CONTRACT.md &sect;27.6.
 *
 * <p>The split here is deliberate. Everything that <em>decides</em> — matching
 * specs against the tenant's current state, ordering the work, resolving
 * manifest keys to server identifiers — is pure and lives in {@code compute},
 * so {@link #plan} and {@link #apply} cannot disagree about what would happen:
 * apply runs exactly the steps plan reported. Only reading the snapshot and
 * running a step touch the network.
 */
public final class ManifestApi {

    /** How many items a planning read asks for per page. */
    private static final PageRequest PLAN_PAGE = PageRequest.of(200);

    private final ManagementApi api;

    /**
     * Binds the handle to a management surface.
     *
     * @param api the surface whose namespaces this reconciler drives
     */
    ManifestApi(ManagementApi api) {
        this.api = api;
    }

    /**
     * Reports what reconciling {@code manifest} would do. Issues <em>no</em> writes.
     *
     * @param manifest the shape the tenant should have
     * @return the ordered set of actions that would reconcile it
     * @throws NetworkError if the manifest cannot be reconciled, or a planning
     *                      read fails
     */
    public ManagementPlan plan(ManagementManifest manifest) {
        ManifestValidation.validate(manifest);
        Snapshot snapshot = read(manifest);
        List<Step> steps = compute(manifest, snapshot, new Resolved());
        requirePasswords(steps);
        return new ManagementPlan(steps.stream().map(Step::action).toList());
    }

    /**
     * Reconciles {@code manifest}, stopping at the first failure.
     *
     * <p>Re-running after fixing the cause is the recovery path, and is safe:
     * applying twice converges (&sect;27.6 rule 6).
     *
     * @param manifest the shape the tenant should have
     * @return every planned step paired with what became of it
     * @throws NetworkError if the manifest cannot be reconciled, or a planning
     *                      read fails
     */
    public ApplyReport apply(ManagementManifest manifest) {
        ManifestValidation.validate(manifest);
        Snapshot snapshot = read(manifest);
        Resolved resolved = new Resolved();
        List<Step> steps = compute(manifest, snapshot, resolved);
        requirePasswords(steps);
        return execute(steps, resolved);
    }

    // ------------------------------------------------------------------
    // Read
    // ------------------------------------------------------------------

    /** The current tenant state a plan is computed against. */
    private static final class Snapshot {
        private List<Resource> resources = List.of();
        private final Map<UUID, List<Scope>> scopes = new HashMap<>();
        private List<Permission> permissions = List.of();
        private List<Role> roles = List.of();
        private List<Group> groups = List.of();
        private List<UserResponse> users = List.of();
        private final Map<UUID, List<UUID>> roleGrants = new HashMap<>();
        private final Map<UUID, List<UUID>> roleUsers = new HashMap<>();
        private final Map<UUID, List<UUID>> roleGroups = new HashMap<>();
        private final Map<UUID, List<UUID>> groupMembers = new HashMap<>();
    }

    /** Manifest keys resolved to server identifiers. */
    private static final class Resolved {
        private final Map<String, UUID> resources = new HashMap<>();
        private final Map<String, UUID> scopes = new HashMap<>();
        private final Map<String, UUID> permissions = new HashMap<>();
        private final Map<String, UUID> roles = new HashMap<>();
        private final Map<String, UUID> groups = new HashMap<>();
        private final Map<String, UUID> users = new HashMap<>();
    }

    private Snapshot read(ManagementManifest manifest) {
        Snapshot snapshot = new Snapshot();
        snapshot.resources = api.resources().listAll(PLAN_PAGE);
        snapshot.permissions = api.permissions().listAll(PLAN_PAGE);
        snapshot.roles = api.roles().listAll(PLAN_PAGE);
        snapshot.groups = api.groups().listAll(PLAN_PAGE);
        snapshot.users = api.users().listAll(PLAN_PAGE);

        // Only the resources, roles and groups the manifest could match: a
        // tenant with a thousand resources should not cost a thousand scope
        // reads to plan five.
        List<String> wantedResources = manifest.resources().stream()
                .map(ManagementManifest.ResourceSpec::name).toList();
        for (Resource r : snapshot.resources) {
            if (wantedResources.contains(r.name())) {
                snapshot.scopes.put(r.id(), api.scopes().list(r.id()));
            }
        }
        List<String> wantedRoles = manifest.roles().stream()
                .map(ManagementManifest.RoleSpec::name).toList();
        for (Role r : snapshot.roles) {
            if (!wantedRoles.contains(r.name())) {
                continue;
            }
            snapshot.roleGrants.put(r.id(), api.roles().listPermissions(r.id()).stream()
                    .map(g -> g.permission().id()).toList());
            snapshot.roleUsers.put(r.id(), api.roles().listUsers(r.id()).stream()
                    .map(a -> a.user().id()).toList());
            snapshot.roleGroups.put(r.id(), api.roles().listGroups(r.id()).stream()
                    .map(a -> a.group().id()).toList());
        }
        List<String> wantedGroups = manifest.groups().stream()
                .map(ManagementManifest.GroupSpec::name).toList();
        for (Group g : snapshot.groups) {
            if (wantedGroups.contains(g.name())) {
                snapshot.groupMembers.put(g.id(), api.groups().listMembersAll(g.id(), PLAN_PAGE)
                        .stream().map(UserResponse::id).toList());
            }
        }
        return snapshot;
    }

    // ------------------------------------------------------------------
    // Plan
    // ------------------------------------------------------------------

    /** One executable step, carrying manifest keys rather than identifiers. */
    private record Step(ManagementPlan.PlannedAction action, Kind kind, String key,
                        @Nullable Object spec, @Nullable String related) {
    }

    /** Which operation a step runs. */
    private enum Kind {
        NOOP, CREATE_RESOURCE, UPDATE_RESOURCE, CREATE_SCOPE, CREATE_PERMISSION,
        UPDATE_PERMISSION, CREATE_ROLE, UPDATE_ROLE, GRANT_PERMISSION, CREATE_GROUP,
        UPDATE_GROUP, ASSIGN_ROLE_TO_GROUP, CREATE_USER, UPDATE_USER, ASSIGN_ROLE_TO_USER,
        ADD_GROUP_MEMBER
    }

    private static List<Step> compute(ManagementManifest m, Snapshot snap, Resolved res) {
        List<Step> out = new ArrayList<>();
        Map<String, ManagementManifest.ResourceSpec> specs = new HashMap<>();
        for (ManagementManifest.ResourceSpec r : m.resources()) {
            specs.put(r.key(), r);
        }

        for (String key : ManifestValidation.topologicalOrder(m)) {
            ManagementManifest.ResourceSpec spec = specs.get(key);
            boolean parentPending = spec.parent() != null && !res.resources.containsKey(spec.parent());
            UUID parentId = spec.parent() == null ? null : res.resources.get(spec.parent());
            // A child whose parent is itself pending cannot already exist, so
            // matching it against a root of the same name would be wrong.
            Resource existing = parentPending ? null : snap.resources.stream()
                    .filter(r -> r.name().equals(spec.name()) && Objects.equals(r.parentId(), parentId))
                    .findFirst().orElse(null);
            String summary = "resource '" + spec.name() + "' (" + spec.resourceType() + ")";
            if (existing != null) {
                res.resources.put(key, existing.id());
                boolean drifted = !existing.resourceType().equals(spec.resourceType());
                out.add(step(drifted ? ManagementPlan.Change.UPDATE : ManagementPlan.Change.NO_CHANGE,
                        ManagementPlan.Target.RESOURCE, key, summary,
                        drifted ? Kind.UPDATE_RESOURCE : Kind.NOOP, spec, null));
            } else {
                out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.RESOURCE, key,
                        summary, Kind.CREATE_RESOURCE, spec, null));
            }
        }

        for (ManagementManifest.ResourceSpec spec : m.resources()) {
            UUID resourceId = res.resources.get(spec.key());
            List<Scope> current = resourceId == null ? List.of()
                    : snap.scopes.getOrDefault(resourceId, List.of());
            for (ManagementManifest.ScopeSpec sc : spec.scopes()) {
                String summary = "scope '" + sc.name() + "' under resource '" + spec.name() + "'";
                Scope found = current.stream().filter(s -> s.name().equals(sc.name()))
                        .findFirst().orElse(null);
                if (found != null) {
                    res.scopes.put(sc.key(), found.id());
                    out.add(step(ManagementPlan.Change.NO_CHANGE, ManagementPlan.Target.SCOPE,
                            sc.key(), summary, Kind.NOOP, sc, spec.key()));
                } else {
                    out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.SCOPE,
                            sc.key(), summary, Kind.CREATE_SCOPE, sc, spec.key()));
                }
            }
        }

        for (ManagementManifest.PermissionSpec spec : m.permissions()) {
            String summary = "permission '" + spec.action() + "'";
            Permission found = snap.permissions.stream()
                    .filter(p -> p.action().equals(spec.action())).findFirst().orElse(null);
            if (found != null) {
                res.permissions.put(spec.key(), found.id());
                boolean drifted = !found.description().equals(spec.description());
                out.add(step(drifted ? ManagementPlan.Change.UPDATE : ManagementPlan.Change.NO_CHANGE,
                        ManagementPlan.Target.PERMISSION, spec.key(), summary,
                        drifted ? Kind.UPDATE_PERMISSION : Kind.NOOP, spec, null));
            } else {
                out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.PERMISSION,
                        spec.key(), summary, Kind.CREATE_PERMISSION, spec, null));
            }
        }

        for (ManagementManifest.RoleSpec spec : m.roles()) {
            String summary = "role '" + spec.name() + "'";
            Role found = snap.roles.stream().filter(r -> r.name().equals(spec.name()))
                    .findFirst().orElse(null);
            if (found != null) {
                res.roles.put(spec.key(), found.id());
                boolean drifted = !found.description().equals(spec.description())
                        || found.isGlobal() != spec.global();
                out.add(step(drifted ? ManagementPlan.Change.UPDATE : ManagementPlan.Change.NO_CHANGE,
                        ManagementPlan.Target.ROLE, spec.key(), summary,
                        drifted ? Kind.UPDATE_ROLE : Kind.NOOP, spec, null));
            } else {
                out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.ROLE, spec.key(),
                        summary, Kind.CREATE_ROLE, spec, null));
            }
        }

        for (ManagementManifest.RoleSpec role : m.roles()) {
            UUID roleId = res.roles.get(role.key());
            List<UUID> granted = roleId == null ? List.of()
                    : snap.roleGrants.getOrDefault(roleId, List.of());
            for (ManagementManifest.GrantSpec grant : role.grants()) {
                String summary = "grant '" + grant.permission() + "' to role '" + role.name() + "'";
                UUID permissionId = res.permissions.get(grant.permission());
                if (permissionId != null && granted.contains(permissionId)) {
                    out.add(step(ManagementPlan.Change.NO_CHANGE, ManagementPlan.Target.ROLE_GRANT,
                            role.key(), summary, Kind.NOOP, grant, role.key()));
                } else {
                    out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.ROLE_GRANT,
                            role.key(), summary, Kind.GRANT_PERMISSION, grant, role.key()));
                }
            }
        }

        for (ManagementManifest.GroupSpec spec : m.groups()) {
            String summary = "group '" + spec.name() + "'";
            Group found = snap.groups.stream().filter(g -> g.name().equals(spec.name()))
                    .findFirst().orElse(null);
            if (found != null) {
                res.groups.put(spec.key(), found.id());
                boolean drifted = !found.description().equals(spec.description());
                out.add(step(drifted ? ManagementPlan.Change.UPDATE : ManagementPlan.Change.NO_CHANGE,
                        ManagementPlan.Target.GROUP, spec.key(), summary,
                        drifted ? Kind.UPDATE_GROUP : Kind.NOOP, spec, null));
            } else {
                out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.GROUP, spec.key(),
                        summary, Kind.CREATE_GROUP, spec, null));
            }
        }

        for (ManagementManifest.GroupSpec group : m.groups()) {
            for (String roleKey : group.roles()) {
                String summary = "role '" + roleKey + "' on group '" + group.name() + "'";
                UUID roleId = res.roles.get(roleKey);
                UUID groupId = res.groups.get(group.key());
                boolean already = roleId != null && groupId != null
                        && snap.roleGroups.getOrDefault(roleId, List.of()).contains(groupId);
                out.add(step(already ? ManagementPlan.Change.NO_CHANGE : ManagementPlan.Change.CREATE,
                        ManagementPlan.Target.GROUP_ROLE, group.key(), summary,
                        already ? Kind.NOOP : Kind.ASSIGN_ROLE_TO_GROUP, roleKey, group.key()));
            }
        }

        for (ManagementManifest.UserSpec spec : m.users()) {
            String summary = "user '" + spec.username() + "'";
            UserResponse found = snap.users.stream()
                    .filter(u -> u.username().equals(spec.username())).findFirst().orElse(null);
            if (found != null) {
                res.users.put(spec.key(), found.id());
                boolean drifted = !found.email().equals(spec.email());
                out.add(step(drifted ? ManagementPlan.Change.UPDATE : ManagementPlan.Change.NO_CHANGE,
                        ManagementPlan.Target.USER, spec.key(), summary,
                        drifted ? Kind.UPDATE_USER : Kind.NOOP, spec, null));
            } else {
                out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.USER, spec.key(),
                        summary, Kind.CREATE_USER, spec, null));
            }
        }

        for (ManagementManifest.UserSpec user : m.users()) {
            for (String roleKey : user.roles()) {
                String summary = "role '" + roleKey + "' on user '" + user.username() + "'";
                UUID roleId = res.roles.get(roleKey);
                UUID userId = res.users.get(user.key());
                boolean already = roleId != null && userId != null
                        && snap.roleUsers.getOrDefault(roleId, List.of()).contains(userId);
                out.add(step(already ? ManagementPlan.Change.NO_CHANGE : ManagementPlan.Change.CREATE,
                        ManagementPlan.Target.USER_ROLE, user.key(), summary,
                        already ? Kind.NOOP : Kind.ASSIGN_ROLE_TO_USER, roleKey, user.key()));
            }
        }

        for (ManagementManifest.UserSpec user : m.users()) {
            for (String groupKey : user.groups()) {
                String summary = "user '" + user.username() + "' in group '" + groupKey + "'";
                UUID groupId = res.groups.get(groupKey);
                UUID userId = res.users.get(user.key());
                boolean already = groupId != null && userId != null
                        && snap.groupMembers.getOrDefault(groupId, List.of()).contains(userId);
                out.add(step(already ? ManagementPlan.Change.NO_CHANGE : ManagementPlan.Change.CREATE,
                        ManagementPlan.Target.GROUP_MEMBER, user.key(), summary,
                        already ? Kind.NOOP : Kind.ADD_GROUP_MEMBER, groupKey, user.key()));
            }
        }
        return out;
    }

    private static Step step(ManagementPlan.Change change, ManagementPlan.Target target,
                             String key, String summary, Kind kind, @Nullable Object spec,
                             @Nullable String related) {
        return new Step(new ManagementPlan.PlannedAction(change, target, key, summary),
                kind, key, spec, related);
    }

    /**
     * Refuses, before any request, when a user must be created with no password.
     *
     * <p>&sect;27.6 rule 1: discovering this halfway through an apply leaves the
     * tenant part-reconciled, and the fix — supply the password — is one a
     * caller could have been told about before anything was written.
     */
    private static void requirePasswords(List<Step> steps) {
        List<String> missing = new ArrayList<>();
        for (Step s : steps) {
            if (s.kind() == Kind.CREATE_USER
                    && ((ManagementManifest.UserSpec) s.spec()).initialPassword() == null) {
                missing.add(s.key());
            }
        }
        if (!missing.isEmpty()) {
            throw new NetworkError("manifest would create " + missing.size()
                    + " user(s) with no initialPassword: " + missing + ". A user cannot be "
                    + "created without one, and this is refused before any request rather than "
                    + "part-way through an apply (§27.6 rule 1).");
        }
    }

    // ------------------------------------------------------------------
    // Apply
    // ------------------------------------------------------------------

    private ApplyReport execute(List<Step> steps, Resolved res) {
        List<ApplyReport.AppliedStep> applied = new ArrayList<>();
        boolean stopped = false;
        for (Step s : steps) {
            if (stopped) {
                applied.add(new ApplyReport.AppliedStep(s.action(),
                        new ApplyReport.StepOutcome(ApplyReport.Status.NOT_ATTEMPTED, null)));
                continue;
            }
            if (s.kind() == Kind.NOOP) {
                applied.add(new ApplyReport.AppliedStep(s.action(),
                        new ApplyReport.StepOutcome(ApplyReport.Status.UNCHANGED, null)));
                continue;
            }
            try {
                run(s, res);
            } catch (RuntimeException e) {
                applied.add(new ApplyReport.AppliedStep(s.action(),
                        new ApplyReport.StepOutcome(ApplyReport.Status.FAILED, e.getMessage())));
                stopped = true;
                continue;
            }
            ApplyReport.Status status = s.kind().name().startsWith("UPDATE")
                    ? ApplyReport.Status.UPDATED : ApplyReport.Status.CREATED;
            applied.add(new ApplyReport.AppliedStep(s.action(),
                    new ApplyReport.StepOutcome(status, null)));
        }
        return new ApplyReport(applied);
    }

    private void run(Step s, Resolved res) {
        switch (s.kind()) {
            case CREATE_RESOURCE -> {
                ManagementManifest.ResourceSpec spec = (ManagementManifest.ResourceSpec) s.spec();
                UUID parent = spec.parent() == null ? null : res.resources.get(spec.parent());
                Resource created = api.resources().create(new CreateResourceRequest(
                        null, spec.name(), parent, spec.resourceType()));
                res.resources.put(s.key(), created.id());
            }
            case UPDATE_RESOURCE -> {
                ManagementManifest.ResourceSpec spec = (ManagementManifest.ResourceSpec) s.spec();
                api.resources().update(res.resources.get(s.key()),
                        UpdateResourceRequest.builder().resourceType(spec.resourceType()).build());
            }
            case CREATE_SCOPE -> {
                ManagementManifest.ScopeSpec spec = (ManagementManifest.ScopeSpec) s.spec();
                Scope created = api.scopes().create(res.resources.get(s.related()),
                        new CreateScopeRequest(spec.description(), spec.name()));
                res.scopes.put(s.key(), created.id());
            }
            case CREATE_PERMISSION -> {
                ManagementManifest.PermissionSpec spec = (ManagementManifest.PermissionSpec) s.spec();
                Permission created = api.permissions().create(
                        new CreatePermissionRequest(spec.action(), spec.description()));
                res.permissions.put(s.key(), created.id());
            }
            case UPDATE_PERMISSION -> {
                ManagementManifest.PermissionSpec spec = (ManagementManifest.PermissionSpec) s.spec();
                api.permissions().update(res.permissions.get(s.key()),
                        UpdatePermissionRequest.builder().description(spec.description()).build());
            }
            case CREATE_ROLE -> {
                ManagementManifest.RoleSpec spec = (ManagementManifest.RoleSpec) s.spec();
                Role created = api.roles().create(new CreateRoleRequest(
                        spec.description(), spec.global(), spec.name()));
                res.roles.put(s.key(), created.id());
            }
            case UPDATE_ROLE -> {
                ManagementManifest.RoleSpec spec = (ManagementManifest.RoleSpec) s.spec();
                api.roles().update(res.roles.get(s.key()), UpdateRole.builder()
                        .description(spec.description()).isGlobal(spec.global()).build());
            }
            case GRANT_PERMISSION -> {
                ManagementManifest.GrantSpec grant = (ManagementManifest.GrantSpec) s.spec();
                List<UUID> scopeIds = grant.scopes().stream().map(res.scopes::get).toList();
                PermissionEffect effect = grant.effect() == null ? null
                        : PermissionEffect.fromWire(grant.effect());
                api.roles().grantPermission(res.roles.get(s.related()),
                        new GrantPermissionRequest(effect, res.permissions.get(grant.permission()),
                                scopeIds.isEmpty() ? null : scopeIds));
            }
            case CREATE_GROUP -> {
                ManagementManifest.GroupSpec spec = (ManagementManifest.GroupSpec) s.spec();
                Group created = api.groups().create(
                        new CreateGroupRequest(spec.description(), null, spec.name()));
                res.groups.put(s.key(), created.id());
            }
            case UPDATE_GROUP -> {
                ManagementManifest.GroupSpec spec = (ManagementManifest.GroupSpec) s.spec();
                api.groups().update(res.groups.get(s.key()),
                        UpdateGroup.builder().description(spec.description()).build());
            }
            // CONTRACT.md §5.2.3: a manifest has no syntax for naming tenants on
            // an assignment, so every one it applies is unrestricted — which is
            // exactly what the manifests written before the field existed
            // already meant, and keeps `apply` idempotent against them.
            case ASSIGN_ROLE_TO_GROUP -> api.roles().assignToGroup(
                    res.roles.get((String) s.spec()),
                    new AssignRoleToGroupRequest(res.groups.get(s.related()), null, null));
            case CREATE_USER -> {
                ManagementManifest.UserSpec spec = (ManagementManifest.UserSpec) s.spec();
                UserResponse created = api.users().create(new CreateUserRequest(
                        spec.email(), null, null, spec.initialPassword(), spec.username()));
                res.users.put(s.key(), created.id());
            }
            case UPDATE_USER -> {
                ManagementManifest.UserSpec spec = (ManagementManifest.UserSpec) s.spec();
                api.users().update(res.users.get(s.key()),
                        UpdateUserRequest.builder().email(spec.email()).build());
            }
            // §5.2.3 — see ASSIGN_ROLE_TO_GROUP above.
            case ASSIGN_ROLE_TO_USER -> api.roles().assignToUser(
                    res.roles.get((String) s.spec()),
                    new AssignRoleToUserRequest(null, null, res.users.get(s.related())));
            case ADD_GROUP_MEMBER -> api.groups().addMember(
                    res.groups.get((String) s.spec()),
                    new AddMemberRequest(res.users.get(s.related())));
            case NOOP -> {
                // Never reached: execute() short-circuits a no-op before here.
            }
            default -> throw new NetworkError("unknown manifest step " + s.kind());
        }
    }
}
