package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.management.models.AddMemberRequest;
import io.axiam.sdk.management.models.AssignRoleToGroupRequest;
import io.axiam.sdk.management.models.AssignRoleToServiceAccountRequest;
import io.axiam.sdk.management.models.AssignRoleToUserRequest;
import io.axiam.sdk.management.models.CreateGroupRequest;
import io.axiam.sdk.management.models.CreatePermissionRequest;
import io.axiam.sdk.management.models.CreateResourceRequest;
import io.axiam.sdk.management.models.CreateRoleRequest;
import io.axiam.sdk.management.models.CreateScopeRequest;
import io.axiam.sdk.management.models.CreateServiceAccountRequest;
import io.axiam.sdk.management.models.CreateUserRequest;
import io.axiam.sdk.management.models.Group;
import io.axiam.sdk.management.models.GrantPermissionRequest;
import io.axiam.sdk.management.models.Permission;
import io.axiam.sdk.management.models.PermissionEffect;
import io.axiam.sdk.management.models.Resource;
import io.axiam.sdk.management.models.Role;
import io.axiam.sdk.management.models.RoleGroupAssignment;
import io.axiam.sdk.management.models.RoleServiceAccountAssignment;
import io.axiam.sdk.management.models.RoleUserAssignment;
import io.axiam.sdk.management.models.Scope;
import io.axiam.sdk.management.models.ServiceAccountCreatedResponse;
import io.axiam.sdk.management.models.ServiceAccountResponse;
import io.axiam.sdk.management.models.UpdateGroup;
import io.axiam.sdk.management.models.UpdatePermissionRequest;
import io.axiam.sdk.management.models.UpdateResourceRequest;
import io.axiam.sdk.management.models.UpdateRole;
import io.axiam.sdk.management.models.UpdateServiceAccount;
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
        private List<ServiceAccountResponse> serviceAccounts = List.of();
        private final Map<UUID, List<UUID>> roleGrants = new HashMap<>();
        // Full assignment objects, not just subject ids: a role binding's UPDATE
        // decision (contract 1.51, §27.6.1 item 2) needs the server's resourceId
        // and inherits() too, and the restore-on-failed-rebind path needs the
        // server's tenantScope.
        private final Map<UUID, List<RoleUserAssignment>> roleUsers = new HashMap<>();
        private final Map<UUID, List<RoleGroupAssignment>> roleGroups = new HashMap<>();
        private final Map<UUID, List<RoleServiceAccountAssignment>> roleServiceAccounts = new HashMap<>();
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
        private final Map<String, UUID> serviceAccounts = new HashMap<>();
    }

    /**
     * A binding actually present on the server for one (role, subject) pair —
     * what an UPDATE step needs to restore if its rebind fails.
     *
     * @param resourceId the server's resource_id, or {@code null} for a plain binding
     * @param tenantScope the server's tenant_scope, carried across a rebind unchanged
     *                    (CONTRACT.md &sect;27.6.1 item 2: dropping it would silently
     *                    widen an organization-level account's reach)
     */
    private record ExistingBinding(@Nullable UUID resourceId, boolean inherits,
                                   @Nullable List<UUID> tenantScope) {
    }

    private Snapshot read(ManagementManifest manifest) {
        Snapshot snapshot = new Snapshot();
        snapshot.resources = api.resources().listAll(PLAN_PAGE);
        snapshot.permissions = api.permissions().listAll(PLAN_PAGE);
        snapshot.roles = api.roles().listAll(PLAN_PAGE);
        snapshot.groups = api.groups().listAll(PLAN_PAGE);
        snapshot.users = api.users().listAll(PLAN_PAGE);
        // Only when the manifest names one (§27.6.1 item 3): a manifest with no
        // service_accounts section makes no new request over what 1.50 already made.
        snapshot.serviceAccounts = manifest.serviceAccounts().isEmpty()
                ? List.of() : api.serviceAccounts().listAll(PLAN_PAGE);

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
        boolean wantsServiceAccountRoles = !manifest.serviceAccounts().isEmpty();
        for (Role r : snapshot.roles) {
            if (!wantedRoles.contains(r.name())) {
                continue;
            }
            snapshot.roleGrants.put(r.id(), api.roles().listPermissions(r.id()).stream()
                    .map(g -> g.permission().id()).toList());
            snapshot.roleUsers.put(r.id(), api.roles().listUsers(r.id()));
            snapshot.roleGroups.put(r.id(), api.roles().listGroups(r.id()));
            if (wantsServiceAccountRoles) {
                snapshot.roleServiceAccounts.put(r.id(), api.roles().listServiceAccounts(r.id()));
            }
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
        UPDATE_GROUP, ASSIGN_ROLE_TO_GROUP, REBIND_ROLE_ON_GROUP, CREATE_USER, UPDATE_USER,
        ASSIGN_ROLE_TO_USER, REBIND_ROLE_ON_USER, ADD_GROUP_MEMBER, CREATE_SERVICE_ACCOUNT,
        UPDATE_SERVICE_ACCOUNT, ASSIGN_ROLE_TO_SERVICE_ACCOUNT, REBIND_ROLE_ON_SERVICE_ACCOUNT
    }

    /**
     * The desired state of one role binding, resolved against manifest keys, plus
     * enough of the server's existing assignment (when there is one) to restore it if
     * a rebind's re-assign fails (CONTRACT.md &sect;27.6.1 item 2, contract 1.51).
     *
     * @param roleKey the role's manifest key
     * @param resourceKey the resource's manifest key, or {@code null} for a plain binding
     * @param inherit the stated {@code inherit}, or {@code null} to mean "inheriting,
     *                say nothing"
     * @param existing the server's current assignment for this (role, subject) pair,
     *                 or {@code null} when there is none
     */
    private record BindingChange(String roleKey, @Nullable String resourceKey,
                                 @Nullable Boolean inherit, @Nullable ExistingBinding existing) {
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
                // §27.6.1 item 1 (contract 1.51): metadata is silent unless stated
                // (rule 3), and drift is JSON value equality of the whole object —
                // never a key-by-key merge, and never compared at all when the
                // manifest said nothing about it.
                boolean metadataDrifted = spec.metadata() != null
                        && !metadataEquals(spec.metadata(), existing.metadata());
                boolean drifted = !existing.resourceType().equals(spec.resourceType()) || metadataDrifted;
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
            for (ManagementManifest.RoleBinding binding : group.roles()) {
                ExistingBinding existing = res.roles.containsKey(binding.role())
                        ? findGroupBinding(snap, res.roles.get(binding.role()), res.groups.get(group.key()))
                        : null;
                addBindingStep(out, ManagementPlan.Target.GROUP_ROLE, group.key(),
                        "on group '" + group.name() + "'", binding, existing, res,
                        Kind.ASSIGN_ROLE_TO_GROUP, Kind.REBIND_ROLE_ON_GROUP);
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
            for (ManagementManifest.RoleBinding binding : user.roles()) {
                ExistingBinding existing = res.roles.containsKey(binding.role())
                        ? findUserBinding(snap, res.roles.get(binding.role()), res.users.get(user.key()))
                        : null;
                addBindingStep(out, ManagementPlan.Target.USER_ROLE, user.key(),
                        "on user '" + user.username() + "'", binding, existing, res,
                        Kind.ASSIGN_ROLE_TO_USER, Kind.REBIND_ROLE_ON_USER);
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

        // §27.6 rule 5: accounts and their bindings are ordered last. §27.6.1 item 3:
        // read only when the manifest names one (read() above already made that call).
        for (ManagementManifest.ServiceAccountSpec spec : m.serviceAccounts()) {
            List<ServiceAccountResponse> matches = snap.serviceAccounts.stream()
                    .filter(a -> a.name().equals(spec.name())).toList();
            if (matches.size() > 1) {
                // §27.6.1 item 3: the server's only unique index is client_id, so a
                // stated name matching more than one existing account is refused
                // before any write — picking one would reconcile an account the
                // manifest did not clearly identify.
                throw new NetworkError("manifest names service account '" + spec.key()
                        + "' (name '" + spec.name() + "'), which matches " + matches.size()
                        + " existing service accounts — plan cannot pick one");
            }
            String summary = "service account '" + spec.name() + "'";
            ServiceAccountResponse found = matches.isEmpty() ? null : matches.get(0);
            if (found != null) {
                res.serviceAccounts.put(spec.key(), found.id());
                boolean drifted = spec.description() != null
                        && !spec.description().equals(found.description());
                out.add(step(drifted ? ManagementPlan.Change.UPDATE : ManagementPlan.Change.NO_CHANGE,
                        ManagementPlan.Target.SERVICE_ACCOUNT, spec.key(), summary,
                        drifted ? Kind.UPDATE_SERVICE_ACCOUNT : Kind.NOOP, spec, null));
            } else {
                out.add(step(ManagementPlan.Change.CREATE, ManagementPlan.Target.SERVICE_ACCOUNT,
                        spec.key(), summary, Kind.CREATE_SERVICE_ACCOUNT, spec, null));
            }
        }

        for (ManagementManifest.ServiceAccountSpec sa : m.serviceAccounts()) {
            for (ManagementManifest.RoleBinding binding : sa.roles()) {
                ExistingBinding existing = res.roles.containsKey(binding.role())
                        ? findServiceAccountBinding(
                                snap, res.roles.get(binding.role()), res.serviceAccounts.get(sa.key()))
                        : null;
                addBindingStep(out, ManagementPlan.Target.SERVICE_ACCOUNT_ROLE, sa.key(),
                        "on service account '" + sa.name() + "'", binding, existing, res,
                        Kind.ASSIGN_ROLE_TO_SERVICE_ACCOUNT, Kind.REBIND_ROLE_ON_SERVICE_ACCOUNT);
            }
        }
        return out;
    }

    /** The server's existing binding of {@code roleId} to {@code groupId}, or {@code null}. */
    private static @Nullable ExistingBinding findGroupBinding(
            Snapshot snap, @Nullable UUID roleId, @Nullable UUID groupId) {
        if (roleId == null || groupId == null) {
            return null;
        }
        return snap.roleGroups.getOrDefault(roleId, List.of()).stream()
                .filter(a -> a.group().id().equals(groupId)).findFirst()
                .map(a -> new ExistingBinding(a.resourceId(), a.inherits(), a.tenantScope())).orElse(null);
    }

    /** The server's existing binding of {@code roleId} to {@code userId}, or {@code null}. */
    private static @Nullable ExistingBinding findUserBinding(
            Snapshot snap, @Nullable UUID roleId, @Nullable UUID userId) {
        if (roleId == null || userId == null) {
            return null;
        }
        return snap.roleUsers.getOrDefault(roleId, List.of()).stream()
                .filter(a -> a.user().id().equals(userId)).findFirst()
                .map(a -> new ExistingBinding(a.resourceId(), a.inherits(), a.tenantScope())).orElse(null);
    }

    /** The server's existing binding of {@code roleId} to {@code serviceAccountId}, or {@code null}. */
    private static @Nullable ExistingBinding findServiceAccountBinding(
            Snapshot snap, @Nullable UUID roleId, @Nullable UUID serviceAccountId) {
        if (roleId == null || serviceAccountId == null) {
            return null;
        }
        return snap.roleServiceAccounts.getOrDefault(roleId, List.of()).stream()
                .filter(a -> a.serviceAccount().id().equals(serviceAccountId)).findFirst()
                .map(a -> new ExistingBinding(a.resourceId(), a.inherits(), a.tenantScope())).orElse(null);
    }

    /**
     * Emits the Create/Update/NoChange step for one role binding, common to groups,
     * users and service accounts (CONTRACT.md &sect;27.6.1 item 2, contract 1.51).
     *
     * @param out the step list to append to
     * @param target which kind of binding this is, for the plan's summary
     * @param subjectKey the subject's manifest key
     * @param onWhat "on group 'g'" / "on user 'u'" / "on service account 's'", for the summary
     * @param binding the desired binding
     * @param existing the server's current binding of this (role, subject) pair, or
     *                 {@code null} when there is none
     * @param res manifest keys resolved so far, to name the resource in the summary
     * @param createKind the Kind that assigns a fresh binding
     * @param rebindKind the Kind that unassigns then re-assigns a drifted one
     */
    private static void addBindingStep(List<Step> out, ManagementPlan.Target target, String subjectKey,
            String onWhat, ManagementManifest.RoleBinding binding, @Nullable ExistingBinding existing,
            Resolved res, Kind createKind, Kind rebindKind) {
        String summary = "role '" + binding.role() + "' " + onWhat;
        // CONTRACT 1.52 N6.2 (C-12): a stated `inherit: true` is planned like an
        // omitted one and MUST NEVER reach the wire as a literal `true` — only a
        // stated `false` is ever sent; both an omitted and a stated `true`
        // normalize to `null` (BindingChange's own contract: "null to mean
        // inheriting, say nothing").
        Boolean wireInherit = Boolean.FALSE.equals(binding.inherit()) ? Boolean.FALSE : null;
        BindingChange change = new BindingChange(binding.role(), binding.resource(),
                wireInherit, existing);
        if (existing == null) {
            out.add(step(ManagementPlan.Change.CREATE, target, subjectKey, summary,
                    createKind, change, subjectKey));
            return;
        }
        UUID desiredResourceId = binding.resource() == null ? null : res.resources.get(binding.resource());
        boolean desiredInherit = binding.inherit() == null || binding.inherit();
        boolean sameResource = Objects.equals(existing.resourceId(), desiredResourceId);
        boolean sameInherit = existing.inherits() == desiredInherit;
        if (sameResource && sameInherit) {
            out.add(step(ManagementPlan.Change.NO_CHANGE, target, subjectKey, summary,
                    Kind.NOOP, change, subjectKey));
        } else {
            out.add(step(ManagementPlan.Change.UPDATE, target, subjectKey, summary,
                    rebindKind, change, subjectKey));
        }
    }

    /** JSON value equality of a stated metadata object against the server's own (never {@code null}). */
    private static boolean metadataEquals(JsonNode stated, @Nullable JsonNode serverSide) {
        JsonNode server = serverSide == null || serverSide.isNull() ? EMPTY_OBJECT : serverSide;
        return stated.equals(server);
    }

    private static final ObjectNode EMPTY_OBJECT = com.fasterxml.jackson.databind.node.JsonNodeFactory
            .instance.objectNode();

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
            RunOutcome outcome;
            try {
                outcome = run(s, res);
            } catch (BindingRebindFailedException e) {
                // CONTRACT.md §27.6.1 item 2: unassign-then-assign is not atomic. The
                // restore (re-assigning the PREVIOUS binding) has already been
                // attempted inside run(); e.restored() says whether it held.
                applied.add(new ApplyReport.AppliedStep(s.action(),
                        new ApplyReport.StepOutcome(ApplyReport.Status.FAILED, e.getMessage(),
                                null, e.restored())));
                stopped = true;
                continue;
            } catch (RuntimeException e) {
                applied.add(new ApplyReport.AppliedStep(s.action(),
                        new ApplyReport.StepOutcome(ApplyReport.Status.FAILED, e.getMessage())));
                stopped = true;
                continue;
            }
            // §27.5 rule 5: the created service account's one-time secret is carried
            // on THIS step's outcome, even if a later step of the same apply fails —
            // execute() only marks LATER steps NOT_ATTEMPTED, never this one.
            ApplyReport.Status status = s.kind().name().startsWith("UPDATE")
                    || s.kind().name().startsWith("REBIND")
                    ? ApplyReport.Status.UPDATED : ApplyReport.Status.CREATED;
            applied.add(new ApplyReport.AppliedStep(s.action(),
                    new ApplyReport.StepOutcome(status, null, outcome.createdServiceAccount(), null)));
        }
        return new ApplyReport(applied);
    }

    /** What {@link #run} produced, beyond "it did not throw". */
    private record RunOutcome(@Nullable ServiceAccountCreatedResponse createdServiceAccount) {
        static final RunOutcome NONE = new RunOutcome(null);
    }

    /**
     * Marks a rebind (unassign-then-assign) whose assign half failed, carrying whether
     * the best-effort restore of the previous binding held.
     */
    private static final class BindingRebindFailedException extends RuntimeException {
        private final boolean restored;

        BindingRebindFailedException(String message, boolean restored) {
            super(message);
            this.restored = restored;
        }

        boolean restored() {
            return restored;
        }
    }

    private RunOutcome run(Step s, Resolved res) {
        switch (s.kind()) {
            case CREATE_RESOURCE -> {
                ManagementManifest.ResourceSpec spec = (ManagementManifest.ResourceSpec) s.spec();
                UUID parent = spec.parent() == null ? null : res.resources.get(spec.parent());
                Resource created = api.resources().create(new CreateResourceRequest(
                        spec.metadata(), spec.name(), parent, spec.resourceType()));
                res.resources.put(s.key(), created.id());
            }
            case UPDATE_RESOURCE -> {
                ManagementManifest.ResourceSpec spec = (ManagementManifest.ResourceSpec) s.spec();
                UpdateResourceRequest.Builder update =
                        UpdateResourceRequest.builder().resourceType(spec.resourceType());
                if (spec.metadata() != null) {
                    // §27.6.1 item 1: stated, so carried — whether or not metadata
                    // itself was the field that drifted, exactly as resourceType
                    // above is carried whenever THIS step fires at all.
                    update.metadata(spec.metadata());
                }
                api.resources().update(res.resources.get(s.key()), update.build());
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
            // CONTRACT.md §5.2.3: a manifest has no syntax for naming tenants on a
            // FRESH assignment, so every one it creates is unrestricted — which is
            // exactly what the manifests written before the field existed already
            // meant, and keeps `apply` idempotent against them. A REBIND (below)
            // carries the server's existing tenant_scope across instead.
            case ASSIGN_ROLE_TO_GROUP -> {
                BindingChange c = (BindingChange) s.spec();
                api.roles().assignToGroup(res.roles.get(c.roleKey()),
                        new AssignRoleToGroupRequest(res.groups.get(s.related()), c.inherit(),
                                c.resourceKey() == null ? null : res.resources.get(c.resourceKey()), null));
            }
            case REBIND_ROLE_ON_GROUP -> {
                BindingChange c = (BindingChange) s.spec();
                UUID roleId = res.roles.get(c.roleKey());
                UUID groupId = res.groups.get(s.related());
                rebind(
                        () -> api.roles().unassignFromGroup(roleId, groupId,
                                strOrNull(c.existing().resourceId())),
                        () -> api.roles().assignToGroup(roleId, new AssignRoleToGroupRequest(
                                groupId, c.inherit(),
                                c.resourceKey() == null ? null : res.resources.get(c.resourceKey()),
                                c.existing().tenantScope())),
                        () -> api.roles().assignToGroup(roleId, new AssignRoleToGroupRequest(
                                groupId, c.existing().inherits() ? null : false,
                                c.existing().resourceId(), c.existing().tenantScope())));
            }
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
            case ASSIGN_ROLE_TO_USER -> {
                BindingChange c = (BindingChange) s.spec();
                api.roles().assignToUser(res.roles.get(c.roleKey()),
                        new AssignRoleToUserRequest(c.inherit(),
                                c.resourceKey() == null ? null : res.resources.get(c.resourceKey()),
                                null, res.users.get(s.related())));
            }
            case REBIND_ROLE_ON_USER -> {
                BindingChange c = (BindingChange) s.spec();
                UUID roleId = res.roles.get(c.roleKey());
                UUID userId = res.users.get(s.related());
                rebind(
                        () -> api.roles().unassignFromUser(roleId, userId,
                                strOrNull(c.existing().resourceId())),
                        () -> api.roles().assignToUser(roleId, new AssignRoleToUserRequest(
                                c.inherit(),
                                c.resourceKey() == null ? null : res.resources.get(c.resourceKey()),
                                c.existing().tenantScope(), userId)),
                        () -> api.roles().assignToUser(roleId, new AssignRoleToUserRequest(
                                c.existing().inherits() ? null : false,
                                c.existing().resourceId(), c.existing().tenantScope(), userId)));
            }
            case ADD_GROUP_MEMBER -> api.groups().addMember(
                    res.groups.get((String) s.spec()),
                    new AddMemberRequest(res.users.get(s.related())));
            case CREATE_SERVICE_ACCOUNT -> {
                ManagementManifest.ServiceAccountSpec spec = (ManagementManifest.ServiceAccountSpec) s.spec();
                ServiceAccountCreatedResponse created = api.serviceAccounts().create(
                        new CreateServiceAccountRequest(spec.description(), spec.name()));
                res.serviceAccounts.put(s.key(), created.id());
                return new RunOutcome(created);
            }
            case UPDATE_SERVICE_ACCOUNT -> {
                ManagementManifest.ServiceAccountSpec spec = (ManagementManifest.ServiceAccountSpec) s.spec();
                // §27.6.1 item 3: description is the only field Update reconciles;
                // status is not a manifest field in 1.51 (never sent from here).
                api.serviceAccounts().update(res.serviceAccounts.get(s.key()),
                        UpdateServiceAccount.builder().description(spec.description()).build());
            }
            case ASSIGN_ROLE_TO_SERVICE_ACCOUNT -> {
                BindingChange c = (BindingChange) s.spec();
                api.roles().assignToServiceAccount(res.roles.get(c.roleKey()),
                        new AssignRoleToServiceAccountRequest(c.inherit(),
                                c.resourceKey() == null ? null : res.resources.get(c.resourceKey()),
                                res.serviceAccounts.get(s.related()), null));
            }
            case REBIND_ROLE_ON_SERVICE_ACCOUNT -> {
                BindingChange c = (BindingChange) s.spec();
                UUID roleId = res.roles.get(c.roleKey());
                UUID saId = res.serviceAccounts.get(s.related());
                rebind(
                        () -> api.roles().unassignFromServiceAccount(roleId, saId,
                                strOrNull(c.existing().resourceId())),
                        () -> api.roles().assignToServiceAccount(roleId,
                                new AssignRoleToServiceAccountRequest(c.inherit(),
                                        c.resourceKey() == null ? null : res.resources.get(c.resourceKey()),
                                        saId, c.existing().tenantScope())),
                        () -> api.roles().assignToServiceAccount(roleId,
                                new AssignRoleToServiceAccountRequest(
                                        c.existing().inherits() ? null : false,
                                        c.existing().resourceId(), saId, c.existing().tenantScope())));
            }
            case NOOP -> {
                // Never reached: execute() short-circuits a no-op before here.
            }
            default -> throw new NetworkError("unknown manifest step " + s.kind());
        }
        return RunOutcome.NONE;
    }

    /**
     * Reconciles one drifted role binding as unassign-then-assign (CONTRACT.md
     * &sect;27.6.1 item 2, contract 1.51). Not atomic: if {@code assignNew} fails after
     * {@code unassign} succeeded, {@code restore} re-applies the previous binding on a
     * best-effort basis before the failure propagates.
     *
     * @param unassign removes the server's current binding
     * @param assignNew applies the manifest's desired binding
     * @param restore re-applies the previous binding, tried only if {@code assignNew} failed
     * @throws BindingRebindFailedException wrapping {@code assignNew}'s failure, naming
     *                                       whether {@code restore} held
     */
    private static void rebind(Runnable unassign, Runnable assignNew, Runnable restore) {
        unassign.run();
        try {
            assignNew.run();
        } catch (RuntimeException assignFailure) {
            boolean restored;
            try {
                restore.run();
                restored = true;
            } catch (RuntimeException restoreFailure) {
                restored = false;
            }
            throw new BindingRebindFailedException(assignFailure.getMessage(), restored);
        }
    }

    private static @Nullable String strOrNull(@Nullable UUID id) {
        return id == null ? null : id.toString();
    }
}
