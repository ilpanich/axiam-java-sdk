package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.NetworkError;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The shape a tenant should have — CONTRACT.md &sect;27.6.
 *
 * <p>A manifest is a <em>value</em>. It is built before the things in it exist,
 * so it cannot name them by UUID; every spec carries a manifest-local key that
 * other specs refer to, and {@link ManifestApi#plan} resolves those keys against
 * the tenant's current state.
 *
 * <p>Nothing here touches the network and nothing here needs a client — which is
 * what makes a manifest something you can load from configuration, commit to a
 * repository, and diff.
 *
 * <p>Deliberately covers only the namespaces that describe a tenant's
 * <em>shape</em>. Certificates, CA certificates, PGP keys and SCIM tokens are
 * absent on purpose (&sect;27.6): they mint one-time secrets, and a declarative
 * layer that "ensures a certificate exists" either re-mints one on every run or
 * silently accepts drift. Both are worse than an imperative call made once, on
 * purpose, whose result the caller stores.
 *
 * @param resources resources, in any order — {@code plan} sorts them so a parent
 *                  precedes its children
 * @param permissions permissions; what binds one to a resource is the scope list
 *                    on a role's grant
 * @param roles roles and the permissions granted to them
 * @param groups groups and the roles their members inherit
 * @param users users, their role assignments and their group memberships
 * @param serviceAccounts service accounts and the roles bound to them (CONTRACT.md
 *                        &sect;27.6.1 item 3, contract 1.51)
 */
public record ManagementManifest(
        List<ResourceSpec> resources,
        List<PermissionSpec> permissions,
        List<RoleSpec> roles,
        List<GroupSpec> groups,
        List<UserSpec> users,
        List<ServiceAccountSpec> serviceAccounts) {

    /**
     * Canonical constructor, defensively copying every list.
     *
     * @param resources resources, in any order
     * @param permissions permissions
     * @param roles roles and their grants
     * @param groups groups and their roles
     * @param users users and their bindings
     * @param serviceAccounts service accounts and their role bindings
     */
    public ManagementManifest {
        resources = List.copyOf(resources);
        permissions = List.copyOf(permissions);
        roles = List.copyOf(roles);
        groups = List.copyOf(groups);
        users = List.copyOf(users);
        serviceAccounts = List.copyOf(serviceAccounts);
    }

    /**
     * An empty manifest, declaring nothing.
     *
     * @return a manifest with no specs of any kind
     */
    public static ManagementManifest empty() {
        return new ManagementManifest(
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    /**
     * Starts a fluent builder.
     *
     * <p>The record form is fine for a small manifest and gets unreadable for a
     * real one — nested lists of lists, counting closing braces. This is the
     * same value, built a line at a time, and {@link Builder#build} validates it
     * where it is <em>written</em>.
     *
     * @return a fresh builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A scope, always beneath the resource that declares it.
     *
     * @param key manifest-local identifier, referred to by a role's grants
     * @param name the scope's name — its natural key within its resource
     * @param description human-readable description; the server requires one
     */
    public record ScopeSpec(String key, String name, String description) {
    }

    /**
     * A resource in the hierarchy, and the scopes beneath it.
     *
     * @param key manifest-local identifier, referred to by parent and by grants
     * @param name the resource's name — its natural key within the tenant
     * @param resourceType the server's resource_type discriminator
     * @param parent the key of this resource's parent, or {@code null} for a root
     * @param scopes scopes declared under this resource
     * @param metadata an optional JSON object (CONTRACT.md &sect;27.6.1 item 1, contract
     *                 1.51); {@code null} is silent — never sent, never compared. A stated
     *                 value is sent on {@code Create} and, when it drifts, on {@code Update} —
     *                 drift is JSON value equality of the <em>whole</em> object, never a
     *                 key-by-key merge, so a stated empty object matches what the server
     *                 returns for a resource created with none.
     */
    public record ResourceSpec(String key, String name, String resourceType,
                               @Nullable String parent, List<ScopeSpec> scopes,
                               @Nullable JsonNode metadata) {
        /**
         * Canonical constructor, defensively copying the scope list.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the server's resource_type discriminator
         * @param parent the parent's key, or {@code null}
         * @param scopes scopes declared under this resource
         * @param metadata an optional JSON object, or {@code null} to say nothing about it
         */
        public ResourceSpec {
            scopes = List.copyOf(scopes);
        }

        /**
         * The pre-1.51 four-argument shape, with no metadata stated.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the server's resource_type discriminator
         * @param parent the parent's key, or {@code null}
         * @param scopes scopes declared under this resource
         */
        public ResourceSpec(String key, String name, String resourceType,
                            @Nullable String parent, List<ScopeSpec> scopes) {
            this(key, name, resourceType, parent, scopes, null);
        }
    }

    /**
     * A role binding — either a bare role key (no resource scope, and so no
     * inheritance question) or a resource-scoped binding with an explicit
     * {@code inherit} (CONTRACT.md &sect;27.6.1 item 2, contract 1.51).
     *
     * <p>{@code resource} and {@code inherit} travel together: {@code inherit} is
     * meaningless without a {@code resource} to stop at, so a binding with
     * {@code inherit} set and {@code resource} {@code null} is rejected by
     * manifest validation rejects it before any request, the same as the server
     * would refuse it. {@code inherit} reaches the wire only as {@code false} —
     * {@link #scoped(String, String)}'s two-argument form (inherit left
     * {@code null}) is what keeps a resource-scoped binding's body byte-for-byte
     * a pre-1.51 body when the caller did not ask for the non-inheriting form.
     *
     * @param role the role's manifest key
     * @param resource the resource's manifest key, or {@code null} for a plain,
     *                 tenant-wide binding
     * @param inherit {@code false} to stop the binding at {@code resource}
     *                rather than reaching its descendants; {@code null} (the
     *                default) to say nothing and let the server's own default
     *                (inheriting) apply — never sent as {@code true} explicitly
     */
    public record RoleBinding(String role, @Nullable String resource, @Nullable Boolean inherit) {

        /** Validates that a role key was given. */
        public RoleBinding {
            Objects.requireNonNull(role, "role");
        }

        /**
         * A plain, tenant-wide binding — the shape every manifest used before 1.51.
         *
         * @param roleKey the role's manifest key
         * @return a binding naming no resource
         */
        public static RoleBinding role(String roleKey) {
            return new RoleBinding(roleKey, null, null);
        }

        /**
         * A resource-scoped binding that inherits to descendants (the server's default —
         * {@code inherit} is not sent).
         *
         * @param roleKey the role's manifest key
         * @param resourceKey the resource's manifest key
         * @return a resource-scoped, inheriting binding
         */
        public static RoleBinding scoped(String roleKey, String resourceKey) {
            return new RoleBinding(roleKey, Objects.requireNonNull(resourceKey, "resourceKey"), null);
        }

        /**
         * A resource-scoped binding with an explicit {@code inherit}.
         *
         * @param roleKey the role's manifest key
         * @param resourceKey the resource's manifest key
         * @param inherit {@code false} to stop at {@code resourceKey}; {@code true} is
         *                refused (&sect;27.6.1 item 2: an SDK
         *                MUST NOT send {@code inherit: true} explicitly — omit it instead,
         *                via {@link #scoped(String, String)})
         * @return a resource-scoped binding carrying an explicit {@code inherit}
         */
        public static RoleBinding scoped(String roleKey, String resourceKey, boolean inherit) {
            return new RoleBinding(roleKey, Objects.requireNonNull(resourceKey, "resourceKey"), inherit);
        }

        /** Whether this binding is resource-scoped. */
        boolean isScoped() {
            return resource != null;
        }
    }

    /**
     * A permission — an action, tenant-wide.
     *
     * @param key manifest-local identifier, referred to by a role's grants
     * @param action the action — the permission's natural key within the tenant
     * @param description human-readable description; the server requires one
     */
    public record PermissionSpec(String key, String action, String description) {
    }

    /**
     * One permission granted to a role, optionally narrowed to scopes.
     *
     * <p>A {@code deny} effect overrides <em>every</em> allow, at any depth of
     * the resource hierarchy and at equal specificity — AXIAM's RBAC engine is
     * deny-override, not most-specific-wins.
     *
     * @param permission the key of the permission being granted
     * @param effect {@code "allow"}, {@code "deny"}, or {@code null} to let the
     *               server default, which is allow
     * @param scopes the keys of scopes this grant is narrowed to; empty means
     *               the whole resource
     */
    public record GrantSpec(String permission, @Nullable String effect, List<String> scopes) {
        /**
         * Canonical constructor, defensively copying the scope list.
         *
         * @param permission the permission's key
         * @param effect allow, deny, or {@code null}
         * @param scopes the scope keys this grant is narrowed to
         */
        public GrantSpec {
            scopes = List.copyOf(scopes);
        }
    }

    /**
     * A role and the permissions granted to it.
     *
     * @param key manifest-local identifier, referred to by users and groups
     * @param name the role's name — its natural key within the tenant
     * @param description human-readable description; the server requires one
     * @param global whether the role applies tenant-wide rather than to a
     *               resource subtree
     * @param grants permissions this role grants
     */
    public record RoleSpec(String key, String name, String description, boolean global,
                           List<GrantSpec> grants) {
        /**
         * Canonical constructor, defensively copying the grant list.
         *
         * @param key manifest-local identifier
         * @param name the role's name
         * @param description human-readable description
         * @param global whether the role is tenant-wide
         * @param grants permissions this role grants
         */
        public RoleSpec {
            grants = List.copyOf(grants);
        }
    }

    /**
     * A group and the roles its members inherit.
     *
     * @param key manifest-local identifier, referred to by users
     * @param name the group's name — its natural key within the tenant
     * @param description human-readable description; the server requires one
     * @param roles the roles assigned to this group, plain or resource-scoped
     *              (contract 1.51)
     */
    public record GroupSpec(String key, String name, String description, List<RoleBinding> roles) {
        /**
         * Canonical constructor, defensively copying the role list.
         *
         * @param key manifest-local identifier
         * @param name the group's name
         * @param description human-readable description
         * @param roles the roles assigned to this group
         */
        public GroupSpec {
            roles = List.copyOf(roles);
        }
    }

    /**
     * A user, their roles and their group memberships.
     *
     * @param key manifest-local identifier
     * @param username the username — the user's natural key within the tenant
     * @param email the user's email address
     * @param initialPassword the password to set IF this user has to be created,
     *                        or {@code null}. Never used for a user that already
     *                        exists: a manifest is a description of shape, and
     *                        silently resetting a live account's password because
     *                        a config file mentions one is not a shape change
     * @param roles the roles assigned directly to this user, plain or resource-scoped
     *              (contract 1.51)
     * @param groups the keys of groups this user belongs to
     */
    public record UserSpec(String key, String username, String email,
                           @Nullable Sensitive initialPassword,
                           List<RoleBinding> roles, List<String> groups) {
        /**
         * Canonical constructor, defensively copying both lists.
         *
         * @param key manifest-local identifier
         * @param username the username
         * @param email the user's email address
         * @param initialPassword the create-only password, or {@code null}
         * @param roles roles assigned directly
         * @param groups group keys this user belongs to
         */
        public UserSpec {
            roles = List.copyOf(roles);
            groups = List.copyOf(groups);
        }
    }

    /**
     * A service account and the roles bound to it (CONTRACT.md &sect;27.6.1 item 3,
     * contract 1.51).
     *
     * <p>Reconciled by {@code name}, not by a server-enforced unique key: the server's
     * only unique index on a service account is its {@code client_id}, so a tenant can
     * hold two accounts sharing one name. Planning against a manifest naming an
     * ambiguous one fails before any write — picking one would reconcile an account the
     * manifest did not clearly identify.
     *
     * @param key manifest-local identifier, referred to by nothing else in this
     *            manifest today — a service account owns no groups or resources
     *            of its own in 1.51
     * @param name the service account's name — its natural (but not server-unique)
     *             key within the tenant
     * @param description human-readable description; the only field {@code Update}
     *                     reconciles. {@code null} says nothing about it — never
     *                     sent, never compared
     * @param roles the roles bound to this service account, plain or resource-scoped
     */
    public record ServiceAccountSpec(String key, String name, @Nullable String description,
                                     List<RoleBinding> roles) {
        /**
         * Canonical constructor, defensively copying the role list.
         *
         * @param key manifest-local identifier
         * @param name the service account's name
         * @param description human-readable description, or {@code null}
         * @param roles the roles bound to this service account
         */
        public ServiceAccountSpec {
            roles = List.copyOf(roles);
        }
    }

    /**
     * Assembles a {@link ManagementManifest} fluently, validating at the end.
     *
     * <p>A forward reference — a scope naming a resource no {@code resource(...)}
     * call has declared, a grant naming an undeclared role — is caught here
     * rather than at plan time, because it is a mistake in the declaration and
     * hearing about it at the declaration is what makes this form worth having.
     */
    public static final class Builder {

        private final List<ResourceSpec> resources = new ArrayList<>();
        private final List<PermissionSpec> permissions = new ArrayList<>();
        private final List<RoleSpec> roles = new ArrayList<>();
        private final List<GroupSpec> groups = new ArrayList<>();
        private final List<UserSpec> users = new ArrayList<>();
        private final List<ServiceAccountSpec> serviceAccounts = new ArrayList<>();
        private final List<String> problems = new ArrayList<>();

        /** Mutable scope lists, keyed by resource key, folded in at build time. */
        private final Map<String, List<ScopeSpec>> scopes = new LinkedHashMap<>();
        /** Stated metadata, keyed by resource key, folded in at build time. */
        private final Map<String, JsonNode> metadataByResource = new LinkedHashMap<>();
        /** Mutable grant lists, keyed by role key, folded in at build time. */
        private final Map<String, List<GrantSpec>> grants = new LinkedHashMap<>();
        /** Mutable role-binding lists, keyed by group key. */
        private final Map<String, List<RoleBinding>> groupRoles = new LinkedHashMap<>();
        /** Mutable role-binding lists, keyed by user key. */
        private final Map<String, List<RoleBinding>> userRoles = new LinkedHashMap<>();
        /** Mutable group-membership lists, keyed by user key. */
        private final Map<String, List<String>> userGroups = new LinkedHashMap<>();
        /** Mutable role-binding lists, keyed by service-account key. */
        private final Map<String, List<RoleBinding>> serviceAccountRoles = new LinkedHashMap<>();

        Builder() {
        }

        /**
         * Declares a root resource.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the server's resource_type discriminator
         * @return this builder
         */
        public Builder resource(String key, String name, String resourceType) {
            resources.add(new ResourceSpec(key, name, resourceType, null, List.of()));
            return this;
        }

        /**
         * Declares a resource beneath the resource named by {@code parentKey}.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the server's resource_type discriminator
         * @param parentKey the parent resource's key
         * @return this builder
         */
        public Builder childResource(String key, String name, String resourceType, String parentKey) {
            resources.add(new ResourceSpec(key, name, resourceType, parentKey, List.of()));
            return this;
        }

        /**
         * Declares a scope beneath the resource named by {@code resourceKey}.
         *
         * @param resourceKey the resource this scope lives under
         * @param key manifest-local identifier
         * @param name the scope's name
         * @param description human-readable description
         * @return this builder
         */
        public Builder scope(String resourceKey, String key, String name, String description) {
            if (resources.stream().noneMatch(r -> r.key().equals(resourceKey))) {
                problems.add("scope '" + key + "' names resource '" + resourceKey
                        + "', which no resource(...) call has declared yet");
                return this;
            }
            scopes.computeIfAbsent(resourceKey, k -> new ArrayList<>())
                    .add(new ScopeSpec(key, name, description));
            return this;
        }

        /**
         * States the resource named by {@code resourceKey}'s metadata (CONTRACT.md
         * &sect;27.6.1 item 1, contract 1.51).
         *
         * <p>Silent unless called: a resource with no {@code metadata(...)} call says
         * nothing about it, and {@code plan}/{@code apply} never touch the field. A
         * stated value — including {@code NullNode}/an empty object — is sent on
         * {@code Create} and compared, as JSON value equality of the whole object,
         * on every later {@code plan}.
         *
         * @param resourceKey the resource this metadata belongs to
         * @param metadata the JSON object to state
         * @return this builder
         */
        public Builder metadata(String resourceKey, JsonNode metadata) {
            if (resources.stream().noneMatch(r -> r.key().equals(resourceKey))) {
                problems.add("metadata names resource '" + resourceKey
                        + "', which no resource(...) call has declared yet");
                return this;
            }
            metadataByResource.put(resourceKey, metadata);
            return this;
        }

        /**
         * Declares a permission.
         *
         * @param key manifest-local identifier
         * @param action the action
         * @param description human-readable description
         * @return this builder
         */
        public Builder permission(String key, String action, String description) {
            permissions.add(new PermissionSpec(key, action, description));
            return this;
        }

        /**
         * Declares a resource-scoped role.
         *
         * @param key manifest-local identifier
         * @param name the role's name
         * @param description human-readable description
         * @return this builder
         */
        public Builder role(String key, String name, String description) {
            roles.add(new RoleSpec(key, name, description, false, List.of()));
            return this;
        }

        /**
         * Declares a tenant-wide role.
         *
         * @param key manifest-local identifier
         * @param name the role's name
         * @param description human-readable description
         * @return this builder
         */
        public Builder globalRole(String key, String name, String description) {
            roles.add(new RoleSpec(key, name, description, true, List.of()));
            return this;
        }

        /**
         * Grants a permission to the role named by {@code roleKey}.
         *
         * @param roleKey the role receiving the grant
         * @param permissionKey the permission being granted
         * @param effect {@code "allow"}, {@code "deny"}, or {@code null} for the
         *               server's default
         * @param scopeKeys the scopes this grant is narrowed to; pass none to
         *                  grant across the whole resource
         * @return this builder
         */
        public Builder grant(String roleKey, String permissionKey, @Nullable String effect,
                             String... scopeKeys) {
            if (roles.stream().noneMatch(r -> r.key().equals(roleKey))) {
                problems.add("grant of '" + permissionKey + "' names role '" + roleKey
                        + "', which no role(...) call has declared yet");
                return this;
            }
            grants.computeIfAbsent(roleKey, k -> new ArrayList<>())
                    .add(new GrantSpec(permissionKey, effect, List.of(scopeKeys)));
            return this;
        }

        /**
         * Declares a group and the plain (tenant-wide) roles its members inherit.
         *
         * <p>For a resource-scoped binding, declare the group with no roles here and
         * call {@link #groupRole(String, RoleBinding)} instead — a {@code String}
         * varargs list can only ever mean the plain shape.
         *
         * @param key manifest-local identifier
         * @param name the group's name
         * @param description human-readable description
         * @param roleKeys the roles this group's members inherit, tenant-wide
         * @return this builder
         */
        public Builder group(String key, String name, String description, String... roleKeys) {
            groups.add(new GroupSpec(key, name, description, List.of()));
            for (String roleKey : roleKeys) {
                groupRoles.computeIfAbsent(key, k -> new ArrayList<>()).add(RoleBinding.role(roleKey));
            }
            return this;
        }

        /**
         * Binds a role to the group named by {@code groupKey}, plain or resource-scoped
         * (CONTRACT.md &sect;27.6.1 item 2, contract 1.51).
         *
         * @param groupKey the group receiving the binding
         * @param binding the role binding — {@link RoleBinding#role} or
         *                {@link RoleBinding#scoped}
         * @return this builder
         */
        public Builder groupRole(String groupKey, RoleBinding binding) {
            if (groups.stream().noneMatch(g -> g.key().equals(groupKey))) {
                problems.add("groupRole names group '" + groupKey
                        + "', which no group(...) call has declared yet");
                return this;
            }
            groupRoles.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(binding);
            return this;
        }

        /**
         * Declares a user.
         *
         * @param key manifest-local identifier
         * @param username the username
         * @param email the user's email address
         * @param initialPassword used only if the user has to be created; never
         *                        sent for one that already exists
         * @return this builder
         */
        public Builder user(String key, String username, String email,
                            @Nullable Sensitive initialPassword) {
            users.add(new UserSpec(key, username, email, initialPassword, List.of(), List.of()));
            return this;
        }

        /**
         * Assigns a plain, tenant-wide role directly to the user named by {@code userKey}.
         *
         * @param userKey the user receiving the role
         * @param roleKey the role being assigned
         * @return this builder
         */
        public Builder assignRole(String userKey, String roleKey) {
            return assignRole(userKey, RoleBinding.role(roleKey));
        }

        /**
         * Binds a role directly to the user named by {@code userKey}, plain or
         * resource-scoped (CONTRACT.md &sect;27.6.1 item 2, contract 1.51).
         *
         * @param userKey the user receiving the binding
         * @param binding the role binding — {@link RoleBinding#role} or
         *                {@link RoleBinding#scoped}
         * @return this builder
         */
        public Builder assignRole(String userKey, RoleBinding binding) {
            if (users.stream().noneMatch(u -> u.key().equals(userKey))) {
                problems.add("assignRole names user '" + userKey
                        + "', which no user(...) call has declared yet");
                return this;
            }
            userRoles.computeIfAbsent(userKey, k -> new ArrayList<>()).add(binding);
            return this;
        }

        /**
         * Puts the user named by {@code userKey} into the group named by {@code groupKey}.
         *
         * @param userKey the user joining the group
         * @param groupKey the group being joined
         * @return this builder
         */
        public Builder addToGroup(String userKey, String groupKey) {
            if (users.stream().noneMatch(u -> u.key().equals(userKey))) {
                problems.add("addToGroup names user '" + userKey
                        + "', which no user(...) call has declared yet");
                return this;
            }
            userGroups.computeIfAbsent(userKey, k -> new ArrayList<>()).add(groupKey);
            return this;
        }

        /**
         * Declares a service account (CONTRACT.md &sect;27.6.1 item 3, contract 1.51).
         *
         * @param key manifest-local identifier
         * @param name the service account's name — reconciled by name, not uniquely
         *             enforced by the server; see {@link ServiceAccountSpec}
         * @param description human-readable description, or {@code null} to say
         *                     nothing about it
         * @return this builder
         */
        public Builder serviceAccount(String key, String name, @Nullable String description) {
            serviceAccounts.add(new ServiceAccountSpec(key, name, description, List.of()));
            return this;
        }

        /**
         * Binds a role to the service account named by {@code serviceAccountKey}, plain
         * or resource-scoped.
         *
         * @param serviceAccountKey the service account receiving the binding
         * @param binding the role binding — {@link RoleBinding#role} or
         *                {@link RoleBinding#scoped}
         * @return this builder
         */
        public Builder assignServiceAccountRole(String serviceAccountKey, RoleBinding binding) {
            if (serviceAccounts.stream().noneMatch(s -> s.key().equals(serviceAccountKey))) {
                problems.add("assignServiceAccountRole names service account '" + serviceAccountKey
                        + "', which no serviceAccount(...) call has declared yet");
                return this;
            }
            serviceAccountRoles.computeIfAbsent(serviceAccountKey, k -> new ArrayList<>()).add(binding);
            return this;
        }

        /**
         * Returns the assembled manifest, or throws with the reason it cannot be
         * reconciled.
         *
         * @return the assembled, validated manifest
         * @throws NetworkError if a forward reference was made, or if the
         *                      assembled manifest has a dangling key, a duplicate
         *                      key, or a cycle in the resource parents
         */
        public ManagementManifest build() {
            if (!problems.isEmpty()) {
                throw new NetworkError("manifest builder found " + problems.size()
                        + " problem(s): " + String.join("; ", problems));
            }
            List<ResourceSpec> withScopes = new ArrayList<>();
            for (ResourceSpec r : resources) {
                withScopes.add(new ResourceSpec(r.key(), r.name(), r.resourceType(), r.parent(),
                        scopes.getOrDefault(r.key(), List.of()), metadataByResource.get(r.key())));
            }
            List<RoleSpec> withGrants = new ArrayList<>();
            for (RoleSpec r : roles) {
                withGrants.add(new RoleSpec(r.key(), r.name(), r.description(), r.global(),
                        grants.getOrDefault(r.key(), List.of())));
            }
            List<GroupSpec> withGroupRoles = new ArrayList<>();
            for (GroupSpec g : groups) {
                withGroupRoles.add(new GroupSpec(g.key(), g.name(), g.description(),
                        groupRoles.getOrDefault(g.key(), List.of())));
            }
            List<UserSpec> withBindings = new ArrayList<>();
            for (UserSpec u : users) {
                withBindings.add(new UserSpec(u.key(), u.username(), u.email(),
                        u.initialPassword(), userRoles.getOrDefault(u.key(), List.of()),
                        userGroups.getOrDefault(u.key(), List.of())));
            }
            List<ServiceAccountSpec> withServiceAccountRoles = new ArrayList<>();
            for (ServiceAccountSpec s : serviceAccounts) {
                withServiceAccountRoles.add(new ServiceAccountSpec(s.key(), s.name(),
                        s.description(), serviceAccountRoles.getOrDefault(s.key(), List.of())));
            }
            ManagementManifest manifest = new ManagementManifest(withScopes, permissions,
                    withGrants, withGroupRoles, withBindings, withServiceAccountRoles);
            ManifestValidation.validate(manifest);
            return manifest;
        }
    }

    /** Key sets a validation pass needs, gathered once. */
    record Keys(Set<String> resources, Set<String> scopes, Set<String> permissions,
                Set<String> roles, Set<String> groups, Set<String> serviceAccounts,
                Set<String> globalRoles) {
        static Keys of(ManagementManifest m) {
            Set<String> resourceKeys = new HashSet<>();
            Set<String> scopeKeys = new HashSet<>();
            for (ResourceSpec r : m.resources()) {
                resourceKeys.add(r.key());
                for (ScopeSpec s : r.scopes()) {
                    scopeKeys.add(s.key());
                }
            }
            Set<String> permissionKeys = new HashSet<>();
            for (PermissionSpec p : m.permissions()) {
                permissionKeys.add(p.key());
            }
            Set<String> roleKeys = new HashSet<>();
            Set<String> globalRoleKeys = new HashSet<>();
            for (RoleSpec r : m.roles()) {
                roleKeys.add(r.key());
                if (r.global()) {
                    globalRoleKeys.add(r.key());
                }
            }
            Set<String> groupKeys = new HashSet<>();
            for (GroupSpec g : m.groups()) {
                groupKeys.add(g.key());
            }
            Set<String> serviceAccountKeys = new HashSet<>();
            for (ServiceAccountSpec s : m.serviceAccounts()) {
                serviceAccountKeys.add(s.key());
            }
            return new Keys(resourceKeys, scopeKeys, permissionKeys, roleKeys, groupKeys,
                    serviceAccountKeys, globalRoleKeys);
        }
    }
}
