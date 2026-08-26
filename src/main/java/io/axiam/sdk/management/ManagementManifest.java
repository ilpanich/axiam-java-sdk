package io.axiam.sdk.management;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.NetworkError;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
 */
public record ManagementManifest(
        List<ResourceSpec> resources,
        List<PermissionSpec> permissions,
        List<RoleSpec> roles,
        List<GroupSpec> groups,
        List<UserSpec> users) {

    /**
     * Canonical constructor, defensively copying every list.
     *
     * @param resources resources, in any order
     * @param permissions permissions
     * @param roles roles and their grants
     * @param groups groups and their roles
     * @param users users and their bindings
     */
    public ManagementManifest {
        resources = List.copyOf(resources);
        permissions = List.copyOf(permissions);
        roles = List.copyOf(roles);
        groups = List.copyOf(groups);
        users = List.copyOf(users);
    }

    /**
     * An empty manifest, declaring nothing.
     *
     * @return a manifest with no specs of any kind
     */
    public static ManagementManifest empty() {
        return new ManagementManifest(List.of(), List.of(), List.of(), List.of(), List.of());
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
     */
    public record ResourceSpec(String key, String name, String resourceType,
                               @Nullable String parent, List<ScopeSpec> scopes) {
        /**
         * Canonical constructor, defensively copying the scope list.
         *
         * @param key manifest-local identifier
         * @param name the resource's name
         * @param resourceType the server's resource_type discriminator
         * @param parent the parent's key, or {@code null}
         * @param scopes scopes declared under this resource
         */
        public ResourceSpec {
            scopes = List.copyOf(scopes);
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
     * @param roles the keys of roles assigned to this group
     */
    public record GroupSpec(String key, String name, String description, List<String> roles) {
        /**
         * Canonical constructor, defensively copying the role list.
         *
         * @param key manifest-local identifier
         * @param name the group's name
         * @param description human-readable description
         * @param roles the keys of roles assigned to this group
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
     * @param roles the keys of roles assigned directly to this user
     * @param groups the keys of groups this user belongs to
     */
    public record UserSpec(String key, String username, String email,
                           @Nullable Sensitive initialPassword,
                           List<String> roles, List<String> groups) {
        /**
         * Canonical constructor, defensively copying both key lists.
         *
         * @param key manifest-local identifier
         * @param username the username
         * @param email the user's email address
         * @param initialPassword the create-only password, or {@code null}
         * @param roles role keys assigned directly
         * @param groups group keys this user belongs to
         */
        public UserSpec {
            roles = List.copyOf(roles);
            groups = List.copyOf(groups);
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
        private final List<String> problems = new ArrayList<>();

        /** Mutable scope lists, keyed by resource key, folded in at build time. */
        private final Map<String, List<ScopeSpec>> scopes = new LinkedHashMap<>();
        /** Mutable grant lists, keyed by role key, folded in at build time. */
        private final Map<String, List<GrantSpec>> grants = new LinkedHashMap<>();
        /** Mutable role-assignment lists, keyed by user key. */
        private final Map<String, List<String>> userRoles = new LinkedHashMap<>();
        /** Mutable group-membership lists, keyed by user key. */
        private final Map<String, List<String>> userGroups = new LinkedHashMap<>();

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
         * Declares a group and the roles its members inherit.
         *
         * @param key manifest-local identifier
         * @param name the group's name
         * @param description human-readable description
         * @param roleKeys the roles this group's members inherit
         * @return this builder
         */
        public Builder group(String key, String name, String description, String... roleKeys) {
            groups.add(new GroupSpec(key, name, description, List.of(roleKeys)));
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
         * Assigns a role directly to the user named by {@code userKey}.
         *
         * @param userKey the user receiving the role
         * @param roleKey the role being assigned
         * @return this builder
         */
        public Builder assignRole(String userKey, String roleKey) {
            if (users.stream().noneMatch(u -> u.key().equals(userKey))) {
                problems.add("assignRole names user '" + userKey
                        + "', which no user(...) call has declared yet");
                return this;
            }
            userRoles.computeIfAbsent(userKey, k -> new ArrayList<>()).add(roleKey);
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
                        scopes.getOrDefault(r.key(), List.of())));
            }
            List<RoleSpec> withGrants = new ArrayList<>();
            for (RoleSpec r : roles) {
                withGrants.add(new RoleSpec(r.key(), r.name(), r.description(), r.global(),
                        grants.getOrDefault(r.key(), List.of())));
            }
            List<UserSpec> withBindings = new ArrayList<>();
            for (UserSpec u : users) {
                withBindings.add(new UserSpec(u.key(), u.username(), u.email(),
                        u.initialPassword(), userRoles.getOrDefault(u.key(), List.of()),
                        userGroups.getOrDefault(u.key(), List.of())));
            }
            ManagementManifest manifest = new ManagementManifest(
                    withScopes, permissions, withGrants, groups, withBindings);
            ManifestValidation.validate(manifest);
            return manifest;
        }
    }

    /** Key sets a validation pass needs, gathered once. */
    record Keys(Set<String> resources, Set<String> scopes, Set<String> permissions,
                Set<String> roles, Set<String> groups) {
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
            for (RoleSpec r : m.roles()) {
                roleKeys.add(r.key());
            }
            Set<String> groupKeys = new HashSet<>();
            for (GroupSpec g : m.groups()) {
                groupKeys.add(g.key());
            }
            return new Keys(resourceKeys, scopeKeys, permissionKeys, roleKeys, groupKeys);
        }
    }
}
