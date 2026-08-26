package io.axiam.sdk.management;

import io.axiam.sdk.errors.NetworkError;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Rejects a manifest that cannot be reconciled, before any request is made.
 *
 * <p>CONTRACT.md &sect;27.6 rules 2 and 5 both land here. Every failure this
 * catches would otherwise surface halfway through an apply, with part of the
 * tenant already changed — which is the expensive moment to learn that a role
 * refers to a permission nobody declared. Every problem is reported, not just
 * the first: fixing them one at a time is a slow way to learn about four.
 */
final class ManifestValidation {

    private ManifestValidation() {
    }

    /**
     * Validates {@code manifest}, throwing if it cannot be reconciled.
     *
     * @throws NetworkError naming every problem found
     */
    static void validate(ManagementManifest manifest) {
        List<String> problems = new ArrayList<>();
        ManagementManifest.Keys keys = ManagementManifest.Keys.of(manifest);

        duplicates("resource", manifest.resources().stream().map(
                ManagementManifest.ResourceSpec::key).toList(), problems);
        duplicates("scope", manifest.resources().stream()
                .flatMap(r -> r.scopes().stream())
                .map(ManagementManifest.ScopeSpec::key).toList(), problems);
        duplicates("permission", manifest.permissions().stream().map(
                ManagementManifest.PermissionSpec::key).toList(), problems);
        duplicates("role", manifest.roles().stream().map(
                ManagementManifest.RoleSpec::key).toList(), problems);
        duplicates("group", manifest.groups().stream().map(
                ManagementManifest.GroupSpec::key).toList(), problems);
        duplicates("user", manifest.users().stream().map(
                ManagementManifest.UserSpec::key).toList(), problems);

        for (ManagementManifest.ResourceSpec r : manifest.resources()) {
            if (r.parent() != null && !keys.resources().contains(r.parent())) {
                problems.add("resource '" + r.key() + "' names parent '" + r.parent()
                        + "', which no resource declares");
            }
        }
        for (ManagementManifest.RoleSpec role : manifest.roles()) {
            for (ManagementManifest.GrantSpec grant : role.grants()) {
                if (!keys.permissions().contains(grant.permission())) {
                    problems.add("role '" + role.key() + "' grants permission '"
                            + grant.permission() + "', which no permission declares");
                }
                for (String scope : grant.scopes()) {
                    if (!keys.scopes().contains(scope)) {
                        problems.add("role '" + role.key() + "' scopes a grant to '" + scope
                                + "', which no scope declares");
                    }
                }
            }
        }
        for (ManagementManifest.GroupSpec group : manifest.groups()) {
            for (String role : group.roles()) {
                if (!keys.roles().contains(role)) {
                    problems.add("group '" + group.key() + "' is assigned role '" + role
                            + "', which no role declares");
                }
            }
        }
        for (ManagementManifest.UserSpec user : manifest.users()) {
            for (String role : user.roles()) {
                if (!keys.roles().contains(role)) {
                    problems.add("user '" + user.key() + "' is assigned role '" + role
                            + "', which no role declares");
                }
            }
            for (String group : user.groups()) {
                if (!keys.groups().contains(group)) {
                    problems.add("user '" + user.key() + "' is in group '" + group
                            + "', which no group declares");
                }
            }
        }

        try {
            topologicalOrder(manifest);
        } catch (NetworkError e) {
            problems.add(e.getMessage());
        }

        if (!problems.isEmpty()) {
            throw new NetworkError("manifest is not reconcilable (" + problems.size()
                    + " problem(s)): " + String.join("; ", problems));
        }
    }

    private static void duplicates(String kind, List<String> keys, List<String> problems) {
        Set<String> seen = new HashSet<>();
        for (String key : keys) {
            if (!seen.add(key)) {
                problems.add(kind + " key '" + key + "' is declared more than once");
            }
        }
    }

    /**
     * Resource keys ordered so a parent always precedes its children.
     *
     * <p>Throws on a cycle rather than looping: a resource graph with a cycle
     * has no valid creation order, and discovering that by hanging is worse than
     * discovering it by message.
     *
     * @throws NetworkError when the parent graph has a cycle
     */
    static List<String> topologicalOrder(ManagementManifest manifest) {
        Map<String, String> parents = new HashMap<>();
        for (ManagementManifest.ResourceSpec r : manifest.resources()) {
            parents.put(r.key(), r.parent());
        }
        List<String> order = new ArrayList<>();
        Set<String> placed = new HashSet<>();

        // Iterate the manifest's own order so the result is stable run to run
        // (§27.6 rule 8), rather than a map traversal order that is not.
        for (ManagementManifest.ResourceSpec r : manifest.resources()) {
            List<String> chain = new ArrayList<>();
            Set<String> guard = new HashSet<>();
            String cursor = r.key();
            while (cursor != null && !placed.contains(cursor)) {
                if (!guard.add(cursor)) {
                    throw new NetworkError("resource parent graph has a cycle through '"
                            + cursor + "'; there is no order in which these can be created");
                }
                chain.add(cursor);
                cursor = parents.get(cursor);
            }
            for (int i = chain.size() - 1; i >= 0; i--) {
                if (placed.add(chain.get(i))) {
                    order.add(chain.get(i));
                }
            }
        }
        return order;
    }
}
