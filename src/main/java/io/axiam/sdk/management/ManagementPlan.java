package io.axiam.sdk.management;

import java.util.List;

/**
 * The ordered set of actions that would reconcile a manifest
 * (CONTRACT.md &sect;27.6).
 *
 * <p>Ordering is derived, not incidental: resources (parents before children),
 * then scopes, permissions, roles, role grants, groups, group bindings, users,
 * and finally the user bindings that need all of the above to exist. Two plans
 * over unchanged state are equal, in the same order (&sect;27.6 rule 8) — a plan
 * that reorders between runs cannot be diffed, and diffing it is most of the
 * reason it exists.
 *
 * @param actions every step, including the no-ops
 */
public record ManagementPlan(List<PlannedAction> actions) {

    /**
     * Canonical constructor, defensively copying the action list.
     *
     * @param actions every step, including the no-ops
     */
    public ManagementPlan {
        actions = List.copyOf(actions);
    }

    /**
     * The steps of this plan that would actually change something.
     *
     * @return every action whose change is not {@link Change#NO_CHANGE}
     */
    public List<PlannedAction> changes() {
        return actions.stream().filter(a -> a.change() != Change.NO_CHANGE).toList();
    }

    /**
     * Whether applying this plan would change nothing.
     *
     * <p>This is the &sect;27.6 rule 6 acceptance test: apply then plan must
     * land here, or the SDK has a drift-detection bug.
     *
     * @return {@code true} when no step would change anything
     */
    public boolean isConverged() {
        return changes().isEmpty();
    }

    /** Whether reconciling one spec would create, update, or do nothing. */
    public enum Change {
        /** The thing does not exist and would be created. */
        CREATE,
        /** It exists but a field the manifest states has drifted. */
        UPDATE,
        /** It already matches. */
        NO_CHANGE
    }

    /** Which part of the manifest an action came from. */
    public enum Target {
        /** A resource in the hierarchy. */
        RESOURCE,
        /** A scope beneath a resource. */
        SCOPE,
        /** A tenant-wide permission. */
        PERMISSION,
        /** A role. */
        ROLE,
        /** A permission granted to a role. */
        ROLE_GRANT,
        /** A group. */
        GROUP,
        /** A role assigned to a group. */
        GROUP_ROLE,
        /** A user. */
        USER,
        /** A role assigned directly to a user. */
        USER_ROLE,
        /** A user's membership of a group. */
        GROUP_MEMBER
    }

    /**
     * One step of a plan.
     *
     * @param change whether this step creates, updates, or does nothing
     * @param target what kind of thing it acts on
     * @param key the manifest key it came from, for a human reading the plan
     * @param summary a one-line description, stable across runs so plans diff
     */
    public record PlannedAction(Change change, Target target, String key, String summary) {
    }
}
