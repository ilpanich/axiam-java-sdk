package io.axiam.sdk.examples.managementmanifest;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.management.ApplyReport;
import io.axiam.sdk.management.ManagementManifest;
import io.axiam.sdk.management.ManagementPlan;

/**
 * The CONTRACT.md &sect;27.6 declarative layer: describe the tenant you want,
 * see what would change, then apply it.
 *
 * <p>A manifest states what should exist. It is not a diff and not a migration:
 * running it against a tenant that already matches writes nothing, and running
 * it twice is the same as running it once. What it never does is delete —
 * something the manifest does not mention is something the manifest has no
 * opinion about, not something it wants gone (&sect;27.6 rule 4).
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ADMIN=... AXIAM_ADMIN_PASSWORD=...
 * java ManagementManifestExample.java [--apply]}
 */
public final class ManagementManifestExample {

    public static void main(String[] args) {
        boolean apply = args.length > 0 && "--apply".equals(args[0]);
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenant = getenv("AXIAM_TENANT", "acme");
        String admin = getenv("AXIAM_ADMIN", "admin@example.com");
        String password = getenv("AXIAM_ADMIN_PASSWORD", "changeme");

        // The builder checks back-references as they are made: a grant naming a
        // role no role(...) call has declared is refused at build(), before any
        // request. Ordering between KINDS is derived (resources before scopes,
        // permissions before grants), so this reads top-down but need not.
        ManagementManifest manifest = ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .scope("docs", "draft", "draft", "Unpublished work")
                .childResource("archive", "archive", "collection", "docs")
                .permission("read", "document:read", "Read a document")
                .permission("purge", "document:purge", "Permanently delete a document")
                .role("editor", "Editor", "Edits documents")
                // A grant narrowed to a scope applies only within it.
                .grant("editor", "read", null, "draft")
                // AXIAM's RBAC is DENY-OVERRIDE: this refusal beats every allow
                // that reaches the same principal, at any depth of the resource
                // hierarchy. It is not "the more specific rule wins".
                .grant("editor", "purge", "deny")
                .group("staff", "Staff", "Everyone in the company", "editor")
                .user("alice", "alice", "alice@example.test", Sensitive.of("correct-horse-battery"))
                .assignRole("alice", "editor")
                .addToGroup("alice", "staff")
                .build();

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenant).orgSlug(tenant).build()) {
            client.login(admin, password);

            // plan() issues reads and nothing else — it cannot change the
            // tenant, so it is safe to run against production to find out what
            // an apply would do.
            ManagementPlan plan = client.management().manifest().plan(manifest);
            System.out.println(plan.isConverged()
                    ? "tenant already matches the manifest; nothing to do"
                    : plan.changes().size() + " change(s) pending:");
            for (ManagementPlan.PlannedAction action : plan.changes()) {
                System.out.println("  " + action.change() + " " + action.target()
                        + "  " + action.summary());
            }

            if (!apply) {
                System.out.println("(re-run with --apply to execute)");
                return;
            }

            // apply() stops at the FIRST failure and does not roll back
            // (§27.6 rule 7). Everything before the failure stands; everything
            // after it is reported as never attempted. That is deliberate: an
            // automatic rollback would be a second unreviewed batch of writes
            // issued at exactly the moment the tenant is in an unknown state.
            ApplyReport report = client.management().manifest().apply(manifest);
            for (ApplyReport.AppliedStep step : report.steps()) {
                System.out.printf("  %-13s %s%n",
                        step.outcome().status(), step.action().summary());
            }
            report.failure().ifPresent(failed -> System.out.println(
                    "stopped at: " + failed.action().summary()
                            + " -- " + failed.outcome().message()));
            System.out.println(report.isComplete()
                    ? "applied " + report.changedCount() + " change(s)"
                    : "INCOMPLETE: fix the failure above and re-run; what succeeded stands");
        }
    }

    private static String getenv(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private ManagementManifestExample() {
    }
}
