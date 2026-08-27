package io.axiam.sdk.examples.managementbasics;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.Page;
import io.axiam.sdk.management.PageRequest;
import io.axiam.sdk.management.models.CreateRoleRequest;
import io.axiam.sdk.management.models.CreateUserRequest;
import io.axiam.sdk.management.models.Role;
import io.axiam.sdk.management.models.Tenant;
import io.axiam.sdk.management.models.TenantKind;
import io.axiam.sdk.management.models.UpdateUserRequest;
import io.axiam.sdk.management.models.UserResponse;

import java.util.List;
import java.util.UUID;

/**
 * Walks the CONTRACT.md &sect;27 management surface: namespace handles, paging,
 * sparse updates, one-time secrets, and the three error classifications.
 *
 * <p>Every call goes through {@code client.management()}, which is a view over
 * the same session the rest of the SDK uses — there is no second client to
 * build, no second login, and no second set of TLS settings to get wrong.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ADMIN=... AXIAM_ADMIN_PASSWORD=...
 * java ManagementBasicsExample.java}
 */
public final class ManagementBasicsExample {

    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenant = getenv("AXIAM_TENANT", "acme");
        String admin = getenv("AXIAM_ADMIN", "admin@example.com");
        String password = getenv("AXIAM_ADMIN_PASSWORD", "changeme");

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenant).orgSlug(tenant).build()) {
            client.login(admin, password);

            // §27.2: a handle is a view, not a connection. Acquiring one is
            // free and performs no I/O, so holding onto it buys nothing.
            System.out.println("org    : " + client.resolvedOrgId().orElseThrow());
            System.out.println("tenant : " + client.resolvedTenantId().orElseThrow());

            // ----------------------------------------------------------
            // §27.4 rule 4 — paging
            // ----------------------------------------------------------

            // total is the size of the WHOLE set, not of this page. Treating
            // items().size() as the total is the bug this type exists to stop.
            Page<UserResponse> firstPage = client.management().users().list(PageRequest.of(25));
            System.out.println("users  : " + firstPage.items().size()
                    + " of " + firstPage.total());

            // listAll walks to exhaustion. It stops on an empty page even if
            // the server's total disagrees, so a miscounting server costs one
            // wasted request rather than an unbounded loop.
            List<Role> roles = client.management().roles().listAll(PageRequest.of(100));
            System.out.println("roles  : " + roles.size());

            // ----------------------------------------------------------
            // §27.4 rule 4 — search rides on the page request
            // ----------------------------------------------------------

            // The term goes where offset and limit already live, rather than
            // becoming a third argument on each of the twenty list methods.
            // That is what makes listAll carry it across the whole walk: a walk
            // that filtered page one and not page two would hand back the
            // matches followed by the unfiltered tail.
            //
            // The SERVER filters, before offset/limit, so total() counts
            // MATCHES. Filtering the list here in Java would give you neither
            // that nor a page count that belongs to the set it labels.
            Page<UserResponse> matches =
                    client.management().users().list(PageRequest.matching(25, "ada"));
            System.out.println("matches: " + matches.total() + " users match \"ada\"");

            // Blank is the same request as unset: no search key at all. A box
            // that fires on every keystroke sends one of these the moment it is
            // cleared, and "rows containing the empty string" is a different
            // question from "all rows".
            Page<UserResponse> cleared =
                    client.management().users().list(PageRequest.matching(25, "   "));
            System.out.println("cleared: " + cleared.total() + " (everything again)");

            // The server caps the term's length. This SDK does not copy that
            // cap: a truncation the server would not have made is a silently
            // different query, with nothing to say so.

            // ----------------------------------------------------------
            // §27.11 — open enums, and three nulls that are not zero
            // ----------------------------------------------------------

            // A value this SDK's copy of the spec does not list decodes to
            // UNKNOWN rather than failing the whole response. A closed enum
            // would turn the next kind the server adds into a parse error on an
            // entire list, taking down every tenant on the page over one field
            // of one of them — including the ones you were after.
            for (Tenant each : client.management().tenants().list(PageRequest.of(5)).items()) {
                if (each.kind() == null) {
                    // A row written before organization scope existed. Read it
                    // as standard — that is what it is.
                    System.out.println("tenant : " + each.slug() + " (no kind recorded)");
                } else if (each.kind() == TenantKind.UNKNOWN) {
                    // Newer server, older SDK. The record is intact; only this
                    // one field is unrecognised. Do not carry it back into an
                    // update — UNKNOWN.wire() is the empty string, which the
                    // server refuses rather than accepting a wrong spelling.
                    System.out.println("tenant : " + each.slug() + " (kind this SDK "
                            + "does not know — leave it out of any update)");
                } else {
                    System.out.println("tenant : " + each.slug() + " " + each.kind());
                }
            }

            // Certificate.boundServiceAccountId() is resolved by list() and is
            // null on get(). Null there means "this read does not carry it",
            // not "there is nothing bound" — the SDK spends no second request
            // filling it in behind you. MtlsTrustAnchorResponse.trustedAnchors()
            // reads the same way: null means NOTHING WAS RELOADED, not that the
            // listener trusts zero CAs.
            client.management().certificates().list(PageRequest.of(5)).items().stream()
                    .filter(certificate -> certificate.boundServiceAccountId() != null)
                    .forEach(certificate -> System.out.println("cert   : " + certificate.id()
                            + " authenticates " + certificate.boundServiceAccountId()));

            // ----------------------------------------------------------
            // §27.4 rule 5 — sparse update vs replacement
            // ----------------------------------------------------------

            UUID someUser = firstPage.items().isEmpty() ? null : firstPage.items().get(0).id();
            if (someUser != null) {
                // A sparse body sends ONLY what the builder was given. What you
                // do not set is absent from the JSON entirely — not sent as
                // null, which the server would read as "clear this field".
                client.management().users().update(someUser,
                        UpdateUserRequest.builder().email("renamed@example.test").build());
            }

            // A replacement body has no builder: its canonical constructor
            // takes every field, so forgetting one is a compile error rather
            // than a silent overwrite with null.
            Role created = client.management().roles()
                    .create(new CreateRoleRequest("Edits documents", false, "Editor"));
            System.out.println("created: " + created.id());

            // ----------------------------------------------------------
            // §27.4 rule 7 — the three classifications
            // ----------------------------------------------------------

            // Each is a SUBTYPE of the §2 error it classifies, so code that
            // already catches AuthzError or NetworkError keeps working, and
            // code that wants the distinction can ask for it.
            try {
                client.management().users().get(UUID.randomUUID());
            } catch (NotFoundError e) {
                System.out.println("404 -> NotFoundError (still an AuthzError)");
            }

            try {
                client.management().roles()
                        .create(new CreateRoleRequest("Edits documents", false, "Editor"));
            } catch (ConflictError e) {
                // Also an AuthzError: §2 already mapped 409 there, and the
                // sub-type keeps that mapping rather than moving the status.
                System.out.println("409 -> ConflictError: " + e.getMessage());
            }

            try {
                client.management().users().create(new CreateUserRequest(
                        "not-an-email", null, null, Sensitive.of("correct-horse"), "someone"));
            } catch (ValidationError e) {
                // A ValidationError carries the server's per-field detail when
                // it sent any, so the caller can point at the offending input.
                System.out.println("400 -> ValidationError on fields: " + e.fields());
            }

            // §27.4 rule 8: only GETs are retried. A create that times out is
            // reported, never repeated — one retried POST is two roles.
        }
    }

    private static String getenv(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private ManagementBasicsExample() {
    }
}
