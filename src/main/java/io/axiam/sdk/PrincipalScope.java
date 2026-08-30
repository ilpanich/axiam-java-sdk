package io.axiam.sdk;

import java.util.List;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Where the signed-in principal lives, and how far its roles reach —
 * CONTRACT.md &sect;5.2.2 and &sect;5.2.3.
 *
 * <p>Grouped into one type rather than spread across {@link LoginResult}'s
 * components because they are read together and grow together: &sect;5.2.2
 * added three of these and &sect;5.2.3 a fourth, and a record that gains a
 * component per contract revision is one whose canonical constructor breaks
 * every time.
 *
 * <p>Every component is nullable, and absent has a specific meaning in each
 * case rather than "unknown" — see the individual parameters. A server older
 * than contract 1.34 sends none of them.
 *
 * @param actingTenantId       the tenant a request <strong>acts on</strong> —
 *                             what the {@code X-Axiam-Tenant} header names.
 *                             {@code null} when the server does not report it
 * @param principalTenantId    the tenant this principal's record
 *                             <strong>lives in</strong>. The same value as
 *                             {@code actingTenantId} for every ordinary
 *                             principal; the two diverge only once an
 *                             organization-level principal selects another
 *                             tenant to act on. This is where the account's own
 *                             credentials belong, and what a &sect;23
 *                             registration record for <em>this</em> account
 *                             must be sealed against — see
 *                             {@code AxiamClient.opaqueEnrollmentForSelf}.
 *                             Falls back to {@code actingTenantId} when the
 *                             server omits it, which is exactly right there: a
 *                             server that cannot switch the acting tenant
 *                             cannot make the two differ
 * @param principalTenantSlug  slug of {@code principalTenantId} —
 *                             {@code "organization"} for an organization-level
 *                             principal; {@code null} when the server omits it
 * @param orgId                the caller's organization as a UUID
 *                             (&sect;5.2.2 rule 3). Read this rather than
 *                             resolving a slug through
 *                             {@code GET /api/v1/organizations}, which is
 *                             {@code super-admin}-only and returns only the
 *                             caller's own organization
 * @param reachableTenantIds   the tenants this caller's roles reach, when they
 *                             are narrowed (&sect;5.2.3). {@code null} means
 *                             <strong>unrestricted</strong>, which is both the
 *                             common case and the only thing a server older
 *                             than contract 1.35 can mean. A present list is a
 *                             deliberately narrowed organization-level account:
 *                             confine any tenant switch to it, because naming
 *                             anything outside is refused at the header. Note
 *                             the pairing with
 *                             {@link LoginResult#organizationLevel()} — a
 *                             narrowed account still reports {@code true}
 *                             there, so gating on that flag alone offers
 *                             tenants the server will refuse
 */
public record PrincipalScope(
        @Nullable UUID actingTenantId,
        @Nullable UUID principalTenantId,
        @Nullable String principalTenantSlug,
        @Nullable UUID orgId,
        @Nullable List<UUID> reachableTenantIds) {

    /**
     * Normalises the two "absent means something specific" cases.
     *
     * <p>{@code principalTenantId} falls back to {@code actingTenantId}
     * (&sect;5.2.2 rule 1: absent means <em>equal</em>, not unknown), and an
     * empty {@code reachableTenantIds} becomes {@code null} — an empty list
     * would read as "reaches nothing", the opposite of what an omitted field
     * means here.
     */
    public PrincipalScope {
        if (principalTenantId == null) {
            principalTenantId = actingTenantId;
        }
        if (reachableTenantIds != null) {
            reachableTenantIds =
                    reachableTenantIds.isEmpty() ? null : List.copyOf(reachableTenantIds);
        }
    }
}
