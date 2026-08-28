package io.axiam.sdk.management;

import org.jspecify.annotations.Nullable;

import java.util.UUID;

/**
 * Per-handle overrides for the two implicit path parameters
 * (CONTRACT.md &sect;27.4 rule 3).
 *
 * <p>Thirty-one of the 147 routes carry {@code {org_id}}, {@code {tenant_id}} or
 * both, and in almost every call they are the client's own. Making the caller
 * restate them every time is ceremony that gets wrapped in a helper anyway;
 * making them impossible to override is worse, because a platform-admin token
 * legitimately administers a tenant other than the one its client was built
 * with. So they default from the client, and every handle that needs one
 * exposes an override.
 *
 * <p>Named {@code NamespaceScope} rather than {@code Scope} because the
 * server's schema set already has a {@code Scope} — the sub-resource kind
 * &sect;27.1's {@code scopes} namespace administers — and two exported types of
 * that name is one too many.
 *
 * @param orgId an override for {@code {org_id}}, or {@code null} for the client's
 * @param tenantId an override for {@code {tenant_id}}, or {@code null} for the client's
 */
public record NamespaceScope(@Nullable UUID orgId, @Nullable UUID tenantId) {

    /** A scope overriding neither parameter. */
    private static final NamespaceScope NONE = new NamespaceScope(null, null);

    /**
     * The scope that overrides nothing, so both parameters default from the client.
     *
     * @return a {@code NamespaceScope} with no overrides
     */
    public static NamespaceScope inherited() {
        return NONE;
    }

    /**
     * A copy of this scope addressing {@code orgId} instead.
     *
     * @param orgId the organization to address
     * @return a new {@code NamespaceScope}; this one is unchanged
     */
    public NamespaceScope withOrg(UUID orgId) {
        return new NamespaceScope(orgId, tenantId);
    }

    /**
     * A copy of this scope addressing {@code tenantId} instead.
     *
     * @param tenantId the tenant to address
     * @return a new {@code NamespaceScope}; this one is unchanged
     */
    public NamespaceScope withTenant(UUID tenantId) {
        return new NamespaceScope(orgId, tenantId);
    }
}
