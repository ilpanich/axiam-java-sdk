package io.axiam.sdk.oidc;

import java.util.List;
import java.util.UUID;

import org.jspecify.annotations.Nullable;

/**
 * A UMA resource set — an AXIAM resource seen through the Protection API
 * (CONTRACT.md &sect;20.1).
 *
 * <p>{@code id} is <strong>the AXIAM resource id</strong>, not a parallel
 * identifier: the same UUID is directly usable as the {@code resourceId} of a
 * later {@link RequestedPermission}, and as the resource id anywhere else in
 * this SDK.
 *
 * @param id             assigned by the server on registration; {@code null} on the way in
 * @param name           human-readable name, shown in the admin UI
 * @param type           free-form resource type; defaults server-side to {@code uma_resource} when {@code null}, so a resource server that omits it does not produce a row that sorts oddly next to hand-made ones
 * @param resourceScopes the scope names a resource server may ask for on this resource. <strong>Replaced wholesale by an update, never merged</strong> (&sect;20.2 rule 8) — this SDK does not read the current scopes and fold them into an update payload as a convenience, because that would make removing a scope impossible through it
 */
public record ResourceSet(
        @Nullable UUID id,
        String name,
        @Nullable String type,
        List<String> resourceScopes) {

    /** A registration payload with no type and no scopes.
     *
     * @param name the resource name
     * @return the resource set
     */
    public static ResourceSet of(String name) {
        return new ResourceSet(null, name, null, List.of());
    }

    /** A registration payload naming a type and a declared scope set.
     *
     * @param name           the resource name
     * @param type           the resource type
     * @param resourceScopes the complete declared scope set
     * @return the resource set
     */
    public static ResourceSet of(String name, String type, List<String> resourceScopes) {
        return new ResourceSet(null, name, type, List.copyOf(resourceScopes));
    }
}
