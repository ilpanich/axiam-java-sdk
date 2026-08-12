package io.axiam.sdk.oidc;

import java.util.List;
import java.util.UUID;

/**
 * One {@code (resource, scopes)} pair a resource server requires
 * (CONTRACT.md &sect;20.1).
 *
 * @param resourceId     the AXIAM resource id — the same UUID the Protection API returned as {@code _id}
 * @param resourceScopes scope names, each of which the resource must already declare; matched exactly, with no prefix or wildcard semantics in either direction
 */
public record RequestedPermission(UUID resourceId, List<String> resourceScopes) {

    /** One pair.
     *
     * @param resourceId     the resource
     * @param resourceScopes the scopes required on it
     * @return the requested permission
     */
    public static RequestedPermission of(UUID resourceId, List<String> resourceScopes) {
        return new RequestedPermission(resourceId, List.copyOf(resourceScopes));
    }
}
