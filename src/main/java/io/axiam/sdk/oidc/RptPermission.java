package io.axiam.sdk.oidc;

import java.util.List;
import java.util.UUID;

/**
 * One entry of an RPT's {@code permissions} claim (CONTRACT.md &sect;20.1).
 *
 * <p><strong>A record of a decision already made, not a live authorization
 * answer</strong> (&sect;20.2 rule 7). These are the pairs the engine allowed
 * when the RPT was minted; a grant revoked afterwards does not empty a live
 * RPT. Do not cache them beyond the token's own expiry — which is why that
 * expiry is short.
 *
 * @param resourceId     the resource the engine allowed
 * @param resourceScopes the scopes it allowed on that resource
 * @param exp            absolute expiry, seconds since the epoch
 */
public record RptPermission(UUID resourceId, List<String> resourceScopes, long exp) {
}
