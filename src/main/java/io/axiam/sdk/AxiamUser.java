package io.axiam.sdk;

import java.util.List;

/**
 * Authenticated user identity returned as part of a completed
 * {@link LoginResult} (D-04).
 *
 * @param userId   the authenticated user's id
 * @param tenantId the tenant the user authenticated into
 * @param roles    the user's roles within {@code tenantId}, read from the access token's
 *                 {@code roles} claim only; empty when the claim is absent. OAuth2 scopes are
 *                 never mapped to roles (CONTRACT.md &sect;10): a scope named {@code admin} is not
 *                 the {@code admin} role
 */
public record AxiamUser(String userId, String tenantId, List<String> roles) {
}
