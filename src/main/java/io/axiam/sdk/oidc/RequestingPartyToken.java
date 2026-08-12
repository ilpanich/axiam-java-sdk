package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

/**
 * The result of the UMA ticket grant (CONTRACT.md &sect;20.1).
 *
 * <p><strong>There is no {@code refreshToken} component, and that is
 * deliberate</strong> (&sect;20.2 rule 5). The grant issues none, so an RPT
 * cannot outlive the ticket that authorised it; an application that wants a
 * fresh one re-runs the grant. This result never enters the &sect;9
 * single-flight refresh guard — there is nothing to refresh.
 *
 * @param accessToken the RPT itself (&sect;20.6 secret)
 * @param tokenType   always {@code Bearer}
 * @param expiresIn   {@code min(claimToken remaining, server ceiling, 300 s)}
 */
public record RequestingPartyToken(Sensitive accessToken, String tokenType, int expiresIn) {
}
