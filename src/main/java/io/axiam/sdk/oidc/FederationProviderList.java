package io.axiam.sdk.oidc;

import java.util.List;

/**
 * The result of {@code ssoProviders} (wire schema
 * {@code PublicFederationProvidersResponse}, CONTRACT.md &sect;12.1).
 *
 * <p>An <strong>empty</strong> {@link #providers()} is a normal success, never
 * an error (&sect;12.1 note 9). An unknown organization, a known one with
 * nothing configured, and a request naming no workspace at all all answer
 * {@code 200} this way, precisely so the endpoint cannot be used to enumerate
 * organization or tenant slugs.
 *
 * @param providers the providers to offer, in a stable server-defined order
 */
public record FederationProviderList(List<FederationProvider> providers) {

    /**
     * The query parameter the server delivers a handoff code in, on the SPA's
     * own callback URL (CONTRACT.md &sect;12.1 note 12).
     */
    public static final String HANDOFF_QUERY_PARAM = "axiam_handoff";

    /**
     * How long a handoff code is valid, in seconds (&sect;12.1 note 12). It
     * exists to survive one redirect. Redeem it immediately, once.
     */
    public static final long HANDOFF_CODE_TTL_SECONDS = 60L;
}
