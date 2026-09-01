package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

/**
 * One sign-in button (wire schema {@code PublicFederationProvider},
 * CONTRACT.md &sect;12.1, contract 1.38).
 *
 * <p>This is an <strong>unauthenticated</strong> response and carries only
 * what a button needs. There is no {@code client_id}, no {@code metadata_url},
 * no endpoint URL and no secret — absent by construction rather than filtered
 * out — and &sect;12.1 note 9 forbids an SDK from expecting one.
 *
 * @param id             config id, echoed back to the matching start operation. Pass it
 *                       through unmodified: inheritance is resolved server-side
 *                       (&sect;12.1 note 13) and this id is how the server is told what
 *                       resolution produced
 * @param providerKind   which provider this is, for the button's branding —
 *                       {@code google}, {@code github}, {@code generic_oidc}, …
 *                       <strong>Not</strong> what selects the start operation; see
 *                       {@code protocol}
 * @param displayName    the operator's display name for the provider
 * @param protocol       {@link #PROTOCOL_OIDC_CONNECT}, {@link #PROTOCOL_SAML} or
 *                       {@link #PROTOCOL_OAUTH2} — the value that selects which start
 *                       operation to call (&sect;12.1 note 10). Kept as the wire string
 *                       rather than narrowed to an enum: the server owns this
 *                       vocabulary, and a value added server-side must not become a
 *                       deserialization failure for the whole list
 * @param hasBundledMark whether AXIAM ships this provider's own sign-in mark, which its
 *                       button must then use. {@code false} for the generic kinds,
 *                       whose buttons read "Sign in with {@code displayName}" and use
 *                       {@code buttonIcon} where the operator uploaded one
 * @param inherited      {@code true} when the provider is inherited from the
 *                       organization rather than configured on this tenant (&sect;12.1
 *                       note 13). Informational — it is not needed to sign in, and
 *                       nothing in this SDK computes it
 * @param buttonIcon     the operator's uploaded button icon as a bounded raster
 *                       {@code data:} URL, or {@code null} — which is the case for most
 *                       providers: it is present only for generic ones whose operator
 *                       uploaded a mark
 */
public record FederationProvider(
        String id,
        String providerKind,
        String displayName,
        String protocol,
        boolean hasBundledMark,
        boolean inherited,
        @Nullable String buttonIcon) {

    /** {@code protocol} value selecting {@code ssoStart} (CONTRACT.md &sect;12.1 note 10). */
    public static final String PROTOCOL_OIDC_CONNECT = "OidcConnect";

    /** {@code protocol} value selecting {@code ssoStartOauth2} (&sect;12.1 note 10). */
    public static final String PROTOCOL_OAUTH2 = "OAuth2";

    /**
     * {@code protocol} value selecting the SAML login endpoint, which is
     * <strong>not</strong> a &sect;12 vocabulary operation (&sect;12.1 note 10).
     */
    public static final String PROTOCOL_SAML = "Saml";
}
