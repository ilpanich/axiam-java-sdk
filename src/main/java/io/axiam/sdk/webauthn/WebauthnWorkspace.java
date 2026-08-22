package io.axiam.sdk.webauthn;

import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * The workspace a usernameless ceremony runs inside (CONTRACT.md &sect;24.1).
 *
 * <p>Unlike the five tenant-scoped {@code /oauth2/*} operations of &sect;12.1
 * rule 2, this endpoint <strong>accepts slugs</strong>, so a slug-only client
 * can run a discoverable sign-in. The SDK fills these from its own configured
 * identity when the caller passes {@code null}.
 *
 * @param orgId      organization UUID
 * @param orgSlug    organization slug — accepted here, unlike on the
 *                   {@code /oauth2/*} operations
 * @param tenantId   tenant UUID
 * @param tenantSlug tenant slug
 */
public record WebauthnWorkspace(
        @Nullable UUID orgId,
        @Nullable String orgSlug,
        @Nullable UUID tenantId,
        @Nullable String tenantSlug) {
}
