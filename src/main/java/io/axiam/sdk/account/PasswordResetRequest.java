package io.axiam.sdk.account;

import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Names the account a reset mail should go to (CONTRACT.md &sect;25.1).
 *
 * <p>Slugs are accepted here, as on {@code login} — this is not an
 * {@code /oauth2/*} endpoint and &sect;12.1 rule 2's UUID requirement does not
 * reach it. {@code null} fields fall back to the client's own configuration.
 *
 * @param email      the address to send the reset mail to
 * @param orgSlug    organization slug
 * @param tenantId   tenant UUID
 * @param tenantSlug tenant slug
 */
public record PasswordResetRequest(
        String email,
        @Nullable String orgSlug,
        @Nullable UUID tenantId,
        @Nullable String tenantSlug) {

    /**
     * A request naming only the address; the workspace comes from the client.
     *
     * @param email the address to send the reset mail to
     */
    public PasswordResetRequest(String email) {
        this(email, null, null, null);
    }
}
