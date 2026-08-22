package io.axiam.sdk.account;

import com.fasterxml.jackson.databind.JsonNode;
import io.axiam.sdk.Sensitive;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Everything {@code confirmPasswordReset} needs (CONTRACT.md &sect;25.1).
 *
 * @param token       the single-use token from the reset mail
 * @param newPassword the replacement password
 * @param tenantId    the tenant the account belongs to. A <strong>body</strong>
 *                    field — this is not an {@code /oauth2/*} endpoint.
 * @param opaque      the &sect;23 registration record, for a tenant whose
 *                    {@code passwordResetContext} says it requires one. Sending
 *                    a plaintext {@code newPassword} to a tenant in
 *                    {@code opaque_mode: required} is refused, and refused late
 *                    (&sect;25.4 rule 1).
 */
public record PasswordResetConfirmation(
        Sensitive token, Sensitive newPassword, UUID tenantId, @Nullable JsonNode opaque) {

    /**
     * A confirmation with no &sect;23 record — the plaintext path.
     *
     * @param token       the single-use token from the reset mail
     * @param newPassword the replacement password
     * @param tenantId    the tenant the account belongs to
     */
    public PasswordResetConfirmation(Sensitive token, Sensitive newPassword, UUID tenantId) {
        this(token, newPassword, tenantId, null);
    }
}
