package io.axiam.sdk.account;

import com.fasterxml.jackson.databind.JsonNode;
import org.jspecify.annotations.Nullable;

/**
 * The effective OPAQUE policy for the account a reset token belongs to
 * (CONTRACT.md &sect;25.1).
 *
 * <p>Discloses no identity. Contract 1.26 removed the username from this
 * response when OPAQUE replaced SRP — OPAQUE has no identity in its key
 * derivation, so nothing needed it, and an unauthenticated endpoint that
 * confirms which account a token belongs to is an oracle worth not having
 * (&sect;25.4 rule 2).
 *
 * @param opaque the tenant's OPAQUE parameters when it has OPAQUE enabled;
 *               {@code null} means plaintext is accepted
 */
public record PasswordResetContext(@Nullable JsonNode opaque) {
}
