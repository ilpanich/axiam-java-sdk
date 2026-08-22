package io.axiam.sdk.webauthn;

import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * A credential the user just enrolled — the {@code 201} body of
 * {@code register/finish} (CONTRACT.md &sect;24.1).
 *
 * @param id             the AXIAM record id
 * @param credentialId   base64url credential id, as the authenticator reported it
 * @param name           the caller-supplied label
 * @param credentialType {@code "passkey"} or {@code "security_key"}, as the
 *                       server classified it
 * @param createdAt      RFC 3339 timestamp of enrolment
 * @param lastUsedAt     RFC 3339 timestamp of the last successful assertion,
 *                       {@code null} when the credential has never produced one
 */
public record WebauthnCredential(
        UUID id,
        String credentialId,
        String name,
        String credentialType,
        String createdAt,
        @Nullable String lastUsedAt) {
}
