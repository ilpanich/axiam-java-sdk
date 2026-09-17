package io.axiam.sdk.mcp;

import org.jspecify.annotations.Nullable;

/**
 * The &sect;28 challenge values a guard emits, built once at guard-construction
 * time so that an invalid one is a startup failure rather than a surprise on
 * the 401 path.
 *
 * <p>Returned by {@link Mcp#mcpGuardChallenges}; {@code null} from that method
 * where {@code resourceMetadataUrl} is unset, which is how "&sect;28 is off"
 * stays byte-for-byte indistinguishable from "&sect;28 is absent" (&sect;28.5
 * rule 1).
 *
 * @param noCredential &sect;28.4 vector 1 &mdash; the request carried
 *                     <strong>no</strong> authentication information, so RFC
 *                     6750 &sect;3 says not to name an error
 * @param invalidToken &sect;28.4 vector 2 &mdash; a credential was presented
 *                     and rejected. The only thing a 401 this guard emits
 *                     ever says about why
 * @param insufficientScope &sect;28.4 vector 3 &mdash; present only where the
 *                          route named a scope at construction time; emitted
 *                          on a {@code no_grant} denial and nowhere else
 * @param metadataPath the document's path, exempted from authentication by
 *                     the guard (&sect;28.3 rule 2)
 */
public record McpGuardChallenges(
        String noCredential, String invalidToken, @Nullable String insufficientScope, String metadataPath) {
}
