package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

/**
 * The tuple an {@link OidcStateStore} holds for one in-flight login
 * (CONTRACT.md &sect;12.3 rule 1).
 *
 * <p>{@link #codeVerifier()} stays {@link Sensitive} while stored (CONTRACT.md
 * &sect;12.5: the verifier is secret for its whole lifetime, "including …
 * in any {@code OidcStateStore} entry"), so this record's {@code toString()}
 * — e.g. logged by a custom store implementation — never emits the raw
 * verifier.
 *
 * @param state        the {@code state} value this entry is keyed by; not a secret (CONTRACT.md &sect;12.3 rule 2)
 * @param nonce        the {@code nonce} to check the ID token's {@code nonce} claim against; not a secret (&sect;12.3 rule 2)
 * @param codeVerifier the PKCE verifier for the matching authorization request (&sect;12.5 secret)
 * @param redirectUri  the {@code redirect_uri} that was sent on the authorization request and must be replayed on exchange
 * @param returnTo     optional application-owned data, e.g. the page the user was heading to before login
 */
public record OidcStateEntry(String state, String nonce, Sensitive codeVerifier, String redirectUri,
        @Nullable String returnTo) {

    /**
     * Convenience constructor for an entry with no {@link #returnTo()} data.
     *
     * @param state        the {@code state} value this entry is keyed by
     * @param nonce        the {@code nonce} to check the ID token's {@code nonce} claim against
     * @param codeVerifier the PKCE verifier for the matching authorization request
     * @param redirectUri  the {@code redirect_uri} that was sent on the authorization request
     */
    public OidcStateEntry(String state, String nonce, Sensitive codeVerifier, String redirectUri) {
        this(state, nonce, codeVerifier, redirectUri, null);
    }
}
