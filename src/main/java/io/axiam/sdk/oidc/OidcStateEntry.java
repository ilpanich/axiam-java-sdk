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
 * @param bindingDigest optional (contract 1.68, &sect;12.8 rule 1): lower-case hex SHA-256 of the browser-binding
 *                     cookie value the login glue set; the callback refuses an entry that has none. A caller-supplied
 *                     store MUST persist it and return it unchanged. Not a secret, but kept out of {@link #toString()}
 */
public record OidcStateEntry(String state, String nonce, Sensitive codeVerifier, String redirectUri,
        @Nullable String returnTo, @Nullable String bindingDigest) {

    /**
     * Constructor for an entry with {@link #returnTo()} data and no browser binding
     * (the shape this record had before contract 1.68).
     *
     * @param state        the {@code state} value this entry is keyed by
     * @param nonce        the {@code nonce} to check the ID token's {@code nonce} claim against
     * @param codeVerifier the PKCE verifier for the matching authorization request
     * @param redirectUri  the {@code redirect_uri} that was sent on the authorization request
     * @param returnTo     optional application-owned data
     */
    public OidcStateEntry(String state, String nonce, Sensitive codeVerifier, String redirectUri,
            @Nullable String returnTo) {
        this(state, nonce, codeVerifier, redirectUri, returnTo, null);
    }

    /**
     * Returns a copy of this entry carrying {@code digest} as its browser-binding digest.
     *
     * @param digest lower-case hex SHA-256 of the binding cookie value
     * @return the bound copy
     */
    public OidcStateEntry withBindingDigest(String digest) {
        return new OidcStateEntry(state, nonce, codeVerifier, redirectUri, returnTo, digest);
    }

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

    /**
     * Redacts the code verifier and the browser-binding digest (CONTRACT.md &sect;12.8 rule 1 (e):
     * the digest is not logged either).
     */
    @Override
    public String toString() {
        return "OidcStateEntry[state=" + state + ", nonce=" + nonce + ", codeVerifier=[SENSITIVE], redirectUri="
                + redirectUri + ", returnTo=" + returnTo + ", bindingDigest="
                + (bindingDigest == null ? "null" : "[REDACTED]") + "]";
    }
}
