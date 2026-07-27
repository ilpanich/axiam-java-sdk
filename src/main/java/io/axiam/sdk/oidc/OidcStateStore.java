package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

/**
 * Optional server-side store for in-flight {@code oidcBegin} state
 * (CONTRACT.md &sect;12.3 rule 1).
 *
 * <p>Implement this to back the login/callback handlers with your own storage
 * (Redis, a database, an encrypted cookie). Two invariants are normative:
 *
 * <ol>
 *   <li><strong>Single-use.</strong> {@link #consume(String)} MUST return the
 *       entry <em>and delete it atomically</em>, so a replayed callback
 *       cannot reuse a {@code state}.</li>
 *   <li><strong>Expiry.</strong> An entry older than 10 minutes MUST NOT be
 *       returned.</li>
 * </ol>
 *
 * <p>Strictly optional: the nine &sect;12 operations never touch a store —
 * {@code oidcBegin} and {@code oidcExchange} are stateless by contract, and
 * the caller normally keeps {@code state}/{@code nonce}/{@code codeVerifier}
 * in its own HTTP session. This store exists for framework glue (the Spring
 * login/callback pair), where a login and its callback are two separate HTTP
 * requests with nothing but a {@code state} value linking them.
 */
public interface OidcStateStore {

    /**
     * Persists {@code entry}, keyed by its {@code state}, starting its TTL now.
     *
     * @param entry the entry to persist
     */
    void save(OidcStateEntry entry);

    /**
     * Atomically fetches <strong>and removes</strong> the entry for
     * {@code state}.
     *
     * @param state the {@code state} value to look up
     * @return the entry, or {@code null} when the state is unknown, already
     *         consumed, or expired — three cases a caller MUST treat
     *         identically (as a failed login), because distinguishing them
     *         leaks whether a {@code state} ever existed
     */
    @Nullable OidcStateEntry consume(String state);
}
