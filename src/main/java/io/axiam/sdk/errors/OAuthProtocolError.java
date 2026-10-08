package io.axiam.sdk.errors;

import org.jspecify.annotations.Nullable;

/**
 * An RFC 6749 protocol error returned by an {@code /oauth2/*} endpoint as an
 * {@code OAuth2ErrorResponse} body (CONTRACT.md &sect;2 sub-type table,
 * &sect;12.3 rule 3).
 *
 * <p>A sub-type of {@link AuthError}, not a replacement for it: existing
 * {@code catch (AuthError e)} code keeps working unchanged. Raised for a
 * {@code 400} from {@code POST /oauth2/token} (e.g. {@code invalid_grant})
 * and for a {@code 401} from {@code POST /oauth2/introspect} /
 * {@code POST /oauth2/revoke} (client authentication failed) — neither of
 * which may collapse into the generic &sect;2 {@code 400} &rarr;
 * {@link NetworkError} / {@code 401} &rarr; {@link AuthError} rows.
 *
 * <p>{@link #getMessage()} is exactly {@code "<error>: <error_description>"},
 * built from the two wire fields, or just {@code "<error>"} when the server
 * sent no {@code error_description} &mdash; RFC 6749 &sect;5.2 makes that
 * member OPTIONAL, and CONTRACT.md &sect;2 dispatches on {@code error} alone.
 * Both are also exposed individually via {@link #error()} and
 * {@link #errorDescription()}.
 *
 * <p>{@link #isAccessDenied()} and {@link #isExpiredToken()} tell apart the two
 * terminal answers a polling grant can end in (CONTRACT.md &sect;14.2 rule 3,
 * &sect;33.4): a person said no, or nobody answered in time.
 */
public final class OAuthProtocolError extends AuthError {

    /** The RFC 6749 {@code error} code (e.g. {@code "invalid_grant"}, {@code "invalid_client"}). */
    private final String error;

    /** The server's human-readable {@code error_description}, or {@code null} when it sent none. Never contains token material. */
    private final @Nullable String errorDescription;

    /**
     * Creates an {@code OAuthProtocolError} from an {@code OAuth2ErrorResponse} body.
     *
     * @param error            the RFC 6749 {@code error} code
     * @param errorDescription the server's human-readable description of {@code error},
     *                         or {@code null} when the server sent none
     */
    public OAuthProtocolError(String error, @Nullable String errorDescription) {
        super(errorDescription == null ? error : error + ": " + errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
    }

    /**
     * Returns the RFC 6749 {@code error} code.
     *
     * @return the RFC 6749 {@code error} code (e.g. {@code "invalid_grant"})
     */
    public String error() {
        return error;
    }

    /**
     * Returns the server's human-readable description of {@link #error()}.
     *
     * @return the server's {@code error_description}, or {@code null} when the
     *         server sent none; never contains token material
     */
    public @Nullable String errorDescription() {
        return errorDescription;
    }

    /**
     * Whether this is the {@code access_denied} answer &mdash; at a CIBA or
     * device-grant poll, the user refused (CONTRACT.md &sect;33.4, &sect;14.2
     * rule 3). Terminal, and distinct from {@link #isExpiredToken()}.
     *
     * @return {@code true} when {@link #error()} is {@code access_denied}
     */
    public boolean isAccessDenied() {
        return "access_denied".equals(error);
    }

    /**
     * Whether this is the {@code expired_token} answer &mdash; at a CIBA or
     * device-grant poll, nobody decided in time. Also raised locally by
     * {@code cibaAwait} and {@code deviceLogin} when they reach their
     * {@code expires_in} deadline (CONTRACT.md &sect;33.7 rule 4).
     *
     * @return {@code true} when {@link #error()} is {@code expired_token}
     */
    public boolean isExpiredToken() {
        return "expired_token".equals(error);
    }
}
