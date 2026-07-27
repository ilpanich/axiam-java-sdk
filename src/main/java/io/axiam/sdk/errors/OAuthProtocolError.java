package io.axiam.sdk.errors;

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
 * <p>{@link #getMessage()} is always exactly {@code "<error>: <error_description>"},
 * built from the two wire fields, which are also exposed individually via
 * {@link #error()} and {@link #errorDescription()}.
 */
public final class OAuthProtocolError extends AuthError {

    /** The RFC 6749 {@code error} code (e.g. {@code "invalid_grant"}, {@code "invalid_client"}). */
    private final String error;

    /** The server's human-readable {@code error_description}. Never contains token material. */
    private final String errorDescription;

    /**
     * Creates an {@code OAuthProtocolError} from an {@code OAuth2ErrorResponse} body.
     *
     * @param error            the RFC 6749 {@code error} code
     * @param errorDescription the server's human-readable description of {@code error}
     */
    public OAuthProtocolError(String error, String errorDescription) {
        super(error + ": " + errorDescription);
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
     * @return the server's {@code error_description}; never contains token material
     */
    public String errorDescription() {
        return errorDescription;
    }
}
