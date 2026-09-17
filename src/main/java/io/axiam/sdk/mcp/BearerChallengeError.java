package io.axiam.sdk.mcp;

/**
 * RFC 6750 &sect;3.1's three {@code error} codes &mdash; the complete
 * vocabulary a {@code WWW-Authenticate: Bearer} challenge may name
 * (CONTRACT.md &sect;28.4). Not even a well-formed-looking OAuth error code
 * such as {@code invalid_grant} is accepted outside these three.
 */
public enum BearerChallengeError {

    /** A 400 an application builds for its own malformed request; never emitted by this SDK's own guards. */
    INVALID_REQUEST("invalid_request"),
    /** A credential was presented and rejected &mdash; the only reason this SDK's own guards ever name. */
    INVALID_TOKEN("invalid_token"),
    /** A {@code require_access} check named a scope and the decision came back {@code no_grant} (&sect;28.5 rule 5). */
    INSUFFICIENT_SCOPE("insufficient_scope");

    private final String wireValue;

    BearerChallengeError(String wireValue) {
        this.wireValue = wireValue;
    }

    /**
     * The exact token this error is spelled with inside the challenge, e.g. {@code error="invalid_token"}.
     *
     * @return the RFC 6750 &sect;3.1 wire spelling
     */
    public String wireValue() {
        return wireValue;
    }
}
