package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import java.time.Instant;
import java.util.Objects;

/**
 * {@code CibaInitiateResponse} (CONTRACT.md &sect;33.2), plus when it was received.
 *
 * <p><strong>A successful initiation proves nothing about the user</strong>
 * (&sect;33.3 rule 4): AXIAM answers a hint that names nobody, a locked user and
 * a real one identically, and the only signal that a user did not answer is
 * {@code expired_token}.
 *
 * @param authReqId  the request's id at the token endpoint &mdash; a bearer credential for the grant
 *                   (&sect;33.5); never parse or length-check it
 * @param expiresIn  the request's lifetime in seconds &mdash; authoritative (&sect;33.7 rule 4)
 * @param interval   the minimum seconds between token requests: the response's value, or 5 when it
 *                   was absent or zero
 * @param receivedAt when the response was received; {@code cibaAwait}'s deadline is this plus
 *                   {@code expiresIn}
 */
public record CibaInitiateResponse(Sensitive authReqId, long expiresIn, long interval, Instant receivedAt) {

    /**
     * Requires the id and the receipt time.
     *
     * @param authReqId  the request's id
     * @param expiresIn  the lifetime in seconds
     * @param interval   the polling interval in seconds
     * @param receivedAt when the response was received
     */
    public CibaInitiateResponse {
        Objects.requireNonNull(authReqId, "authReqId");
        Objects.requireNonNull(receivedAt, "receivedAt");
    }
}
