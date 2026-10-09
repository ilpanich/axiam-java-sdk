package io.axiam.sdk.ssf;

/**
 * One SET a poll returned and the helper refused. Pass
 * {@link SetErr#fromReason(SetFailureReason)} of it in the next poll's
 * {@code setErrs}.
 *
 * @param jti    the key the transmitter returned the SET under
 * @param reason why it was refused
 */
public record RefusedSet(String jti, SetFailureReason reason) {
}
