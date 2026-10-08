package io.axiam.sdk.ssf;

/**
 * Why {@link SsfReceiver#verifySet(String)} refused a SET &mdash; the step of
 * CONTRACT.md &sect;32.7 that failed.
 */
public enum SetFailureReason {
    /** Not three base64url parts decoding to a JSON header and payload object (step 1). */
    MALFORMED("malformed"),
    /** The header {@code typ} is not {@code secevent+jwt} / {@code application/secevent+jwt} (step 2). */
    INVALID_TYPE("invalid_type"),
    /** {@code alg} not {@code EdDSA}, no key for {@code kid} after one refetch, or a bad signature (steps 3&ndash;5). */
    INVALID_KEY("invalid_key"),
    /** {@code iss} is not the configured issuer (step 6). */
    INVALID_ISSUER("invalid_issuer"),
    /** {@code aud} does not name the configured audience (step 7). */
    INVALID_AUDIENCE("invalid_audience"),
    /**
     * {@code exp} or {@code sub} present, {@code jti}/{@code iat}/{@code sub_id}
     * absent or mistyped, or {@code events} not exactly one member (step 8).
     */
    INVALID_REQUEST("invalid_request"),
    /** The {@code jti} was already seen inside the replay window (step 9). */
    REPLAYED("replayed");

    private final String code;

    SetFailureReason(String code) {
        this.code = code;
    }

    /**
     * The reason code as the contract spells it ({@code "replayed"} included).
     *
     * @return the code
     */
    public String code() {
        return code;
    }

    /**
     * The RFC 8935 &sect;2.4 {@code err} value to answer a push with, or to send
     * in a poll's {@code setErrs}: {@link #code()} where RFC 8935 defines the
     * code, and {@code invalid_request} for {@link #MALFORMED},
     * {@link #INVALID_TYPE} and {@link #REPLAYED}, which it does not (it defines
     * {@code invalid_request}, {@code invalid_key}, {@code invalid_issuer},
     * {@code invalid_audience}, {@code authentication_failed} and
     * {@code access_denied} only).
     *
     * @return the RFC 8935 {@code err} code
     */
    public String pushErrorCode() {
        return switch (this) {
            case MALFORMED, INVALID_TYPE, REPLAYED -> "invalid_request";
            default -> code;
        };
    }
}
