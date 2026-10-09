package io.axiam.sdk.ssf;

import com.fasterxml.jackson.annotation.JsonInclude;

import org.jspecify.annotations.Nullable;

/**
 * An RFC 8936 {@code setErrs} entry, also the RFC 8935 push answer body
 * ({@code 400 {"err": ...}}).
 *
 * @param err         the RFC 8935 &sect;2.4 code
 * @param description optional text; AXIAM never stores it (CONTRACT.md &sect;32.6)
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SetErr(String err, @Nullable String description) {

    /**
     * The entry for a refusal: its {@link SetFailureReason#pushErrorCode()}.
     *
     * @param reason why the SET was refused
     * @return the entry
     */
    public static SetErr fromReason(SetFailureReason reason) {
        return new SetErr(reason.pushErrorCode(), null);
    }
}
