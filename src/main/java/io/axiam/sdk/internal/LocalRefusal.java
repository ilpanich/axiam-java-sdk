package io.axiam.sdk.internal;

import io.axiam.sdk.errors.FieldError;
import io.axiam.sdk.errors.ValidationError;

import java.util.List;

/**
 * The SDK's local, pre-request {@link ValidationError} (CONTRACT.md &sect;28.7's
 * per-language note): what an operation raises when it refuses its own input
 * before any I/O.
 *
 * <p>{@code status} is {@code 400} &mdash; the code a server would answer for
 * the same rejected field &mdash; though no server was asked and no request was
 * made, exactly as {@code io.axiam.sdk.mcp.Mcp}'s &sect;28 refusals already do.
 * The message names the field and the rule, never the value: the value can be
 * a credential, and an error message is the line most often logged.
 *
 * <p>Internal plumbing; public only because the callers live in other packages.
 */
public final class LocalRefusal {

    private LocalRefusal() {
    }

    /**
     * Builds the refusal.
     *
     * @param operation the operation that refused, e.g. {@code "saml.parse_sp_metadata"}
     * @param field     the field the rule is about
     * @param message   the rule, naming no value
     * @return the error, ready to throw
     */
    public static ValidationError of(String operation, String field, String message) {
        return new ValidationError(operation, 400, operation + ": " + field + ": " + message,
                List.of(new FieldError(field, message)));
    }
}
