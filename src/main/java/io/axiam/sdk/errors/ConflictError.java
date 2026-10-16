package io.axiam.sdk.errors;

import org.jspecify.annotations.Nullable;

/**
 * HTTP 409 on the CONTRACT.md &sect;27 management surface: a uniqueness or
 * state conflict, such as a role name already taken.
 *
 * <p>Never retried (&sect;27.4 rule 8): a 409 is the server telling the truth,
 * not a transient fault, and a retry produces the identical answer one
 * round-trip later.
 *
 * <p>Extends {@link AuthzError}, which &sect;2 already maps 409 to, so a
 * caller's pre-&sect;27 {@code catch (AuthzError e)} still catches it.
 *
 * <p>A 409 of the {@code network} namespace (&sect;36.4, contract 1.62) names its kind in
 * {@code reason_code}, and {@link #reasonCode()} surfaces it verbatim. A caller branches on
 * that and never on the message, which an SDK must not parse; the vocabulary is open, so a
 * value this SDK does not know is returned as the server sent it.
 */
public final class ConflictError extends AuthzError {

    /** The registry operation that conflicted, e.g. {@code "roles.create"}. */
    private final String operation;

    /** The body's {@code reason_code}, verbatim, or {@code null} when it carried none. */
    private final @Nullable String reasonCode;

    /**
     * Creates a {@code ConflictError} for a management operation.
     *
     * @param operation the registry operation that conflicted,
     *                  e.g. {@code "roles.create"}
     * @param message the full, caller-facing description
     */
    public ConflictError(String operation, String message) {
        this(operation, message, null);
    }

    /**
     * Creates a {@code ConflictError} that carries the body's {@code reason_code}.
     *
     * @param operation the registry operation that conflicted,
     *                  e.g. {@code "network.replace_segment"}
     * @param message the full, caller-facing description
     * @param reasonCode the body's {@code reason_code} verbatim, or {@code null} when the
     *                   server (one predating contract 1.62, or an operation that does not
     *                   name one) omitted it
     */
    public ConflictError(String operation, String message, @Nullable String reasonCode) {
        super(message);
        this.operation = operation;
        this.reasonCode = reasonCode;
    }

    /**
     * Returns the server's {@code reason_code} for this 409 (CONTRACT.md &sect;36.3 rule 2,
     * &sect;36.4).
     *
     * <p>For the {@code network} operations one of {@code stale_version},
     * {@code strands_profile}, {@code has_children}, {@code site_gone},
     * {@code duplicate_name}, {@code duplicate_vlan}, {@code duplicate_rank},
     * {@code profile_exists} or {@code other}. The vocabulary is open: an unknown value is
     * returned as sent. It is not the {@code reason} of an authorization decision.
     *
     * @return the machine-readable sub-code, or {@code null} when the response had none
     */
    public @Nullable String reasonCode() {
        return reasonCode;
    }

    /**
     * Returns the registry operation that conflicted.
     *
     * @return the namespace-qualified operation name, e.g. {@code "roles.create"}
     */
    public String operation() {
        return operation;
    }
}
