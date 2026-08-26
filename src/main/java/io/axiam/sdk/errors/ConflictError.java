package io.axiam.sdk.errors;

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
 */
public final class ConflictError extends AuthzError {

    /** The registry operation that conflicted, e.g. {@code "roles.create"}. */
    private final String operation;

    /**
     * Creates a {@code ConflictError} for a management operation.
     *
     * @param operation the registry operation that conflicted,
     *                  e.g. {@code "roles.create"}
     * @param message the full, caller-facing description
     */
    public ConflictError(String operation, String message) {
        super(message);
        this.operation = operation;
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
