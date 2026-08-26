package io.axiam.sdk.errors;

/**
 * HTTP 404 on the CONTRACT.md &sect;27 management surface: the resource does
 * not exist, <em>or</em> it belongs to another tenant.
 *
 * <p>The server answers identically in both cases on purpose: a
 * distinguishable "exists but not yours" lets a caller enumerate another
 * tenant's identifiers. That is why this extends {@link AuthzError} rather
 * than forming a category of its own — in a multi-tenant IAM the two really
 * are one outcome, and a caller's pre-&sect;27
 * {@code catch (AuthzError e)} still catches it.
 */
public final class NotFoundError extends AuthzError {

    /** The registry operation that found nothing, e.g. {@code "users.get"}. */
    private final String operation;

    /**
     * Creates a {@code NotFoundError} for a management operation.
     *
     * @param operation the registry operation that found nothing,
     *                  e.g. {@code "users.get"}
     * @param message the full, caller-facing description
     */
    public NotFoundError(String operation, String message) {
        super(message);
        this.operation = operation;
    }

    /**
     * Returns the registry operation that found nothing.
     *
     * @return the namespace-qualified operation name, e.g. {@code "users.get"}
     */
    public String operation() {
        return operation;
    }
}
