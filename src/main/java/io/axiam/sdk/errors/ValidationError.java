package io.axiam.sdk.errors;

import java.util.List;

/**
 * HTTP 400 or 422 on the CONTRACT.md &sect;27 management surface: the request
 * was rejected.
 *
 * <p>&sect;2 maps 400 to {@link NetworkError}, described there as an "SDK
 * programming error". That description was written when nothing but the SDK
 * itself could produce a 400. On this surface a 400 is usually a
 * <em>user's</em> invalid input — an email that is not an email, a slug
 * already taken — and an application needs to tell that from a broken socket
 * without matching on message text. The parent type is inherited from &sect;2
 * rather than chosen here.
 */
public final class ValidationError extends NetworkError {

    /** The registry operation that was rejected, e.g. {@code "users.create"}. */
    private final String operation;

    /** The HTTP status the server answered with — 400 or 422. */
    private final int status;

    /** Per-field detail, where the server sent any. Empty is normal. */
    private final List<FieldError> fields;

    /**
     * Creates a {@code ValidationError} for a rejected management request.
     *
     * @param operation the registry operation that was rejected,
     *                  e.g. {@code "users.create"}
     * @param status the HTTP status the server answered with — 400 or 422
     * @param message the full, caller-facing description
     * @param fields per-field detail, where the server sent any; never
     *               {@code null}, and empty is normal
     */
    public ValidationError(String operation, int status, String message, List<FieldError> fields) {
        super(message);
        this.operation = operation;
        this.status = status;
        this.fields = List.copyOf(fields);
    }

    /**
     * Returns the registry operation that was rejected.
     *
     * @return the namespace-qualified operation name, e.g. {@code "users.create"}
     */
    public String operation() {
        return operation;
    }

    /**
     * Returns the HTTP status the server answered with.
     *
     * @return {@code 400} or {@code 422}
     */
    public int status() {
        return status;
    }

    /**
     * Returns the per-field detail the server sent, if any.
     *
     * @return an unmodifiable list of field-level complaints; empty is normal,
     *         because not every rejection carries per-field detail
     */
    public List<FieldError> fields() {
        return fields;
    }
}
