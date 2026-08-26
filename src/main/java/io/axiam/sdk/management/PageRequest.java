package io.axiam.sdk.management;

import org.jspecify.annotations.Nullable;

/**
 * Where a paginated management read starts, and how much of it to take
 * (CONTRACT.md &sect;27.4 rule 4).
 *
 * <p>{@code limit} is deliberately nullable with no SDK-side default:
 * &sect;27.4 rule 4 forbids silently truncating, and a client-side default does
 * exactly that while leaving the caller no way to tell a short page from a
 * complete one. A {@code null} limit lets the server decide.
 *
 * @param offset how many items to skip
 * @param limit how many items to take, or {@code null} to let the server decide
 */
public record PageRequest(int offset, @Nullable Integer limit) {

    /**
     * A request starting at offset zero, letting the server choose the size.
     *
     * @return a {@code PageRequest} with no offset and no limit
     */
    public static PageRequest first() {
        return new PageRequest(0, null);
    }

    /**
     * A request starting at offset zero for at most {@code limit} items.
     *
     * @param limit how many items to take
     * @return a {@code PageRequest} for the first {@code limit} items
     */
    public static PageRequest of(int limit) {
        return new PageRequest(0, limit);
    }

    /**
     * A copy of this request starting at {@code offset} instead.
     *
     * @param offset how many items to skip
     * @return a {@code PageRequest} with the same limit and the given offset
     */
    public PageRequest atOffset(int offset) {
        return new PageRequest(offset, limit);
    }
}
