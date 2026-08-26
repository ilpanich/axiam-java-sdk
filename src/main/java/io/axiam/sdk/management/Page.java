package io.axiam.sdk.management;

import java.util.List;

/**
 * One page of a paginated management read (CONTRACT.md &sect;27.4 rule 4).
 *
 * <p>Twenty of the 146 operations take {@code offset}/{@code limit} and answer
 * with the envelope {@code {items, total, offset, limit}}. The other thirteen
 * collection reads answer with a bare array and are <em>not</em> paginated —
 * &sect;27.4 rule 4 forbids modelling those as a page, because a {@code Page}
 * reporting {@code total == items.size()} is indistinguishable from a real one
 * right up to the moment a caller relies on {@code total}.
 *
 * @param <T> the item type this page carries
 * @param items the items on this page
 * @param total how many items exist in the whole set, across every page
 * @param offset the offset this page starts at
 * @param limit the page size the server applied
 */
public record Page<T>(List<T> items, int total, int offset, int limit) {

    /**
     * Canonical constructor, defensively copying {@code items}.
     *
     * @param items the items on this page
     * @param total how many items exist in the whole set, across every page
     * @param offset the offset this page starts at
     * @param limit the page size the server applied
     */
    public Page {
        items = List.copyOf(items);
    }

    /**
     * Whether another page follows this one.
     *
     * @return {@code true} when this page is non-empty and does not reach
     *         {@link #total}
     */
    public boolean hasMore() {
        return !items.isEmpty() && offset + items.size() < total;
    }
}
