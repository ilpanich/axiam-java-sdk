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
 * <p>{@code search} lives here rather than as a third argument on each of the
 * twenty generated {@code list} methods, which is what &sect;27.4 rule 4
 * requires: the term is part of <em>which page this is</em>, not an unrelated
 * filter. That is also what makes {@link #atOffset(int)} — and so
 * {@code listAll} — carry it across the whole walk for free. A walk that
 * filtered the first request and not the rest would return the matches followed
 * by the unfiltered tail, which reads as a server bug from the caller's side.
 *
 * @param offset how many items to skip
 * @param limit how many items to take, or {@code null} to let the server decide
 * @param search a free-text filter applied by the <strong>server</strong>,
 *     before {@code offset}/{@code limit}, or {@code null} for none
 */
public record PageRequest(int offset, @Nullable Integer limit, @Nullable String search) {

    /**
     * A request with no search term.
     *
     * <p>Kept so a call site written against contract 1.30's two-component
     * record still compiles: adding a component to a record is otherwise a
     * source-breaking change for every {@code new PageRequest(...)} in the wild.
     *
     * @param offset how many items to skip
     * @param limit how many items to take, or {@code null} to let the server decide
     */
    public PageRequest(int offset, @Nullable Integer limit) {
        this(offset, limit, null);
    }

    /**
     * A request starting at offset zero, letting the server choose the size.
     *
     * @return a {@code PageRequest} with no offset and no limit
     */
    public static PageRequest first() {
        return new PageRequest(0, null, null);
    }

    /**
     * A request starting at offset zero for at most {@code limit} items.
     *
     * @param limit how many items to take
     * @return a {@code PageRequest} for the first {@code limit} items
     */
    public static PageRequest of(int limit) {
        return new PageRequest(0, limit, null);
    }

    /**
     * A request for the first {@code limit} items matching {@code term}.
     *
     * <p>The term is matched case-insensitively by the server against the
     * identifying fields of whatever is being listed — a name or username, plus
     * the record id, so a UUID out of a log line can be pasted in as-is.
     * {@link Page#total()} then counts <em>matches</em>, not rows, which is what
     * lets a pager built on it show a page count belonging to the result set it
     * is paging.
     *
     * <p>An empty or whitespace-only {@code term} is the same request as none
     * (&sect;27.4 rule 4): a search box that fires on every keystroke sends one
     * the moment it is cleared, and "rows containing the empty string" is a
     * different question from "all rows".
     *
     * <p>The server caps the term's length. This SDK deliberately does not
     * re-implement that cap — a client-side truncation the server would not have
     * made is a silently different query.
     *
     * @param limit how many items to take
     * @param term the free-text filter
     * @return a {@code PageRequest} for the first {@code limit} matches
     */
    public static PageRequest matching(int limit, @Nullable String term) {
        return new PageRequest(0, limit, term);
    }

    /**
     * A copy of this request starting at {@code offset} instead.
     *
     * <p>The search term is carried, not dropped — that is what makes the
     * auto-paging walk filter every request rather than only its first
     * (&sect;27.4 rule 4).
     *
     * @param offset how many items to skip
     * @return a {@code PageRequest} with the same limit and term, and the given offset
     */
    public PageRequest atOffset(int offset) {
        return new PageRequest(offset, limit, search);
    }
}
