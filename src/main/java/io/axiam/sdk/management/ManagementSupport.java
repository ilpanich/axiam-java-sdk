package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.ManagementTransport;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/**
 * The pieces every generated namespace handle leans on.
 *
 * <p>Package-private on purpose: the generated handles live in this package, so
 * nothing here needs to be public, and none of it is API a caller should reach
 * for.
 */
final class ManagementSupport {

    private ManagementSupport() {
    }

    /**
     * Resolves {@code {org_id}}: the handle's override, else the client's.
     *
     * <p>A client that was built with an organization <em>slug</em> and has not
     * logged in fails HERE, with no wire call. &sect;27.4 rule 3 forbids
     * resolving the slug behind the caller's back: a silent extra round-trip on
     * an admin path is what &sect;12.1 rule 2 refuses for {@code /oauth2/*}, and
     * for the same reason — the caller cannot see it, cannot cache it, and pays
     * for it on every call.
     */
    static UUID resolveOrg(ManagementTransport transport, NamespaceScope scope, String operation) {
        if (scope.orgId() != null) {
            return scope.orgId();
        }
        UUID resolved = transport.session().resolvedOrgId();
        if (resolved != null) {
            return resolved;
        }
        throw new NetworkError(operation
                + ": this route needs an organization UUID and the client has none. Build the "
                + "client with orgId(...), log in so the access token's org_id claim resolves "
                + "one, or name one on the handle with inOrg(...).");
    }

    /**
     * Resolves {@code {tenant_id}} where it names the <em>context</em>, not the
     * object.
     *
     * <p>Namespaces where {@code {tenant_id}} names the thing being acted on —
     * {@code tenants}, and the signing CAs under {@code ca_certificates} — take
     * it as an ordinary argument instead and never reach this.
     */
    static UUID resolveTenant(ManagementTransport transport, NamespaceScope scope, String operation) {
        if (scope.tenantId() != null) {
            return scope.tenantId();
        }
        UUID resolved = transport.session().resolvedTenantId();
        if (resolved != null) {
            return resolved;
        }
        throw new NetworkError(operation
                + ": this route needs a tenant UUID, but none has been resolved yet. Call "
                + "login() so the access token's tenant_id claim resolves one, or name one on "
                + "the handle with forTenant(...).");
    }

    /**
     * The query contribution of a {@link PageRequest}.
     *
     * <p>{@code limit} is omitted entirely when unset rather than sent as
     * {@code 0} — the server reads {@code limit=0} as "none", which would
     * return an empty page.
     */
    static java.util.Map<String, @Nullable String> pageQuery(
            java.util.Map<String, @Nullable String> query, @Nullable PageRequest page) {
        PageRequest request = page == null ? PageRequest.first() : page;
        query.put("offset", Integer.toString(request.offset()));
        query.put("limit", request.limit() == null ? null : Integer.toString(request.limit()));
        query.put("search", normalizeSearch(request.search()));
        return query;
    }

    /**
     * The trimmed term, or {@code null} when there is nothing to filter on.
     *
     * <p>Mirrors the server's own normalisation minus the length cap, which is
     * the server's to apply. A {@code null} value here is dropped before the
     * request is built, so an unfiltered read and a read whose search box was
     * cleared are the same request on the wire (&sect;27.4 rule 4).
     */
    static @Nullable String normalizeSearch(@Nullable String term) {
        if (term == null) {
            return null;
        }
        String trimmed = term.strip();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** Converts a response node into a model, or throws a {@link NetworkError}. */
    static <T> T convert(@Nullable JsonNode node, Class<T> type, String operation) {
        try {
            return ManagementTransport.reader().treeToValue(
                    node == null ? ManagementTransport.reader().createObjectNode() : node, type);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new NetworkError(operation + ": the server's response did not match "
                    + type.getSimpleName() + ": " + e.getOriginalMessage(), e);
        }
    }

    /** Converts a bare-array response into a list of models. */
    static <T> List<T> convertList(@Nullable JsonNode node, Class<T> type, String operation) {
        List<T> out = new ArrayList<>();
        if (node == null || !node.isArray()) {
            return List.copyOf(out);
        }
        for (JsonNode item : node) {
            out.add(convert(item, type, operation));
        }
        return List.copyOf(out);
    }

    /**
     * Converts a {@code {items, total, offset, limit}} envelope into a page.
     *
     * <p>{@code total} is read from the envelope and never inferred from the
     * item count: the whole point of the type is that the two differ.
     */
    static <T> Page<T> convertPage(@Nullable JsonNode node, Class<T> type, String operation) {
        if (node == null) {
            return new Page<>(List.of(), 0, 0, 0);
        }
        return new Page<>(convertList(node.get("items"), type, operation),
                node.path("total").asInt(0), node.path("offset").asInt(0),
                node.path("limit").asInt(0));
    }

    /**
     * Walks a paginated read to exhaustion, concatenating every page.
     *
     * <p>The {@code listAll} shape &sect;27.4 rule 4 requires. The walk stops on
     * an empty page even when {@code total} disagrees, so a misreporting server
     * costs one wasted request rather than an unbounded loop.
     */
    static <T> List<T> collectPages(@Nullable PageRequest start, Function<PageRequest, Page<T>> fetch) {
        PageRequest request = start == null ? PageRequest.first() : start;
        List<T> out = new ArrayList<>();
        while (true) {
            Page<T> page = fetch.apply(request);
            out.addAll(page.items());
            int next = page.offset() + page.items().size();
            if (page.items().isEmpty() || next >= page.total()) {
                return List.copyOf(out);
            }
            request = request.atOffset(next);
        }
    }
}
