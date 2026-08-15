package io.axiam.sdk.reactor;

import java.util.List;
import java.util.Objects;

/**
 * One hookable event: its name, what a reactor may change, and what happens when
 * the reactor does not answer (CONTRACT.md &sect;22.5).
 *
 * <p>Mirrors the server's {@code ReactorEventSpec} in
 * {@code crates/axiam-core/src/models/reactor.rs}, which is the single source of
 * truth. The live copy is served at {@code GET /api/v1/reactors/events}; this
 * one is here so a wire contract does not require a network call to be
 * understood.
 *
 * @param name                 wire name, and the second half of the routing key
 *                             ({@code <tenant_id>.<event>})
 * @param interceptable        whether an interceptor may register for this event
 *                             at all; {@code false} means listen-only
 * @param mutable              whether an interceptor's reply may carry a
 *                             {@code patch}
 * @param mutableFields        the complete allow-list: exact field names, or an
 *                             entry ending in {@code .} denoting a namespace
 *                             prefix (see {@link #patchFieldAllowed(String)})
 * @param defaultFailurePolicy the policy a registration inherits when it names
 *                             none
 * @param description          one line, as the admin UI shows it
 */
public record ReactorEventSpec(
        String name,
        boolean interceptable,
        boolean mutable,
        List<String> mutableFields,
        FailurePolicy defaultFailurePolicy,
        String description) {

    /**
     * Canonicalizes the component list: {@code mutableFields} is copied into an
     * unmodifiable list so a registry entry cannot be edited through a leaked
     * reference.
     */
    public ReactorEventSpec {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(defaultFailurePolicy, "defaultFailurePolicy");
        Objects.requireNonNull(description, "description");
        mutableFields = List.copyOf(Objects.requireNonNull(mutableFields, "mutableFields"));
    }

    /**
     * Whether {@code field} may appear in a {@code patch} for this event.
     *
     * <p><strong>The namespace-prefix rule.</strong> An allow-list entry ending
     * in {@code .} is a namespace prefix, and it matches a field that starts with
     * the entry <em>and has at least one character after the dot</em>. So
     * {@code ext.} admits {@code ext.department} and {@code ext.a.b.c}, and
     * refuses {@code ext.} itself (it names the namespace, not a claim),
     * {@code ext}, {@code extra}, {@code external_id} and
     * {@code evil.ext.department}.
     *
     * <p>Everything else follows from that one rule: {@code token.pre_issue}
     * cannot reach {@code iss}, {@code sub}, {@code aud}, {@code exp},
     * {@code iat}, {@code nbf}, {@code jti}, {@code scope}, {@code scp},
     * {@code azp}, {@code act} or {@code client_id}, because none of them begins
     * with {@code ext.}. A hook that can rewrite {@code sub} is a hook that can
     * mint a token for anyone, and a <em>correctly signed</em> reply setting
     * {@code sub} is refused exactly as a forged one is.
     *
     * <p>This is a read-only predicate. It exists so a reactor author can check a
     * key <em>before</em> writing the handler — it is <strong>never</strong> used
     * to filter a handler's patch down to the allowed subset, which &sect;22.4
     * rule 1 forbids.
     *
     * @param field the patch key to test
     * @return {@code true} when the server would accept {@code field} in a patch
     *         for this event
     */
    public boolean patchFieldAllowed(String field) {
        if (!mutable || field == null) {
            return false;
        }
        for (String allowed : mutableFields) {
            if (allowed.endsWith(".")) {
                // "at least one character after the dot" — `ext.` itself is not
                // a claim name, and admitting it would let a reactor set a claim
                // literally called `ext.`.
                if (field.length() > allowed.length() && field.startsWith(allowed)) {
                    return true;
                }
            } else if (field.equals(allowed)) {
                return true;
            }
        }
        return false;
    }
}
