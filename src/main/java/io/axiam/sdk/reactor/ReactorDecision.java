package io.axiam.sdk.reactor;

import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.Objects;

/**
 * What a handler decided about one event (CONTRACT.md &sect;22.4).
 *
 * <p>A <strong>sealed</strong> hierarchy of three answers. Three of &sect;22.4's
 * rules are encoded here structurally rather than by documentation, because each
 * of them is a rule an implementation gets wrong by being permissive:
 *
 * <ol>
 *   <li><strong>{@code allow} and {@code patch} are mutually exclusive.</strong>
 *       There is no way to attach a patch to {@link Allow} — a mutation is a
 *       {@link Mutate}, which serializes {@code decision: "mutate"}. A patch on
 *       an {@code allow} is a reply whose author and whose reader disagree about
 *       what will happen; the server refuses it rather than resolving it.</li>
 *   <li><strong>An empty mutation is malformed.</strong> {@link Mutate} refuses
 *       to be constructed with an empty patch, so it cannot be put on the wire
 *       and rejected as {@code malformed_mutation} at the far end.</li>
 *   <li><strong>{@code require_mfa} rides on {@code allow}.</strong> It is a flag
 *       on {@link Allow}, not a fourth decision, and it is valid on
 *       {@code login.post_auth} only.</li>
 * </ol>
 *
 * <p>What is <em>not</em> encoded here is patch filtering. A patch containing a
 * forbidden key is sent unfiltered and rejected by the server (&sect;22.4 rule 1):
 * dropping the bad key would leave the reactor author believing a field was set
 * when it was silently discarded.
 */
public sealed interface ReactorDecision {

    /**
     * Proceed unchanged.
     *
     * @param requireMfa when {@code true}, proceed only after step-up
     *                   authentication. Valid on {@code login.post_auth}
     *                   <strong>only</strong>; the server rejects it on any other
     *                   event as {@code require_mfa_not_supported}, before it
     *                   even looks at the decision. Serialized only when
     *                   {@code true} — a reply carrying {@code "require_mfa":
     *                   false} produces different canonical bytes and therefore a
     *                   different MAC.
     */
    record Allow(boolean requireMfa) implements ReactorDecision {
    }

    /**
     * Refuse the underlying operation.
     *
     * @param reason audited on the server. A deny with no reason still denies —
     *               the reason is for the audit trail, not for the decision, and
     *               the server substitutes {@code "denied by reactor"} when it is
     *               absent. {@code null} omits the field from the signed bytes.
     */
    record Deny(@Nullable String reason) implements ReactorDecision {
    }

    /**
     * Proceed, applying {@code patch}. Valid on a mutable event only; the server
     * rejects it as {@code not_mutable} on a veto-only one.
     *
     * @param patch a flat, non-empty map of string to string. There is no nested
     *              or typed patch in v1. Sent <strong>unfiltered</strong>: one
     *              forbidden key rejects the whole patch, including the fields
     *              that would have been fine.
     */
    record Mutate(Map<String, String> patch) implements ReactorDecision {

        /**
         * Copies {@code patch} into an unmodifiable map and refuses an empty one
         * — {@code mutate} with no patch is {@code malformed_mutation} on the
         * wire, and a type that cannot represent it is better than a rejection
         * round trip.
         */
        public Mutate {
            patch = Map.copyOf(Objects.requireNonNull(patch, "patch"));
            if (patch.isEmpty()) {
                throw new IllegalArgumentException(
                        "a mutate decision needs a non-empty patch (CONTRACT.md §22.4: "
                                + "an empty patch is rejected as malformed_mutation); "
                                + "return ReactorDecision.allow() to change nothing");
            }
        }
    }

    /**
     * Proceed unchanged.
     *
     * @return an {@link Allow} with no step-up demand
     */
    static ReactorDecision allow() {
        return new Allow(false);
    }

    /**
     * Proceed, but only after step-up authentication ({@code login.post_auth}
     * only).
     *
     * <p>Step-up is <strong>sticky</strong> across the chain: once any reactor
     * demands it, no later reactor can clear it.
     *
     * @return an {@link Allow} carrying {@code require_mfa: true}
     */
    static ReactorDecision allowRequiringStepUp() {
        return new Allow(true);
    }

    /**
     * Refuse, with an audited reason.
     *
     * @param reason why, for the audit trail; may be {@code null}
     * @return a {@link Deny}
     */
    static ReactorDecision deny(@Nullable String reason) {
        return new Deny(reason);
    }

    /**
     * Proceed with a mutation.
     *
     * @param patch a non-empty flat map of field name to string value
     * @return a {@link Mutate}
     * @throws IllegalArgumentException when {@code patch} is empty
     */
    static ReactorDecision mutate(Map<String, String> patch) {
        return new Mutate(patch);
    }
}
