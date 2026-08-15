package io.axiam.sdk.reactor;

import org.jspecify.annotations.Nullable;

/**
 * What the server does when an interceptor produces no usable reply
 * (CONTRACT.md &sect;22.8).
 *
 * <p>"No usable reply" is one closed set and every member takes the same path:
 * timeout, transport failure, budget exhausted before this reactor was reached,
 * the per-tenant in-flight cap breached, and <em>every</em> &sect;22.4 rejection
 * — including a valid signature carrying a forbidden patch field.
 *
 * <p>This is a property of the <em>registration</em>, enforced by the server. It
 * is mirrored here so an SDK caller can read and render it, and so
 * {@link ReactorEvents#defaultFailurePolicyFor} can compose the per-event
 * defaults the same way the server does.
 */
public enum FailurePolicy {

    /** Proceed as if the reactor had replied {@code allow}. */
    FAIL_OPEN("fail_open"),

    /** Deny the underlying operation, with an audited reason naming the failure. */
    FAIL_CLOSED("fail_closed");

    private final String wire;

    FailurePolicy(String wire) {
        this.wire = wire;
    }

    /**
     * Returns the lowercase wire form the AXIAM API uses.
     *
     * @return {@code "fail_open"} or {@code "fail_closed"}
     */
    public String wire() {
        return wire;
    }

    /**
     * Parses a wire form back into a policy.
     *
     * @param raw the wire string, e.g. {@code "fail_closed"}; may be {@code null}
     * @return the matching policy, or {@code null} when {@code raw} names none
     */
    public static @Nullable FailurePolicy fromWire(@Nullable String raw) {
        if (raw == null) {
            return null;
        }
        String normalized = raw.trim().toLowerCase(java.util.Locale.ROOT);
        for (FailurePolicy policy : values()) {
            if (policy.wire.equals(normalized)) {
                return policy;
            }
        }
        return null;
    }
}
