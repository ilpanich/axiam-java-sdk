package io.axiam.sdk.reactor;

import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;

/**
 * The v1 reactor event registry (CONTRACT.md &sect;22.5) — five interceptable
 * events, their mutable-field allow-lists, and their default failure policies.
 *
 * <p>The live copy is served at {@code GET /api/v1/reactors/events} and is the
 * one an admin UI SHOULD read. This constant list is the same data, restated
 * because a wire contract that requires a network call to be understood is not a
 * contract.
 *
 * <p><strong>&sect;22.7 hot-path exclusion.</strong> {@code authz.check},
 * {@code authz.check_batch} and {@code token.introspect} are not hookable and
 * are absent from {@link #REGISTRY} and from every constant below. That absence
 * is asserted by a test, not documented by a comment. This SDK also offers no
 * client-side interceptor, middleware hook or callback presenting itself as the
 * reactor equivalent for those operations. An application that needs external
 * input on an authorization decision writes a <strong>deny grant</strong>, which
 * the engine evaluates in the hot path at hot-path cost.
 */
public final class ReactorEvents {

    /** Before an access token is minted. Mutable: the {@code ext.} claim namespace. */
    public static final String TOKEN_PRE_ISSUE = "token.pre_issue";

    /**
     * After credentials verify, before a session is issued. Veto, or
     * {@code require_mfa} step-up.
     *
     * <p>Covers <em>every</em> interactive sign-in — password authentication,
     * SAML ACS and the OIDC callback. MFA completion and the WebAuthn
     * {@code authenticate/finish} ceremony are not separate firings: both
     * continue a login that was already gated at its first step.
     *
     * <p>The federated paths have no step-up branch, so a {@code require_mfa}
     * answer on a SAML or OIDC sign-in is <strong>refused</strong> (the sign-in
     * fails) rather than silently dropped. A reactor that needs step-up there
     * must answer {@code deny} and drive enrolment out of band.
     */
    public static final String LOGIN_POST_AUTH = "login.post_auth";

    /** Before a user row is written. Mutable: {@code username}, {@code email}, {@code metadata.}. */
    public static final String USER_PRE_CREATE = "user.pre_create";

    /** Before a user row is updated. Mutable: {@code username}, {@code email}, {@code metadata.}. */
    public static final String USER_PRE_UPDATE = "user.pre_update";

    /** Before a role or permission is assigned (four-eyes workflows). Veto only. */
    public static final String GRANT_PRE_ASSIGN = "grant.pre_assign";

    /**
     * Every hookable event in v1, in registry order.
     *
     * <p>Unmodifiable. Note what is <em>not</em> here: see the &sect;22.7 note on
     * this class.
     */
    public static final List<ReactorEventSpec> REGISTRY = List.of(
            new ReactorEventSpec(
                    TOKEN_PRE_ISSUE, true, true, List.of("ext."), FailurePolicy.FAIL_OPEN,
                    "Enrich or veto token issuance. May add claims under `ext.` only."),
            new ReactorEventSpec(
                    LOGIN_POST_AUTH, true, false, List.of(), FailurePolicy.FAIL_CLOSED,
                    "After credentials verify, before session issuance: veto or require step-up MFA."),
            new ReactorEventSpec(
                    USER_PRE_CREATE, true, true, List.of("username", "email", "metadata."),
                    FailurePolicy.FAIL_CLOSED,
                    "Validate or normalize a new user's profile fields."),
            new ReactorEventSpec(
                    USER_PRE_UPDATE, true, true, List.of("username", "email", "metadata."),
                    FailurePolicy.FAIL_CLOSED,
                    "Validate or normalize a profile update."),
            new ReactorEventSpec(
                    GRANT_PRE_ASSIGN, true, false, List.of(), FailurePolicy.FAIL_CLOSED,
                    "Veto a role or permission assignment (four-eyes workflows). Veto-only."));

    private ReactorEvents() {
    }

    /**
     * Looks an event up by wire name.
     *
     * @param name the event name, e.g. {@code token.pre_issue}; may be {@code null}
     * @return the spec, or {@code null} when {@code name} is not in the registry.
     *         An event outside the registry dispatches to nothing and resolves to
     *         {@code allow} server-side, which is what makes &sect;22.7's
     *         hot-path exclusion structural rather than advisory.
     */
    public static @Nullable ReactorEventSpec spec(@Nullable String name) {
        if (name == null) {
            return null;
        }
        for (ReactorEventSpec spec : REGISTRY) {
            if (spec.name().equals(name)) {
                return spec;
            }
        }
        return null;
    }

    /**
     * The {@code failure_policy} a registration should get when it names none:
     * the <strong>strictest</strong> default among the events it subscribes to
     * (CONTRACT.md &sect;22.8).
     *
     * <p>A reactor registered for both {@code token.pre_issue} (open) and
     * {@code login.post_auth} (closed) can veto a login, so it inherits
     * {@code fail_closed} — in either array order. Taking the first event's
     * default would let the order of a JSON array decide whether an unreachable
     * fraud check passes.
     *
     * <p>Unknown names are ignored here rather than defaulted: the server refuses
     * them at registration, and guessing a policy for an event that cannot exist
     * would only hide that refusal.
     *
     * @param events the registration's event names
     * @return {@link FailurePolicy#FAIL_CLOSED} when any named event defaults
     *         closed, {@link FailurePolicy#FAIL_OPEN} only when all of them
     *         default open
     */
    public static FailurePolicy defaultFailurePolicyFor(Collection<String> events) {
        for (String event : events) {
            ReactorEventSpec spec = spec(event);
            if (spec != null && spec.defaultFailurePolicy() == FailurePolicy.FAIL_CLOSED) {
                return FailurePolicy.FAIL_CLOSED;
            }
        }
        return FailurePolicy.FAIL_OPEN;
    }
}
