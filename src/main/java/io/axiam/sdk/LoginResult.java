package io.axiam.sdk;

import org.jspecify.annotations.Nullable;

/**
 * Outcome of {@code login()}/{@code verifyMfa()} (D-03/D-04, CONTRACT.md
 * &sect;1). MFA-required is an expected outcome, represented as a flag —
 * never thrown as an exception: callers MUST check {@link #mfaRequired()}
 * before assuming a session was established.
 *
 * <p><strong>Two components were added in contract 1.28</strong>, and adding a
 * component to a record is a breaking change — see &sect;25.2 rule 1. The
 * server has always been able to answer {@code 403 mfa_setup_required} with a
 * setup token for an account in a tenant that requires MFA; that used to reach
 * callers as an {@code AuthzError}, telling them they lacked permission to log
 * in when what the server said was recoverable and came with the means to
 * recover. The three-argument constructor below keeps existing call sites
 * compiling.
 *
 * @param mfaRequired      {@code true} when the server responded with an MFA
 *                         challenge instead of a completed login
 * @param challengeToken   the opaque, sensitive MFA challenge token to pass to
 *                         {@code verifyMfa()}; populated only when
 *                         {@code mfaRequired} is {@code true}
 * @param user             the authenticated user; populated only on a
 *                         completed (non-MFA-pending) login/verifyMfa
 * @param mfaSetupRequired {@code true} when the tenant requires MFA and this
 *                         account has none (&sect;25.2 rule 1) — an outcome,
 *                         not an error. Pass {@code setupToken} to
 *                         {@code mfaSetupEnroll}, show the user the URI, then
 *                         {@code mfaSetupConfirm}, which completes this login.
 * @param setupToken       authorizes the {@code mfaSetupEnroll}/
 *                         {@code mfaSetupConfirm} pair; populated only when
 *                         {@code mfaSetupRequired} is {@code true}
 * @param organizationLevel {@code true} when the account that just signed in is
 *                         an <strong>organization-level</strong> principal
 *                         (&sect;5.2) — one whose record lives in its
 *                         organization's reserved tenant, so its global grants
 *                         apply in every tenant of that organization, and which
 *                         can act on a different one by sending a different
 *                         {@code X-Tenant-ID} on the next request. An ordinary
 *                         tenant principal is a principal of exactly one tenant
 *                         and gets a {@code 403} for the same header change, so
 *                         check this <em>before</em> offering a tenant switch
 *                         rather than discovering the answer from a failed
 *                         request. {@code false} against a server older than
 *                         contract 1.31, and {@code false} on the two pending
 *                         outcomes, where no principal has been established yet
 */
public record LoginResult(
        boolean mfaRequired,
        @Nullable Sensitive challengeToken,
        @Nullable AxiamUser user,
        boolean mfaSetupRequired,
        @Nullable Sensitive setupToken,
        boolean organizationLevel) {

    /**
     * The pre-1.28 shape: neither setup component set.
     *
     * @param mfaRequired    {@code true} on an MFA challenge
     * @param challengeToken the challenge token, when there is one
     * @param user           the authenticated user, when the login completed
     */
    public LoginResult(boolean mfaRequired, @Nullable Sensitive challengeToken, @Nullable AxiamUser user) {
        this(mfaRequired, challengeToken, user, false, null, false);
    }

    /**
     * The pre-1.31 shape: no &sect;5.2 scope reported.
     *
     * <p>Kept so a call site written against contract 1.28's five-component
     * record still compiles: adding a component to a record is otherwise a
     * source-breaking change for every {@code new LoginResult(...)} in the wild.
     *
     * @param mfaRequired      {@code true} on an MFA challenge
     * @param challengeToken   the challenge token, when there is one
     * @param user             the authenticated user, when the login completed
     * @param mfaSetupRequired {@code true} on the &sect;25.2 rule 1 outcome
     * @param setupToken       the forced-enrolment token, when there is one
     */
    public LoginResult(
            boolean mfaRequired,
            @Nullable Sensitive challengeToken,
            @Nullable AxiamUser user,
            boolean mfaSetupRequired,
            @Nullable Sensitive setupToken) {
        this(mfaRequired, challengeToken, user, mfaSetupRequired, setupToken, false);
    }

    /**
     * A completed login, carrying the &sect;5.2 scope the server reported.
     *
     * @param user              the authenticated user
     * @param organizationLevel whether the principal operates across the
     *                          organization's tenants
     * @return a completed result
     */
    public static LoginResult authenticated(AxiamUser user, boolean organizationLevel) {
        return new LoginResult(false, null, user, false, null, organizationLevel);
    }

    /**
     * The &sect;25.2 rule 1 outcome: the tenant requires MFA and this account
     * has none.
     *
     * @param setupToken the token authorizing the forced-enrolment pair
     * @return a result carrying only the setup branch
     */
    public static LoginResult mfaSetupRequired(Sensitive setupToken) {
        return new LoginResult(false, null, null, true, setupToken, false);
    }
}
