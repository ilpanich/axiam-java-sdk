package io.axiam.sdk.spring;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import java.util.Objects;

/**
 * A configured {@code WWW-Authenticate: UMA} challenge emitter (CONTRACT.md
 * §20.3, emit half).
 *
 * <p>Hand one to {@link AxiamAuthorizationInterceptor} and a denial stops being
 * a bare 403: the interceptor mints a fresh permission ticket for the pairs the
 * caller lacked and returns it in the header, so a UMA-aware client knows where
 * to go for authority instead of only being told "no".
 *
 * <p><strong>Opt-in, and deliberately so.</strong> Emitting a challenge means
 * minting a credential &mdash; a wire call to the Protection API, and a live
 * ticket, produced on a path the caller did not explicitly request. An
 * interceptor that did that on every denial by default would turn each
 * unauthorized request into a Protection API call, which is a
 * denial-of-service amplifier pointed at your own authorization server. So it
 * happens only where an application has constructed the interceptor with one.
 *
 * <p><strong>Failure is not escalation.</strong> If minting fails &mdash; the
 * PAT expired, the Protection API is down, the resource declares none of the
 * requested scopes &mdash; the denial still surfaces as an ordinary 403 without
 * a challenge. A caller who was going to be refused is refused either way;
 * letting a Protection API outage turn a deny into a 500 would hand the outage
 * a second consequence, and letting it turn into an allow would be a security
 * bug.
 */
public final class UmaChallenger {

    private final String realm;
    private final String asUri;
    private final Sensitive pat;
    private final AxiamClient client;

    /**
     * Builds a challenger.
     *
     * @param realm  the protection realm to name in the header
     * @param asUri  the authorization server to send the caller to &mdash;
     *               normally this deployment's issuer, read from discovery
     *               rather than concatenated by hand
     * @param pat    a Protection API Token: a <em>client-credentials</em> token
     *               carrying the {@code uma_protection} scope (§20.2 rule 1). A
     *               user token cannot stand in &mdash; a minted ticket is bound
     *               to the {@code client_id} that minted it
     * @param client the client whose {@code umaRequestTicket} mints the ticket
     */
    public UmaChallenger(String realm, String asUri, Sensitive pat, AxiamClient client) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.asUri = Objects.requireNonNull(asUri, "asUri");
        this.pat = Objects.requireNonNull(pat, "pat");
        this.client = Objects.requireNonNull(client, "client");
    }

    /** The protection realm named in the header. */
    String realm() {
        return realm;
    }

    /** The authorization server the header nominates. */
    String asUri() {
        return asUri;
    }

    /** The Protection API Token used to mint tickets. */
    Sensitive pat() {
        return pat;
    }

    /** The client used to reach the Protection API. */
    AxiamClient client() {
        return client;
    }

    /**
     * Renders without the PAT (§7): a challenger is configuration an
     * application may reasonably log, and the credential inside it is not.
     *
     * @return a redacted description
     */
    @Override
    public String toString() {
        return "UmaChallenger[realm=" + realm + ", asUri=" + asUri + ", pat=" + pat + "]";
    }
}
