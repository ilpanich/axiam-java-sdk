package io.axiam.sdk.examples.umaclient;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.oidc.RequestingPartyToken;
import io.axiam.sdk.oidc.UmaChallenge;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * UMA 2.0 (CONTRACT.md &sect;20) &mdash; the <strong>client</strong> half of
 * the pair.
 *
 * <p>Run {@code examples/uma-resource-server/UmaResourceServerExample.java}
 * first; this program talks to it.
 *
 * <p>The flow, which is the whole reason UMA exists:
 *
 * <ol>
 *   <li>Ask for the invoice with the user's ordinary token. The resource server
 *       refuses &mdash; but its 403 carries {@code WWW-Authenticate: UMA}
 *       naming a ticket and an authorization server.</li>
 *   <li><strong>Parse</strong> the challenge. Note what happens next, and what
 *       does not: parsing performs no exchange (&sect;20.3). The {@code as_uri}
 *       in that header is a host the <em>server we just failed against</em>
 *       chose; auto-redeeming would send the user's token wherever a 403
 *       pointed.</li>
 *   <li>Decide to trust it, then <strong>exchange</strong> the ticket for an
 *       RPT.</li>
 *   <li>Retry with the RPT.</li>
 * </ol>
 *
 * <p>Step 3 is a decision, not a formality &mdash; this example makes it
 * explicitly, by comparing the nominated {@code as_uri} against the issuer this
 * client already trusts, and refusing when they differ.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_INVOICE_ID=... java UmaClientExample.java}
 */
public final class UmaClientExample {

    private UmaClientExample() {
    }

    /**
     * Runs the four steps against a live resource server.
     *
     * @param args ignored; configuration comes from the environment
     * @throws Exception if the HTTP calls to the resource server fail
     */
    public static void main(String[] args) throws Exception {
        String resourceServer = getenv("AXIAM_RESOURCE_SERVER", "http://127.0.0.1:8081");
        // The resource server printed this id when it registered.
        String invoiceId = getenv("AXIAM_INVOICE_ID", "00000000-0000-0000-0000-000000000000");
        // The requesting party's own token — what this program would normally
        // send and, in step 3, the `claim_token` that names *who* is asking.
        String userToken = getenv("AXIAM_USER_TOKEN", "the-requesting-partys-access-token");

        HttpClient http = HttpClient.newHttpClient();
        URI url = URI.create(resourceServer + "/invoices/" + invoiceId);

        // The exchange is a token-endpoint grant, so this client is confidential.
        try (AxiamClient client = AxiamClient.builder(
                        getenv("AXIAM_BASE_URL", "https://localhost:8443"),
                        getenv("AXIAM_TENANT_SLUG", "acme"))
                .oidcClientId(getenv("AXIAM_OIDC_CLIENT_ID", "invoices-client"))
                .oidcClientSecret(getenv("AXIAM_OIDC_CLIENT_SECRET", "client-secret"))
                .build()) {

            // ---- 1. The refusal ----
            HttpResponse<String> refused = http.send(
                    HttpRequest.newBuilder(url).header("Authorization", "Bearer " + userToken).build(),
                    HttpResponse.BodyHandlers.ofString());
            System.out.println("first attempt: " + refused.statusCode());

            String header = refused.headers().firstValue("WWW-Authenticate").orElse(null);
            if (header == null) {
                // A resource server that refuses without a challenge is telling
                // you it has nothing to offer — there is no ticket to redeem,
                // and retrying the same request would be pointless.
                System.out.println("no WWW-Authenticate header: this refusal is not actionable.");
                return;
            }

            // ---- 2. Parse, and only parse ----
            UmaChallenge challenge = UmaChallenge.parse(header);
            if (challenge == null || challenge.ticket() == null) {
                System.out.println("the challenge names no ticket; nothing to redeem.");
                return;
            }

            // Nothing from the challenge is echoed, and there are two separate
            // reasons for that.
            //
            // The ticket, because §20.6 says so: its 60-second life does not
            // make it harmless — for those 60 seconds it IS the credential that
            // converts into an RPT, so a header in a log line is a live
            // credential in a log line.
            //
            // The realm and as_uri, because they are strings a *remote* server
            // chose. They are not secrets, but echoing attacker-controlled text
            // into a terminal or a log file is its own small hazard (escape
            // sequences, log forging), and an example is the last place to teach
            // the habit. What matters here is the shape of the challenge, not
            // its contents.
            System.out.println("challenge parsed: as_uri present=" + (challenge.asUri() != null)
                    + ", ticket present=true");

            // ---- 3. The trust decision ----
            //
            // This is the step §20.3 exists to keep in the caller's hands. The
            // SDK parsed the header and stopped; deciding whether to send the
            // user's token to the host it names is this program's call, and it
            // is a real one — a compromised or merely misconfigured resource
            // server could nominate anything here.
            String trusted = client.oidcDiscover().issuer();
            String nominated = challenge.asUri();
            if (nominated != null && !trimSlash(nominated).equals(trimSlash(trusted))) {
                // Neither side of the comparison is echoed. The nominated value
                // for the reasons above; our own issuer because it is reached
                // through a client constructed with a client secret, and an
                // example that prints values derived from that object is
                // teaching a habit that is fine here and wrong three refactors
                // later. The decision and its outcome are what a reader needs;
                // the values are two lines away in a debugger.
                System.out.println("refusing to redeem: the challenge nominates an authorization");
                System.out.println("server that is not the issuer this client already trusts.");
                System.out.println("this is the auto-exchange §20.3 forbids, and why it forbids it.");
                return;
            }
            System.out.println("as_uri matches the issuer we already trust; redeeming.");

            // ---- 4. Exchange, then retry ----
            //
            // One request. A ticket is spent whether or not this succeeds
            // (§20.2 rule 6), so on failure the next step is a *new* ticket —
            // which means going back to step 1, not resending this one.
            RequestingPartyToken rpt;
            try {
                rpt = client.umaExchangeTicket(challenge.ticket(), Sensitive.of(userToken), null, null);
            } catch (RuntimeException error) {
                System.out.println("exchange failed: " + error.getClass().getSimpleName());
                System.out.println("the ticket is spent either way — request a new one by retrying.");
                return;
            }
            System.out.println("got an RPT, valid for " + rpt.expiresIn() + "s");

            HttpResponse<String> allowed = http.send(
                    HttpRequest.newBuilder(url)
                            .header("Authorization", "Bearer " + rpt.accessToken().expose())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            System.out.println("second attempt: " + allowed.statusCode());
        }
    }

    private static String trimSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String getenv(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
