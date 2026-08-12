package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

/**
 * A parsed {@code WWW-Authenticate: UMA} challenge (UMA 2.0 &sect;3.2,
 * CONTRACT.md &sect;20.3).
 *
 * @param realm  the protection realm the resource server named, or {@code null}
 * @param asUri  the authorization server the resource server nominates, or {@code null}. <strong>Not automatically trusted</strong> — see {@link #parse(String)}
 * @param ticket the ticket to exchange — a bearer credential for its 60-second life — or {@code null}
 */
public record UmaChallenge(
        @Nullable String realm,
        @Nullable String asUri,
        @Nullable Sensitive ticket) {

    /**
     * Parses a {@code WWW-Authenticate: UMA …} header value (&sect;20.3).
     *
     * <p><strong>This deliberately does not exchange the ticket.</strong>
     * Parsing a challenge and acting on it are separate decisions: the
     * {@code as_uri} names an authorization server the caller has not
     * necessarily chosen to trust, and auto-exchanging would send the
     * requesting party's {@code claim_token} to whatever host answered the
     * 403. The caller decides.
     *
     * @param header the header value
     * @return the parsed challenge, or {@code null} when the header is not a UMA challenge
     */
    public static @Nullable UmaChallenge parse(String header) {
        String trimmed = header.strip();
        if (!trimmed.startsWith("UMA")) {
            return null;
        }
        String rest = trimmed.substring(3);
        // "UMA" alone is a valid, if useless, challenge; anything else must be
        // separated by whitespace so `UMAX realm="…"` is not read as UMA.
        if (!rest.isEmpty() && !Character.isWhitespace(rest.charAt(0))) {
            return null;
        }

        String realm = null;
        String asUri = null;
        Sensitive ticket = null;
        for (String part : rest.split(",")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = part.substring(0, eq).strip();
            String value = stripQuotes(part.substring(eq + 1).strip());
            switch (key) {
                case "realm" -> realm = value;
                case "as_uri" -> asUri = value;
                case "ticket" -> ticket = Sensitive.of(value);
                default -> {
                    // Unknown parameters are ignored rather than rejected: UMA
                    // 2.0 permits a server to add its own, and refusing the
                    // whole challenge over one would lose the ticket with it.
                }
            }
        }
        return new UmaChallenge(realm, asUri, ticket);
    }

    /**
     * Formats a {@code WWW-Authenticate: UMA} header value (&sect;20.3, emit
     * half).
     *
     * <p>The resource-server side: having obtained a ticket from
     * {@code umaRequestTicket}, tell the caller where to redeem it.
     *
     * @param realm  the protection realm
     * @param asUri  the authorization server
     * @param ticket the permission ticket
     * @return the header value
     */
    public static String header(String realm, String asUri, Sensitive ticket) {
        return "UMA realm=\"" + realm + "\", as_uri=\"" + asUri
                + "\", ticket=\"" + ticket.expose() + "\"";
    }

    private static String stripQuotes(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
