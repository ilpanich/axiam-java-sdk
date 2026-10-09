package io.axiam.sdk.ssf;

import java.util.Objects;

/**
 * Where an {@link SsfReceiver}'s signing keys come from: the JWKS URL itself,
 * or the transmitter's SSF configuration document, whose {@code issuer} must
 * equal the configured issuer and whose {@code jwks_uri} is used.
 */
public final class SsfKeySource {

    private final String url;
    private final boolean discovery;

    private SsfKeySource(String url, boolean discovery) {
        this.url = Objects.requireNonNull(url, "url");
        this.discovery = discovery;
    }

    /**
     * The JWKS URL itself (AXIAM: {@code {issuer}/oauth2/jwks}).
     *
     * @param jwksUri the JWKS URL
     * @return the source
     */
    public static SsfKeySource jwksUri(String jwksUri) {
        return new SsfKeySource(jwksUri, false);
    }

    /**
     * The transmitter's SSF configuration document
     * ({@code /.well-known/ssf-configuration...}).
     *
     * @param discoveryUrl the configuration document's URL
     * @return the source
     */
    public static SsfKeySource discoveryUrl(String discoveryUrl) {
        return new SsfKeySource(discoveryUrl, true);
    }

    /**
     * The URL this source names.
     *
     * @return the JWKS or configuration URL
     */
    public String url() {
        return url;
    }

    /**
     * Whether {@link #url()} is a configuration document rather than the JWKS.
     *
     * @return {@code true} for {@link #discoveryUrl(String)}
     */
    public boolean isDiscovery() {
        return discovery;
    }

    @Override
    public String toString() {
        return (discovery ? "SsfKeySource.discoveryUrl(" : "SsfKeySource.jwksUri(") + url + ")";
    }
}
