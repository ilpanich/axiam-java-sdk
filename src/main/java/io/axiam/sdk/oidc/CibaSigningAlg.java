package io.axiam.sdk.oidc;

import com.nimbusds.jose.JWSAlgorithm;

/**
 * The algorithms a signed CIBA authentication request may use (CONTRACT.md
 * &sect;33.2): the one the client registered as
 * {@code backchannel_authentication_request_signing_alg}.
 */
public enum CibaSigningAlg {
    /** RSASSA-PSS with SHA-256. */
    PS256(JWSAlgorithm.PS256),
    /** ECDSA on P-256 with SHA-256. */
    ES256(JWSAlgorithm.ES256),
    /** Ed25519. */
    EDDSA(JWSAlgorithm.EdDSA);

    private final JWSAlgorithm jose;

    CibaSigningAlg(JWSAlgorithm jose) {
        this.jose = jose;
    }

    /** {@return the JOSE algorithm} */
    public JWSAlgorithm jose() {
        return jose;
    }
}
