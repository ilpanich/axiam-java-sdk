package io.axiam.sdk;

/**
 * The result of {@link AxiamClient#authenticateDevice()} — CONTRACT.md &sect;6.1
 * rule 6 (contract 1.51).
 *
 * <p>No refresh token exists for this credential (&sect;6.1 rule 6 — a server
 * decision, D-6 of the dogfooding remediation plan): a device re-authenticates by
 * calling {@link AxiamClient#authenticateDevice()} again, which costs one TLS
 * handshake rather than one wire round trip. This SDK adopts {@code accessToken}
 * as the client's credential exactly as it adopts a completed login's, so the
 * caller does not have to thread it through every subsequent call by hand.
 *
 * @param accessToken the certificate-bound access token (CONTRACT.md &sect;10.1
 *                    rule 9 applies to it — see {@code JwksVerifier#verifySenderConstrained})
 * @param tokenType   always {@code "Bearer"} (&sect;1.1.1 rule 5: {@code cnf} alone
 *                    decides boundness, never this field)
 * @param expiresIn   the access token's lifetime in seconds (default 900)
 */
public record DeviceToken(Sensitive accessToken, String tokenType, long expiresIn) {
}
