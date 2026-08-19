package io.axiam.sdk.srp;

/**
 * The two proofs an SRP exchange produces (CONTRACT.md &sect;23.2).
 *
 * <p>{@code clientProof} goes on the verify request. {@code expectedServerProof}
 * stays here and is compared against the response's {@code server_proof}: that
 * comparison is the half of SRP that authenticates the <em>server</em>, and
 * &sect;23.3 rule 6 makes it mandatory.
 *
 * @param clientProof         {@code M1}, lowercase hex
 * @param expectedServerProof the {@code M2} the server must return
 */
public record SrpProofs(String clientProof, String expectedServerProof) {
}
