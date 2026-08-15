package io.axiam.sdk.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jwt.JWTClaimsSet;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.internal.JwksVerifier.PresentedProofs;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16). */
class TokenBindingTest {

    private static final String THUMB = "bwcK0esC3yEWCTuAFrDPBqZ_hvIn0UbmJKlSjMbGZKM";
    private static final String JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private static final String OTHER_JKT = "sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static JWTClaimsSet withCnf(Map<String, Object> cnf) {
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().subject("u");
        if (cnf != null) {
            b.claim("cnf", cnf);
        }
        return b.build();
    }

    private static Map<String, Object> cnf(String cert, String jkt) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (cert != null) {
            m.put("x5t#S256", cert);
        }
        if (jkt != null) {
            m.put("jkt", jkt);
        }
        return m;
    }

    /**
     * THE POSITIVE REGRESSION TEST, and the one this change is most likely to break: an
     * unbound token must still pass with no certificate and no proof. The likeliest wrong
     * implementation of rule 9 is one that starts demanding evidence from every caller.
     */
    @Test
    @DisplayName("an unbound token is accepted with no proofs at all")
    void unboundTokenNeedsNothing() {
        assertDoesNotThrow(
                () -> JwksVerifier.verifyTokenBinding(withCnf(null), PresentedProofs.none()));
        // ...and proofs it never asked for do not make it invalid.
        assertDoesNotThrow(
                () ->
                        JwksVerifier.verifyTokenBinding(
                                withCnf(null), new PresentedProofs(THUMB, JKT)));
    }

    @Test
    @DisplayName("a DPoP-bound token accepts the matching key")
    void dpopBoundAcceptsMatchingKey() {
        assertDoesNotThrow(
                () ->
                        JwksVerifier.verifyTokenBinding(
                                withCnf(cnf(null, JKT)), PresentedProofs.dpop(JKT)));
    }

    @Test
    @DisplayName("a DPoP-bound token is rejected without a proof or with the wrong key")
    void dpopBoundRejectsMissingOrWrong() {
        AuthError missing =
                assertThrows(
                        AuthError.class,
                        () ->
                                JwksVerifier.verifyTokenBinding(
                                        withCnf(cnf(null, JKT)), PresentedProofs.none()));
        assertTrue(missing.getMessage().contains("no verified DPoP proof"), missing.getMessage());

        AuthError wrong =
                assertThrows(
                        AuthError.class,
                        () ->
                                JwksVerifier.verifyTokenBinding(
                                        withCnf(cnf(null, JKT)), PresentedProofs.dpop(OTHER_JKT)));
        assertTrue(wrong.getMessage().contains("different DPoP key"), wrong.getMessage());
    }

    @Test
    @DisplayName("a certificate-bound token still behaves exactly as before")
    void certificateBoundUnchanged() {
        assertDoesNotThrow(
                () ->
                        JwksVerifier.verifyTokenBinding(
                                withCnf(cnf(THUMB, null)), PresentedProofs.certificate(THUMB)));
        assertThrows(
                AuthError.class,
                () ->
                        JwksVerifier.verifyTokenBinding(
                                withCnf(cnf(THUMB, null)), PresentedProofs.none()));
        assertThrows(
                AuthError.class,
                () ->
                        JwksVerifier.verifyTokenBinding(
                                withCnf(cnf(THUMB, null)), PresentedProofs.certificate(OTHER_JKT)));
    }

    /**
     * BOTH NAMED IS A CONJUNCTION. An operator who turned on two constraints asked for two;
     * satisfying the more convenient one is not compliance. Each half is asserted to fail
     * alone, because "check whichever we can" is the likeliest wrong implementation.
     */
    @Test
    @DisplayName("a cnf naming both methods requires both")
    void bothNamedIsAConjunction() {
        JWTClaimsSet both = withCnf(cnf(THUMB, JKT));

        assertDoesNotThrow(
                () -> JwksVerifier.verifyTokenBinding(both, new PresentedProofs(THUMB, JKT)));

        assertThrows(
                AuthError.class,
                () -> JwksVerifier.verifyTokenBinding(both, PresentedProofs.certificate(THUMB)));
        assertThrows(
                AuthError.class,
                () -> JwksVerifier.verifyTokenBinding(both, PresentedProofs.dpop(JKT)));
    }

    /**
     * An empty cnf names nothing checkable and is refused, not read as unbound. Over gRPC
     * this is also how proto3 delivers an empty CnfClaim message, which is why §10.3 rule 3
     * spells it out separately.
     */
    @Test
    @DisplayName("an empty cnf is refused rather than read as unbound")
    void emptyCnfIsRefused() {
        AuthError e =
                assertThrows(
                        AuthError.class,
                        () ->
                                JwksVerifier.verifyTokenBinding(
                                        withCnf(cnf(null, null)), PresentedProofs.none()));
        assertTrue(e.getMessage().contains("no method this SDK can verify"), e.getMessage());
    }

    @Test
    @DisplayName("a malformed cnf is refused")
    void malformedCnfIsRefused() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("u").claim("cnf", "a string").build();
        assertThrows(
                AuthError.class,
                () -> JwksVerifier.verifyTokenBinding(claims, PresentedProofs.none()));
    }

    /**
     * The narrow entry point refuses a DPoP-bound token rather than ignoring the jkt it
     * cannot check. That refusal is what lets it stay in the API without becoming a
     * downgrade path.
     */
    @Test
    @DisplayName("the certificate-only entry point refuses DPoP-bound and both-bound tokens")
    void certificateOnlyEntryPointRefusesDpop() {
        for (String presented : new String[] {null, THUMB}) {
            AuthError e =
                    assertThrows(
                            AuthError.class,
                            () ->
                                    JwksVerifier.verifyCertificateBinding(
                                            withCnf(cnf(null, JKT)), presented));
            assertTrue(e.getMessage().contains("cannot verify"), e.getMessage());
        }

        AuthError both =
                assertThrows(
                        AuthError.class,
                        () -> JwksVerifier.verifyCertificateBinding(withCnf(cnf(THUMB, JKT)), THUMB));
        assertTrue(both.getMessage().contains("both must hold"), both.getMessage());
    }
}
