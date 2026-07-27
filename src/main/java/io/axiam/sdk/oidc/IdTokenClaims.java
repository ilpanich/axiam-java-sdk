package io.axiam.sdk.oidc;

import com.nimbusds.jwt.JWTClaimsSet;

import org.jspecify.annotations.Nullable;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The decoded, <strong>already-validated</strong> ID-token claim set carried
 * by {@link OidcTokenSet#idClaims()} (CONTRACT.md &sect;12.1).
 *
 * <p>Named claims keep their JWT/OIDC wire spelling ({@code iss}, {@code sub},
 * {@code aud}, …) rather than Java camelCase: they are protocol identifiers a
 * caller cross-references against OIDC Core (CONTRACT.md &sect;12 T1
 * reference judgment call 3). {@link #claims()} additionally exposes
 * <strong>every</strong> claim the server sent — including the named ones
 * above and any further claim (e.g. {@code email}, {@code preferred_username})
 * — since the ID token's full claim set is not enumerated by
 * {@code openapi.json} (CONTRACT.md &sect;12.1: unknown claims MUST be
 * preserved, never rejected).
 *
 * <p>Deviation from the TypeScript/Python references: {@code aud} is
 * normalized to a {@code List<String>} here (always a list, even for a
 * single audience) rather than a union of a bare string or a list, since Java
 * has no convenient sum type for a public record component.
 *
 * @param iss    issuer — matched for exact string equality against the discovery document's {@code issuer} (CONTRACT.md &sect;12.4 rule 3)
 * @param sub    subject — the authenticated end user's stable identifier at AXIAM
 * @param aud    audience — contains the relying party's {@code client_id} (&sect;12.4 rule 4); always normalized to a list
 * @param exp    expiry time (epoch seconds)
 * @param iat    issued-at time (epoch seconds)
 * @param nbf    not-before time (epoch seconds), when the server sends one
 * @param nonce  the {@code nonce} echoed back from the authorization request (&sect;12.4 rule 6)
 * @param azp    authorized party — required to equal {@code client_id} when {@code aud} holds multiple audiences (&sect;12.4 rule 4)
 * @param claims every claim the server sent, keyed by claim name, including the named ones above
 */
public record IdTokenClaims(
        String iss,
        String sub,
        List<String> aud,
        long exp,
        long iat,
        @Nullable Long nbf,
        @Nullable String nonce,
        @Nullable String azp,
        Map<String, Object> claims) {

    /**
     * Defensively copies {@link #aud()} and {@link #claims()} so this
     * (otherwise fully immutable) record's collections cannot be mutated
     * after construction.
     *
     * @param iss    issuer claim
     * @param sub    subject claim
     * @param aud    audience claim(s)
     * @param exp    expiry time (epoch seconds)
     * @param iat    issued-at time (epoch seconds)
     * @param nbf    not-before time (epoch seconds), or {@code null}
     * @param nonce  the {@code nonce} claim, or {@code null}
     * @param azp    the {@code azp} claim, or {@code null}
     * @param claims every claim the server sent
     */
    public IdTokenClaims {
        aud = List.copyOf(aud);
        claims = Map.copyOf(claims);
    }

    /**
     * Builds an {@link IdTokenClaims} from an already signature-verified
     * nimbus {@link JWTClaimsSet} (see {@link IdTokenValidator}). Package-visible:
     * only the &sect;12.4 validation path constructs this type — a caller never
     * assembles one directly, since it always represents an already-validated
     * token.
     *
     * @param claimsSet the verified JWT payload
     * @return the corresponding {@link IdTokenClaims}
     */
    static IdTokenClaims from(JWTClaimsSet claimsSet) {
        Date expDate = claimsSet.getExpirationTime();
        Date iatDate = claimsSet.getIssueTime();
        Date nbfDate = claimsSet.getNotBeforeTime();
        List<String> aud = claimsSet.getAudience();

        Map<String, Object> raw = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : claimsSet.getClaims().entrySet()) {
            if (entry.getValue() != null) {
                raw.put(entry.getKey(), entry.getValue());
            }
        }

        return new IdTokenClaims(
                claimsSet.getIssuer(),
                claimsSet.getSubject(),
                aud == null ? List.of() : aud,
                expDate != null ? expDate.getTime() / 1000L : 0L,
                iatDate != null ? iatDate.getTime() / 1000L : 0L,
                nbfDate != null ? nbfDate.getTime() / 1000L : null,
                IdTokenValidator.stringClaimOrNull(claimsSet, "nonce"),
                IdTokenValidator.stringClaimOrNull(claimsSet, "azp"),
                raw);
    }
}
