package io.axiam.sdk.internal;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.axiam.sdk.errors.AuthError;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.
 *
 * <p>The resource-server half of DPoP: given the {@code DPoP} header a caller presented,
 * decide whether it proves possession for <b>this</b> request and <b>this</b> access token,
 * and return the key thumbprint that {@link JwksVerifier#verifyTokenBinding} then matches
 * against the token's {@code cnf.jkt}.
 *
 * <h2>Why this lives in the SDK</h2>
 *
 * <p>§21.7.2 is a ten-check list, and the contract is blunt about partial implementations:
 * <i>"Partial verification is worse than none, because it produces a guard that reports
 * success."</i> Nine of the ten look optional until someone builds an attack out of the one
 * that was skipped, so they belong in one audited place rather than in every application
 * guarding an endpoint.
 *
 * <p>The two most often missing, and what they cost:
 *
 * <ul>
 *   <li><b>{@code typ}</b> — without pinning it to {@code dpop+jwt}, any <i>other</i> JWT
 *       signed by the same key (an access token, an ID token) is replayable as a proof.
 *   <li><b>{@code ath}</b> — without it, a proof captured on one request can be re-aimed at
 *       a different token held by the same key. {@code ath} binds the proof to the token
 *       rather than merely to the key.
 * </ul>
 *
 * <h2>The algorithm comes from the key, never from the header</h2>
 *
 * <p>{@code alg: none} and RSA-public-key-as-HMAC-secret are the same bug wearing different
 * clothes: <i>the token told the verifier how to check the token</i>. This class picks the
 * verifier from the embedded key's own type, so an HMAC verifier is never a candidate no
 * matter what the header says.
 */
public final class DpopVerifier {

    /**
     * §21.7.2 check 7 — the {@code iat} acceptance window, applied in <b>both</b>
     * directions. RFC 9449 recommends a small window without fixing a number; 60 seconds is
     * the contract's RECOMMENDED value. A named constant, because a bare {@code 60} three
     * call frames deep is a number nobody ever revisits.
     */
    public static final Duration IAT_LEEWAY = Duration.ofSeconds(60);

    /**
     * RFC 9449 §4.3 — private key material that must never appear in a proof's embedded
     * public {@code jwk}. {@code k} is the symmetric-key member: its presence means the
     * "public key" is a shared secret.
     */
    private static final List<String> PRIVATE_JWK_MEMBERS =
            List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");

    private DpopVerifier() {}

    /**
     * §21.7.2 check 8 — single-use {@code jti} tracking.
     *
     * <p>One method, and its contract is the point: {@link #claim} must be atomic. A
     * contains-then-add pair read as two calls is a race that two concurrent replays of the
     * same proof can both win.
     */
    public interface JtiStore {
        /**
         * Record {@code jti} as used until {@code expiresAt}.
         *
         * @return {@code true} if this is the first sighting, {@code false} if it is a replay
         */
        boolean claim(String jti, Instant expiresAt);
    }

    /**
     * A {@link JtiStore} for a single JVM.
     *
     * <p><b>Per-process, therefore per-instance.</b> Four replicas behind a load balancer
     * give an attacker four chances to replay a proof inside its freshness window, and a
     * restart clears the window entirely. Any deployment running more than one process
     * needs a shared store (Redis, a database table).
     */
    public static final class InMemoryJtiStore implements JtiStore {
        private final Map<String, Instant> seen = new ConcurrentHashMap<>();

        @Override
        public boolean claim(String jti, Instant expiresAt) {
            Instant now = Instant.now();
            // Prune inline. Entries only ever live for the freshness window, so this stays
            // small without a background sweeper.
            if (seen.size() > 128) {
                seen.entrySet().removeIf(e -> !e.getValue().isAfter(now));
            }
            // putIfAbsent is the atomic half that matters: two concurrent replays cannot
            // both observe "absent" and both insert.
            Instant existing = seen.putIfAbsent(jti, expiresAt);
            if (existing == null) {
                return true;
            }
            if (existing.isAfter(now)) {
                return false;
            }
            // The recorded entry has expired; take it over.
            return seen.replace(jti, existing, expiresAt);
        }
    }

    /** What {@link #verifyProof} needs about the current request. */
    public record DpopRequest(
            String httpMethod,
            String httpUri,
            String accessToken,
            @Nullable String expectedJkt,
            Duration leeway,
            @Nullable Instant now) {

        /** A request with the contract's default leeway and the real clock. */
        public static DpopRequest of(String httpMethod, String httpUri, String accessToken) {
            return new DpopRequest(httpMethod, httpUri, accessToken, null, IAT_LEEWAY, null);
        }

        /** The same request, with the token's {@code cnf.jkt} so check 10 runs here. */
        public DpopRequest withExpectedJkt(String jkt) {
            return new DpopRequest(httpMethod, httpUri, accessToken, jkt, leeway, now);
        }
    }

    /**
     * Verify a DPoP proof against this request — all ten §21.7.2 checks.
     *
     * <p>Returns the proof key's RFC 7638 thumbprint ({@code jkt}) on success. Feed it to
     * {@link JwksVerifier#verifyTokenBinding} as the DPoP half of {@code PresentedProofs};
     * returning it rather than {@code void} is deliberate, so the value a guard passes
     * onward could only have come from a proof that actually verified.
     *
     * <p>There is no "just check the signature" mode, because that is exactly the partial
     * verification the contract calls worse than none.
     *
     * @param proof the raw {@code DPoP} header value
     * @param request the method, URI and access token this proof must match
     * @param jtiStore the replay guard; required, see {@link InMemoryJtiStore}
     * @return the proof key's {@code jkt}
     * @throws AuthError on any failing check
     */
    public static String verifyProof(String proof, DpopRequest request, JtiStore jtiStore) {
        if (proof == null || proof.isEmpty()) {
            throw new AuthError("DPoP proof is missing or empty");
        }
        // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking the
        // first, which is how a verifier and a downstream parser end up reading different
        // proofs.
        if (proof.indexOf(',') >= 0 || proof.trim().chars().anyMatch(Character::isWhitespace)) {
            throw new AuthError("DPoP header must carry exactly one proof");
        }

        JWSObject jws;
        try {
            jws = JWSObject.parse(proof);
        } catch (Exception e) {
            throw new AuthError("DPoP proof is not a compact JWS: " + e.getMessage());
        }
        JWSHeader header = jws.getHeader();

        // Check 1 — typ. First, because it is what stops any other JWT signed by the same
        // key from standing in as a proof.
        String typ = header.getType() == null ? "" : header.getType().toString();
        if (!typ.equalsIgnoreCase("dpop+jwt")) {
            throw new AuthError("DPoP proof typ header must be 'dpop+jwt', got '" + typ + "'");
        }

        // Check 3 (first half) — the header carries a public jwk.
        JWK jwk = header.getJWK();
        if (jwk == null) {
            throw new AuthError("DPoP proof header must carry a public 'jwk'");
        }

        // Check 4 — no private material, tested against the RAW header JSON.
        //
        // Nimbus would already refuse a private JWK here via isPrivate(), but this check
        // runs against the raw JSON on purpose: §21.7.2 check 4 requires it, because many
        // JWK libraries quietly drop d/p/q when parsing into a public-key type — the check
        // would then pass by virtue of the library having hidden the evidence.
        Map<String, Object> rawJwk = rawHeaderJwk(proof);
        for (String member : PRIVATE_JWK_MEMBERS) {
            if (rawJwk.containsKey(member)) {
                throw new AuthError(
                        "DPoP proof jwk carries private key material ("
                                + member
                                + ") — RFC 9449 §4.3");
            }
        }

        // Checks 2 and 3 (second half) — the verifier is chosen by the KEY's own type, and
        // the signature must verify under it.
        JWSVerifier verifier = verifierFor(jwk);
        try {
            if (!jws.verify(verifier)) {
                throw new AuthError("DPoP proof signature is invalid");
            }
        } catch (AuthError e) {
            throw e;
        } catch (Exception e) {
            throw new AuthError("DPoP proof signature could not be checked: " + e.getMessage());
        }

        Map<String, Object> claims;
        try {
            claims = JSONObjectUtils.parse(jws.getPayload().toString());
        } catch (Exception e) {
            throw new AuthError("DPoP proof payload is not a JSON object");
        }

        // Check 5 — htm.
        Object htm = claims.get("htm");
        if (!(htm instanceof String htmStr) || !htmStr.equals(request.httpMethod())) {
            throw new AuthError(
                    "DPoP proof htm " + htm + " does not match request method "
                            + request.httpMethod());
        }

        // Check 6 — htu, with query and fragment stripped from BOTH sides and nothing else
        // touched.
        Object htu = claims.get("htu");
        String expectedHtu = canonicalHtu(request.httpUri());
        if (!(htu instanceof String htuStr) || !canonicalHtu(htuStr).equals(expectedHtu)) {
            throw new AuthError(
                    "DPoP proof htu " + htu + " does not match request URI " + expectedHtu);
        }

        // Check 7 — iat freshness, in both directions. A proof from the future is as
        // suspect as a stale one: it is how a one-sided skew allowance becomes a long-lived
        // proof.
        Object iatRaw = claims.get("iat");
        if (!(iatRaw instanceof Number iatNum)) {
            throw new AuthError("DPoP proof iat must be a number");
        }
        Instant iat = Instant.ofEpochSecond(iatNum.longValue());
        Instant now = request.now() == null ? Instant.now() : request.now();
        Duration leeway = request.leeway() == null ? IAT_LEEWAY : request.leeway();
        if (Duration.between(iat, now).abs().compareTo(leeway) > 0) {
            throw new AuthError(
                    "DPoP proof iat is outside the " + leeway.toSeconds() + "s freshness window");
        }

        // Check 9 — ath ties the proof to this specific access token.
        Object ath = claims.get("ath");
        if (!(ath instanceof String athStr) || athStr.isEmpty()) {
            throw new AuthError("DPoP proof is missing the ath claim");
        }
        if (!MessageDigest.isEqual(
                athStr.getBytes(StandardCharsets.UTF_8),
                accessTokenHash(request.accessToken()).getBytes(StandardCharsets.UTF_8))) {
            throw new AuthError("DPoP proof ath does not match the presented access token");
        }

        // Check 10 — the thumbprint that ties the proof to the token's cnf.
        String jkt = thumbprintS256(jwk);
        if (request.expectedJkt() != null
                && !MessageDigest.isEqual(
                        jkt.getBytes(StandardCharsets.UTF_8),
                        request.expectedJkt().getBytes(StandardCharsets.UTF_8))) {
            throw new AuthError("DPoP proof key does not match the token's cnf.jkt");
        }

        // Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation, and
        // doing it before the cheap checks would let an attacker burn arbitrary jti values
        // out of the store with proofs that were never going to verify.
        Object jti = claims.get("jti");
        if (!(jti instanceof String jtiStr) || jtiStr.isEmpty()) {
            throw new AuthError("DPoP proof is missing a non-empty jti");
        }
        if (!jtiStore.claim(jtiStr, iat.plus(leeway))) {
            throw new AuthError("DPoP proof jti has already been used (replay)");
        }

        return jkt;
    }

    /**
     * §21.7.2 check 2 — pick the verifier from the key itself.
     *
     * <p>This method is why the proof header's {@code alg} never selects anything: the
     * key's own type determines how a signature over it can be checked, and that is not a
     * matter the presenter gets an opinion on. An HMAC verifier is not reachable from here
     * at all, which is what defeats the public-key-as-shared-secret forgery.
     */
    private static JWSVerifier verifierFor(JWK jwk) {
        try {
            if (jwk instanceof RSAKey rsa) {
                return new RSASSAVerifier(rsa.toRSAPublicKey());
            }
            if (jwk instanceof ECKey ec && Curve.P_256.equals(ec.getCurve())) {
                return new ECDSAVerifier(ec.toECPublicKey());
            }
            if (jwk instanceof OctetKeyPair okp && Curve.Ed25519.equals(okp.getCurve())) {
                return new Ed25519Verifier(okp.toPublicJWK());
            }
        } catch (Exception e) {
            throw new AuthError("DPoP proof jwk is not a usable public key: " + e.getMessage());
        }
        throw new AuthError(
                "DPoP proof key type is not permitted by CONTRACT.md §21.7.2 "
                        + "(permitted: ES256, EdDSA, PS256)");
    }

    /** The proof's {@code jwk} header member as raw JSON, for check 4. */
    private static Map<String, Object> rawHeaderJwk(String proof) {
        String[] segments = proof.split("\\.");
        if (segments.length != 3) {
            throw new AuthError("DPoP proof is not a compact JWS with three segments");
        }
        try {
            Map<String, Object> header =
                    JSONObjectUtils.parse(
                            new String(
                                    Base64.getUrlDecoder().decode(segments[0]),
                                    StandardCharsets.UTF_8));
            Object jwk = header.get("jwk");
            return jwk instanceof Map<?, ?> m ? castMap(m) : new LinkedHashMap<>();
        } catch (Exception e) {
            throw new AuthError("DPoP proof header is not valid base64url JSON");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> m) {
        return (Map<String, Object>) m;
    }

    /**
     * RFC 7638 SHA-256 thumbprint of a JWK — the {@code jkt}.
     *
     * <p>Only the members RFC 7638 names for the key type take part. Members outside that
     * set ({@code kid}, {@code use}, {@code alg}, {@code x5c}) are excluded by the spec,
     * which is what makes the thumbprint stable across two encodings of the same key.
     *
     * @param jwk the public key to fingerprint
     * @return the 43-character base64url thumbprint
     */
    public static String thumbprintS256(JWK jwk) {
        try {
            return jwk.computeThumbprint().toString();
        } catch (Exception e) {
            throw new AuthError("DPoP proof jwk cannot be fingerprinted: " + e.getMessage());
        }
    }

    /**
     * The {@code ath} claim value for {@code accessToken} — RFC 9449 §4.2.
     *
     * <p>base64url-unpadded SHA-256 over the token's ASCII bytes, i.e. over the compact JWT
     * string exactly as it travelled in the {@code Authorization} header, not over anything
     * decoded out of it.
     *
     * @param accessToken the token as it arrived
     * @return the 43-character base64url hash
     */
    public static String accessTokenHash(String accessToken) {
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256")
                            .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new AuthError("SHA-256 unavailable: " + e.getMessage());
        }
    }

    /**
     * The {@code htu} comparison form — §21.7.2 check 6.
     *
     * <p>Query and fragment removed, and <b>nothing else</b>. No case folding, no
     * default-port elision, no percent-decoding, no trailing-slash fixing: a normalising
     * comparison is precisely where two unequal URIs become equal, and an attacker who
     * finds such a pair can aim a proof at an endpoint it was never minted for.
     *
     * @param uri the URI to reduce
     * @return the same URI without its query string or fragment
     */
    public static String canonicalHtu(String uri) {
        int hash = uri.indexOf('#');
        String withoutFragment = hash < 0 ? uri : uri.substring(0, hash);
        int query = withoutFragment.indexOf('?');
        return query < 0 ? withoutFragment : withoutFragment.substring(0, query);
    }
}
