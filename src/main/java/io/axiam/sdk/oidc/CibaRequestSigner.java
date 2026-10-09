package io.axiam.sdk.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.internal.LocalRefusal;

import org.jspecify.annotations.Nullable;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

/**
 * The key and algorithm for the signed CIBA request form (CONTRACT.md &sect;33.2,
 * CIBA Core &sect;7.1.1). <strong>Both are the caller's</strong>: there is no
 * default for either, and the SDK signs under exactly the algorithm given
 * &mdash; the one the client registered as
 * {@code backchannel_authentication_request_signing_alg}.
 *
 * <p>A key that cannot sign under the algorithm is refused at construction
 * (the signer signs a probe), with the SDK's local {@code ValidationError} and
 * before any request.
 *
 * <p>The key material is held only inside the signer; {@link #toString()}
 * shows the algorithm and {@code kid}, never the key, and there is no accessor
 * for it (&sect;33.5).
 */
public final class CibaRequestSigner {

    /** The lifetime of a request this SDK signs: five minutes, inside the server's sixty-minute bound. */
    public static final long SIGNED_REQUEST_LIFETIME_SECONDS = 300;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CibaSigningAlg alg;
    private final JWSSigner signer;
    private final @Nullable String kid;

    private CibaRequestSigner(CibaSigningAlg alg, JWSSigner signer, @Nullable String kid) {
        this.alg = alg;
        this.signer = signer;
        this.kid = kid;
    }

    private static RuntimeException refuse() {
        return LocalRefusal.of("ciba_initiate", "signing_key",
                "the key is not a private key that signs under the given algorithm (CONTRACT.md §33.2)");
    }

    /**
     * A signer from a PKCS#8 PEM private key ({@code -----BEGIN PRIVATE KEY-----}):
     * Ed25519 for {@link CibaSigningAlg#EDDSA}, EC P-256 for
     * {@link CibaSigningAlg#ES256}, RSA (2048 bits or more) for
     * {@link CibaSigningAlg#PS256}.
     *
     * @param alg the algorithm the client registered
     * @param pem the PKCS#8 PEM private key
     * @param kid the key's {@code kid} in the client's registered JWK Set, or {@code null}
     * @return the signer
     * @throws io.axiam.sdk.errors.ValidationError when the PEM is not a key that signs under {@code alg}
     */
    public static CibaRequestSigner fromPem(CibaSigningAlg alg, Sensitive pem, @Nullable String kid) {
        Objects.requireNonNull(alg, "alg");
        Objects.requireNonNull(pem, "pem");
        String body = pem.expose()
                .replaceAll("-----BEGIN [A-Z ]*-----", "")
                .replaceAll("-----END [A-Z ]*-----", "")
                .replaceAll("\\s", "");
        if (body.isEmpty()) {
            throw refuse();
        }
        PrivateKey key;
        try {
            String family = switch (alg) {
                case EDDSA -> "Ed25519";
                case ES256 -> "EC";
                case PS256 -> "RSA";
            };
            key = KeyFactory.getInstance(family)
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw refuse();
        }
        return of(alg, key, kid);
    }

    /**
     * A signer from a JCA private key: an {@link EdECPrivateKey} (Ed25519) for
     * {@link CibaSigningAlg#EDDSA}, an {@link ECPrivateKey} on P-256 for
     * {@link CibaSigningAlg#ES256}, an {@link RSAPrivateKey} for
     * {@link CibaSigningAlg#PS256}.
     *
     * @param alg the algorithm the client registered
     * @param key the private key
     * @param kid the key's {@code kid}, or {@code null}
     * @return the signer
     * @throws io.axiam.sdk.errors.ValidationError when the key does not sign under {@code alg}
     */
    public static CibaRequestSigner of(CibaSigningAlg alg, PrivateKey key, @Nullable String kid) {
        Objects.requireNonNull(alg, "alg");
        Objects.requireNonNull(key, "key");
        JWSSigner signer;
        try {
            signer = switch (alg) {
                case EDDSA -> ed25519(key);
                case ES256 -> {
                    if (!(key instanceof ECPrivateKey ec)) {
                        throw refuse();
                    }
                    yield new ECDSASigner(ec);
                }
                case PS256 -> {
                    if (!(key instanceof RSAPrivateKey)) {
                        throw refuse();
                    }
                    yield new RSASSASigner(key);
                }
            };
            // A key that parses is not yet a key for this algorithm: prove it signs.
            JWSObject probe = new JWSObject(new JWSHeader(alg.jose()), new Payload("axiam-ciba-probe"));
            probe.sign(signer);
        } catch (JOSEException | RuntimeException e) {
            if (e instanceof io.axiam.sdk.errors.ValidationError refusal) {
                throw refusal;
            }
            throw refuse();
        }
        return new CibaRequestSigner(alg, signer, kid);
    }

    private static JWSSigner ed25519(PrivateKey key) throws JOSEException {
        if (!(key instanceof EdECPrivateKey ed) || !"Ed25519".equalsIgnoreCase(ed.getParams().getName())) {
            throw refuse();
        }
        byte[] seed = ed.getBytes().orElseThrow(CibaRequestSigner::refuse);
        byte[] publicKey;
        try {
            publicKey = com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPairFromSeed(seed).getPublicKey();
        } catch (GeneralSecurityException e) {
            throw refuse();
        }
        OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicKey))
                .d(Base64URL.encode(seed)).build();
        return new Ed25519Signer(okp);
    }

    /** {@return the algorithm this signer uses} */
    public CibaSigningAlg alg() {
        return alg;
    }

    /** {@return the {@code kid} placed in the header, or {@code null}} */
    public @Nullable String kid() {
        return kid;
    }

    /**
     * Signs a CIBA Core &sect;7.1.1 request object: every member inside the JWT,
     * plus {@code iss} (the {@code client_id}), {@code aud} (the issuer),
     * {@code iat} = {@code nbf} = now, {@code exp} = now + 300 s, and a fresh
     * 256-bit {@code jti}. The header carries the algorithm and, when given,
     * the {@code kid}.
     *
     * @param clientId the client's {@code client_id}
     * @param audience the issuer the call is made against
     * @param members  the authentication-request members, with their JSON types; a
     *                 {@link Sensitive} value is exposed into the signed claims
     * @return the compact JWS, wrapped
     */
    public Sensitive sign(String clientId, String audience, Map<String, Object> members) {
        Instant now = Instant.now();
        byte[] jti = new byte[32];
        RANDOM.nextBytes(jti);
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience(audience)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(SIGNED_REQUEST_LIFETIME_SECONDS)))
                .jwtID(HexFormat.of().formatHex(jti));
        // A Sensitive member (the notification token, §33.5) is exposed here, into the
        // claims the signature covers and nowhere else.
        members.forEach((name, value) -> claims.claim(name, value instanceof Sensitive secret
                ? secret.expose() : value));
        JWSHeader.Builder header = new JWSHeader.Builder(alg.jose());
        if (kid != null) {
            header.keyID(kid);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw LocalRefusal.of("ciba_initiate", "signing_key",
                    "the signed request could not be signed with the given key (CONTRACT.md §33.2)");
        }
        return Sensitive.of(jwt.serialize());
    }

    @Override
    public String toString() {
        return "CibaRequestSigner[alg=" + alg + ", kid=" + kid + ", key=[SENSITIVE]]";
    }
}
