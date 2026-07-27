package io.axiam.sdk.testutil;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import okhttp3.mockwebserver.MockResponse;

import java.util.Date;
import java.util.List;

/**
 * Test-only helpers for CONTRACT.md &sect;12 OIDC tests: EdDSA key
 * generation/signing and OIDC discovery-document/JWKS fixture bodies. Never
 * referenced by production code.
 */
public final class OidcTestSupport {

    private OidcTestSupport() {
    }

    /**
     * Generates a fresh Ed25519 key pair with the given {@code kid}.
     *
     * @param kid the key ID to assign
     * @return the generated key pair
     * @throws Exception if key generation fails
     */
    public static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    /**
     * Signs an ID token with the given key pair and claims.
     *
     * @param keyPair the signing key pair
     * @param claims  the claims to sign
     * @return the compact-serialized, EdDSA-signed JWT
     * @throws Exception if signing fails
     */
    public static String signEdDsa(OctetKeyPair keyPair, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(keyPair));
        return jwt.serialize();
    }

    /**
     * Builds a valid ID-token claim set for {@code issuer}/{@code clientId}/{@code nonce},
     * expiring 15 minutes from now.
     *
     * @param issuer   the {@code iss} claim
     * @param clientId the {@code aud} claim
     * @param nonce    the {@code nonce} claim, or {@code null} to omit it
     * @return the built claim set
     */
    public static JWTClaimsSet validIdTokenClaims(String issuer, String clientId, String nonce) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("user-1")
                .audience(clientId)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
                .issueTime(new Date(System.currentTimeMillis()));
        if (nonce != null) {
            builder.claim("nonce", nonce);
        }
        return builder.build();
    }

    /**
     * Builds a {@code 200 application/json} JWKS document response body.
     *
     * @param publicKey the public key to publish
     * @return the mock response
     */
    public static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    /**
     * Builds a {@code 200 application/json} OIDC discovery-document response
     * body, with every endpoint rooted at {@code baseUrl}.
     *
     * @param baseUrl the mock server's base URL (trailing slash stripped)
     * @return the mock response
     */
    public static MockResponse discoveryResponse(String baseUrl) {
        String trimmed = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String body = "{"
                + "\"issuer\":\"" + trimmed + "\","
                + "\"authorization_endpoint\":\"" + trimmed + "/oauth2/authorize\","
                + "\"token_endpoint\":\"" + trimmed + "/oauth2/token\","
                + "\"userinfo_endpoint\":\"" + trimmed + "/oauth2/userinfo\","
                + "\"jwks_uri\":\"" + trimmed + "/oauth2/jwks\","
                + "\"revocation_endpoint\":\"" + trimmed + "/oauth2/revoke\","
                + "\"introspection_endpoint\":\"" + trimmed + "/oauth2/introspect\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"
                + "\"scopes_supported\":[\"openid\",\"profile\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_post\"],"
                + "\"claims_supported\":[\"sub\",\"iss\"],"
                + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\",\"client_credentials\"]"
                + "}";
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    /**
     * Builds a {@code 200 application/json} {@code TokenResponse} body.
     *
     * @param accessToken  the access token
     * @param refreshToken the refresh token, or {@code null} to omit
     * @param idToken      the ID token, or {@code null} to omit
     * @return the mock response
     */
    public static MockResponse tokenResponse(String accessToken, String refreshToken, String idToken) {
        StringBuilder body = new StringBuilder("{\"access_token\":\"").append(accessToken)
                .append("\",\"token_type\":\"Bearer\",\"expires_in\":900");
        if (refreshToken != null) {
            body.append(",\"refresh_token\":\"").append(refreshToken).append('"');
        }
        if (idToken != null) {
            body.append(",\"id_token\":\"").append(idToken).append('"');
        }
        body.append('}');
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body.toString());
    }
}
