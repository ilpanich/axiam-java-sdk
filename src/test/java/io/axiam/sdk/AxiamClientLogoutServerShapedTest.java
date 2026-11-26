package io.axiam.sdk;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.oidc.VerifiedLogoutToken;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.7.3 rule 1 and &sect;12.7.6 (contract 1.69; #880): the back-channel logout
 * token the server signs carries a header of exactly {@code alg}, {@code typ: logout+jwt} and
 * {@code kid}, and {@code verifyLogoutToken} selects the key by that {@code kid}. The fixture signer
 * adds nothing the server does not send (the shared test signer writes {@code typ: JWT}, so it is
 * not used here), and the JWKS holds two keys with the signing key second.
 */
class AxiamClientLogoutServerShapedTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String CLIENT_ID = "my-app";
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private static String sign(OctetKeyPair key, String typ, String kid, JWTClaimsSet claims) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(new JOSEObjectType(typ));
        if (kid != null) {
            header.keyID(kid);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims);
        jwt.sign(new Ed25519Signer(key));
        return jwt.serialize();
    }

    private static JWTClaimsSet logoutClaims(String issuer) {
        long now = System.currentTimeMillis() / 1000L;
        return new JWTClaimsSet.Builder().issuer(issuer).audience(CLIENT_ID).subject("user-1").jwtID("jti-1")
                .issueTime(new Date(now * 1000L)).expirationTime(new Date((now + 120) * 1000L))
                .claim("sid", "session-abc").claim("events", Map.of(EVENT, Map.of())).build();
    }

    private static MockWebServer server(List<OctetKeyPair> published) throws Exception {
        MockWebServer server = new MockWebServer();
        String base = server.url("/").toString();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (request.getPath().contains("jwks")) {
                    return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                            .setBody(new JWKSet(published.stream().map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK())
                                    .toList()).toString());
                }
                return OidcTestSupport.discoveryResponse(base);
            }
        });
        server.start();
        return server;
    }

    @Test
    void aServerShapedLogoutTokenVerifiesAgainstATwoKeyJwksWithTheSigningKeySecond() throws Exception {
        OctetKeyPair other = OidcTestSupport.generateEd25519KeyPair("kid-old");
        OctetKeyPair signing = OidcTestSupport.generateEd25519KeyPair("kid-current");
        try (MockWebServer server = server(List.of(other, signing))) {
            String base = server.url("/").toString();
            String token = sign(signing, "logout+jwt", "kid-current", logoutClaims(base.substring(0, base.length() - 1)));
            // The header is exactly what the server sends.
            assertEquals(java.util.Set.of("alg", "typ", "kid"),
                    SignedJWT.parse(token).getHeader().toJSONObject().keySet());

            try (AxiamClient c = AxiamClient.builder(base, TENANT_ID).oidcClientId(CLIENT_ID).build()) {
                VerifiedLogoutToken verified = c.verifyLogoutToken(token, null);
                assertEquals("session-abc", verified.sid());
            }
        }
    }

    @Test
    void aKidlessLogoutTokenIsRefusedAsUnknownKidEvenAgainstAOneKeyJwksThatSignedIt() throws Exception {
        OctetKeyPair signing = OidcTestSupport.generateEd25519KeyPair("kid-current");
        try (MockWebServer server = server(List.of(signing))) {
            String base = server.url("/").toString();
            String token = sign(signing, "logout+jwt", null, logoutClaims(base.substring(0, base.length() - 1)));

            try (AxiamClient c = AxiamClient.builder(base, TENANT_ID).oidcClientId(CLIENT_ID).build()) {
                AuthError e = assertThrows(AuthError.class, () -> c.verifyLogoutToken(token, null));
                assertEquals("unknown_kid", e.reason());
            }
        }
    }

    @Test
    void anUnknownKidLogoutTokenIsRefusedAsUnknownKid() throws Exception {
        OctetKeyPair signing = OidcTestSupport.generateEd25519KeyPair("kid-current");
        OctetKeyPair published = OidcTestSupport.generateEd25519KeyPair("kid-other");
        try (MockWebServer server = server(List.of(published))) {
            String base = server.url("/").toString();
            String token = sign(signing, "logout+jwt", "kid-current", logoutClaims(base.substring(0, base.length() - 1)));

            try (AxiamClient c = AxiamClient.builder(base, TENANT_ID).oidcClientId(CLIENT_ID).build()) {
                AuthError e = assertThrows(AuthError.class, () -> c.verifyLogoutToken(token, null));
                assertEquals("unknown_kid", e.reason());
            }
        }
    }

    @Test
    void rules10And11StayOffTheLogoutAndIdTokenPathsWhileTheAccessGuardRefusesBoth() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("kid-current");
        try (MockWebServer server = server(List.of(key))) {
            JwksVerifier verifier = JwksVerifier.forJwksUri(server.url("/oauth2/jwks").toString());
            long exp = System.currentTimeMillis() / 1000L + 600;
            JWTClaimsSet withTenant = new JWTClaimsSet.Builder().subject("user-1").claim("tenant_id", TENANT_ID)
                    .expirationTime(new Date(exp * 1000L)).build();

            String logout = sign(key, "logout+jwt", "kid-current", withTenant);
            String id = sign(key, "JWT", "kid-current", withTenant);

            // The OIDC (ID-token and logout) path applies neither rule 10 nor rule 11.
            assertEquals("user-1", verifier.verifyForOidc(logout).getSubject());
            assertEquals("user-1", verifier.verifyForOidc(id).getSubject());
            // The access-token guard refuses both (rule 10), a valid kid notwithstanding.
            AuthError e1 = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(logout, TENANT_ID));
            AuthError e2 = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(id, TENANT_ID));
            assertTrue(e1.getMessage().contains("typ"), e1.getMessage());
            assertTrue(e2.getMessage().contains("typ"), e2.getMessage());
            // Rule 11 is off the OIDC path as well: a purpose claim does not stop an ID token verifying there.
            JWTClaimsSet withPurpose = new JWTClaimsSet.Builder().subject("user-1").claim("purpose", "x")
                    .expirationTime(new Date(exp * 1000L)).build();
            assertEquals("user-1", verifier.verifyForOidc(sign(key, "JWT", "kid-current", withPurpose)).getSubject());
        }
    }
}
