package io.axiam.sdk;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code close()} releases the OIDC jwks_uri verifiers' HTTP clients; a rebound handle's close leaves shared ones. */
class AxiamClientJwksCloseTest {

    /** The primary handle's OIDC verifier clients, reached reflectively: test-only, no production seam is public. */
    @SuppressWarnings("unchecked")
    private static java.util.List<java.net.http.HttpClient> oidcVerifierClients(AxiamClient client) throws Exception {
        java.lang.reflect.Field f = AxiamClient.class.getDeclaredField("oidcJwksVerifiers");
        f.setAccessible(true);
        java.util.List<java.net.http.HttpClient> clients = new java.util.ArrayList<>();
        for (Object verifier : ((Map<String, Object>) f.get(client)).values()) {
            java.lang.reflect.Method m = verifier.getClass().getDeclaredMethod("fetchClientForTesting");
            m.setAccessible(true);
            Object c = m.invoke(verifier);
            if (c != null) {
                clients.add((java.net.http.HttpClient) c);
            }
        }
        return clients;
    }

    @Test
    void closingThePrimaryHandleReleasesTheOidcVerifierThreadButARebindDoesNot() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
            server.start();
            String issuer = base.substring(0, base.length() - 1);
            long now = System.currentTimeMillis() / 1000L;
            String token = OidcTestSupport.signEdDsa(key, new JWTClaimsSet.Builder()
                    .issuer(issuer).audience("my-app").subject("u").jwtID("j")
                    .issueTime(new Date(now * 1000L)).expirationTime(new Date((now + 120) * 1000L))
                    .claim("sid", "s")
                    .claim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()))
                    .build());

            AxiamClient primary = AxiamClient.builder(base, "33333333-3333-3333-3333-333333333333")
                    .oidcClientId("my-app").build();
            primary.verifyLogoutToken(token, null);
            java.util.List<java.net.http.HttpClient> started = oidcVerifierClients(primary);
            assertEquals(1, started.size());

            AxiamClient rebound = primary.actingTenant(UUID.randomUUID());
            rebound.close();
            for (java.net.http.HttpClient c : started) {
                assertFalse(c.isTerminated(), "a rebound handle must not close the primary's verifiers");
            }

            primary.close();
            for (java.net.http.HttpClient c : started) {
                assertTrue(c.awaitTermination(java.time.Duration.ofSeconds(5)), "primary close() terminates it");
            }
        }
    }
}
