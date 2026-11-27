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
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code close()} releases the OIDC jwks_uri verifiers' HTTP clients; a rebound handle's close leaves shared ones. */
class AxiamClientJwksCloseTest {

    private static java.util.Set<Thread> selectorThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.isAlive() && t.getName().contains("SelectorManager"))
                .collect(java.util.stream.Collectors.toSet());
    }

    /** Selector threads alive now that were not in {@code snapshot}: robust to unrelated threads exiting. */
    private static java.util.Set<Thread> newThreads(java.util.Set<Thread> snapshot) {
        java.util.Set<Thread> now = selectorThreads();
        now.removeAll(snapshot);
        return now;
    }

    private static void assertAllDead(java.util.Set<Thread> threads) throws InterruptedException {
        for (Thread t : threads) {
            t.join(5_000);
            org.junit.jupiter.api.Assertions.assertFalse(t.isAlive(), "selector thread must end after close()");
        }
    }

    @Test
    void closingThePrimaryHandleReleasesTheOidcVerifierThreadButARebindDoesNot() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        java.util.Set<Thread> before = selectorThreads();
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
            java.util.Set<Thread> started = newThreads(before);
            assertEquals(1, started.size());

            AxiamClient rebound = primary.actingTenant(UUID.randomUUID());
            rebound.close();
            for (Thread t : started) {
                assertTrue(t.isAlive(), "a rebound handle must not close the primary's verifiers");
            }

            primary.close();
            assertAllDead(started);
        }
    }
}
