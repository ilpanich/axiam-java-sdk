package io.axiam.sdk.internal;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Each verifier owns an HTTP client (and its selector thread): built on first fetch, released on close. */
class JwksVerifierCloseTest {

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
    void aVerifierThatNeverFetchedStartsNoThread() {
        java.util.Set<Thread> before = selectorThreads();
        List<JwksVerifier> verifiers = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            verifiers.add(new JwksVerifier("http://localhost:1"));
        }
        assertTrue(newThreads(before).isEmpty(), "no verifier that never fetched may own a thread");
    }

    private static String token(OctetKeyPair key) throws Exception {
        return OidcTestSupport.signEdDsa(key, new JWTClaimsSet.Builder()
                .subject("u").claim("tenant_id", "t")
                .expirationTime(new Date(System.currentTimeMillis() + 900_000)).build());
    }

    @Test
    void closeReleasesTheClientThreadWithoutAGcAndAFetchAfterCloseFailsClosed() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        java.util.Set<Thread> before = selectorThreads();
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
            server.start();
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            verifier.verifySignatureOnlyUnchecked(token(key));
            java.util.Set<Thread> started = newThreads(before);
            assertEquals(1, started.size(), "the first fetch builds exactly one client thread");

            verifier.close();
            verifier.close(); // idempotent
            assertAllDead(started);

            JwksVerifier closedBeforeFetch = new JwksVerifier(server.url("/").toString());
            closedBeforeFetch.close();
            assertThrows(AuthError.class, () -> closedBeforeFetch.verifySignatureOnlyUnchecked(token(key)));
            assertTrue(newThreads(before).isEmpty(), "a closed verifier never starts a client");
            assertTrue(server.getRequestCount() == 1, "no request after close");
        }
    }
}
