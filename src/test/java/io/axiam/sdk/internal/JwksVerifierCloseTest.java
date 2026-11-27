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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Each verifier owns an HTTP client (and its selector thread): built on first fetch, released on close. */
class JwksVerifierCloseTest {

    @Test
    void aVerifierThatNeverFetchedStartsNoThread() {
        List<JwksVerifier> verifiers = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            verifiers.add(new JwksVerifier("http://localhost:1"));
        }
        for (JwksVerifier v : verifiers) {
            assertNull(v.fetchClientForTesting(), "a verifier that never fetched must not own a client");
        }
    }

    private static String token(OctetKeyPair key) throws Exception {
        return OidcTestSupport.signEdDsa(key, new JWTClaimsSet.Builder()
                .subject("u").claim("tenant_id", "t")
                .expirationTime(new Date(System.currentTimeMillis() + 900_000)).build());
    }

    @Test
    void closeReleasesTheClientThreadWithoutAGcAndAFetchAfterCloseFailsClosed() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("k1");
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
            server.start();
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            verifier.verifySignatureOnlyUnchecked(token(key));
            java.net.http.HttpClient client = verifier.fetchClientForTesting();
            assertNotNull(client, "the first fetch builds the client");
            assertFalse(client.isTerminated());

            verifier.close();
            verifier.close(); // idempotent
            assertTrue(client.awaitTermination(java.time.Duration.ofSeconds(5)), "close() must terminate the client");
            assertNull(verifier.fetchClientForTesting());

            JwksVerifier closedBeforeFetch = new JwksVerifier(server.url("/").toString());
            closedBeforeFetch.close();
            assertThrows(AuthError.class, () -> closedBeforeFetch.verifySignatureOnlyUnchecked(token(key)));
            assertNull(closedBeforeFetch.fetchClientForTesting(), "a closed verifier never builds a client");
            assertTrue(server.getRequestCount() == 1, "no request after close");
        }
    }
}
