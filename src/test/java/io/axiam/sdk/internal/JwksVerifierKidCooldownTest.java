package io.axiam.sdk.internal;

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

import io.axiam.sdk.errors.AuthError;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.4 rule 2 (JAV-R1-3, plan decision D-4): the unknown-{@code kid} cooldown
 * holds on a cold cache and when the JWKS endpoint fails, not only on a warm cache, and the
 * contract's own conformance test (fifty unknown {@code kid}s in one window cause at most one
 * fetch; a rotated key is accepted after one fetch).
 */
class JwksVerifierKidCooldownTest {

    private static final String TENANT = "tenant-a";

    @Test
    void conformance_fiftyUnknownKidsInOneWindowCauseAtMostOneFetch_thenARotatedKeyIsAcceptedAfterOneFetch()
            throws Exception {
        OctetKeyPair oldKey = key("key-1");
        OctetKeyPair newKey = key("key-2");
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<OctetKeyPair> published = new AtomicReference<>(oldKey);
        try (MockWebServer server = server(fetches, published, 200)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            AtomicLong now = new AtomicLong(1_000_000_000L);
            verifier.setClockForTesting(now::get);

            // Cold cache, fifty distinct unknown kids, one window.
            for (int i = 0; i < 50; i++) {
                String forged = sign(oldKey, "unknown-" + i);
                assertThrows(AuthError.class, () -> verifier.verifyAccessToken(forged, TENANT));
            }
            assertTrue(fetches.get() <= 1, "fifty unknown kids in one window fetched " + fetches.get() + " times");

            // The key rotates; the window passes; one fetch accepts the new key.
            published.set(newKey);
            now.addAndGet(JwksVerifier.UNKNOWN_KID_REFETCH_COOLDOWN.toNanos() + 1);
            int before = fetches.get();
            assertEquals("user-1", verifier.verifyAccessToken(sign(newKey, "key-2"), TENANT).getSubject());
            assertEquals(1, fetches.get() - before, "the rotated key costs exactly one fetch");
        }
    }

    @Test
    void failingEndpoint_twentyTokensCauseOneFetch() throws Exception {
        OctetKeyPair key = key("key-1");
        AtomicInteger fetches = new AtomicInteger();
        try (MockWebServer server = server(fetches, new AtomicReference<>(key), 500)) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            for (int i = 0; i < 20; i++) {
                // Even a token naming the genuine kid: the cache is cold and the endpoint is down.
                String token = sign(key, i % 2 == 0 ? "key-1" : "junk-" + i);
                assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
            }
            assertEquals(1, fetches.get(), "a failed fetch counts toward the window");
        }
    }

    @Test
    void failingEndpoint_theIdTokenPathHoldsTheWindowToo() throws Exception {
        OctetKeyPair key = key("key-1");
        AtomicInteger fetches = new AtomicInteger();
        try (MockWebServer server = server(fetches, new AtomicReference<>(key), 503)) {
            JwksVerifier verifier = JwksVerifier.forJwksUri(server.url("/oauth2/jwks").toString());
            for (int i = 0; i < 20; i++) {
                String token = sign(key, "junk-" + i);
                assertThrows(AuthError.class, () -> verifier.verifyForOidc(token));
            }
            assertEquals(1, fetches.get());
        }
    }

    @Test
    void failingEndpoint_isRetriedOnceTheWindowHasPassed() throws Exception {
        OctetKeyPair key = key("key-1");
        AtomicInteger fetches = new AtomicInteger();
        AtomicInteger status = new AtomicInteger(500);
        AtomicReference<OctetKeyPair> published = new AtomicReference<>(key);
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                fetches.incrementAndGet();
                if (status.get() != 200) {
                    return new MockResponse().setResponseCode(status.get());
                }
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(List.of(published.get().toPublicJWK())).toString());
            }
        });
        server.start();
        try (server) {
            JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
            AtomicLong now = new AtomicLong(1_000_000_000L);
            verifier.setClockForTesting(now::get);
            String token = sign(key, "key-1");
            assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));

            status.set(200);
            now.addAndGet(JwksVerifier.UNKNOWN_KID_REFETCH_COOLDOWN.toNanos() + 1);
            assertEquals("user-1", verifier.verifyAccessToken(token, TENANT).getSubject());
        }
    }

    // --- helpers -----------------------------------------------------------

    private static OctetKeyPair key(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static String sign(OctetKeyPair key, String kid) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user-1").claim("tenant_id", TENANT)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000L)).build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(new JOSEObjectType("at+jwt"))
                .keyID(kid).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(key));
        return jwt.serialize();
    }

    private static MockWebServer server(AtomicInteger fetches, AtomicReference<OctetKeyPair> published, int status)
            throws Exception {
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                fetches.incrementAndGet();
                if (status != 200) {
                    return new MockResponse().setResponseCode(status);
                }
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(List.of(published.get().toPublicJWK())).toString());
            }
        });
        server.start();
        return server;
    }
}
