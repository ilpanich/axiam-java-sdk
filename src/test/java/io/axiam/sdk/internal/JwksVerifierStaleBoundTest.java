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

import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CONTRACT.md &sect;12.4 rule 2, "Stale-if-error, bounded" (contract 1.69; D-10): the conformance test, with an
 * injected clock and a counting mock server. Everything but the empty-set case pins behaviour the verifier
 * already had ({@code JWKS_TTL} + {@code JWKS_MAX_STALE}); the empty set ({@code {"keys":[]}}) must be a failed
 * refresh, not a replacement.
 */
class JwksVerifierStaleBoundTest {

    private static final String TENANT = "tenant-a";
    private static final long T0 = 1_000_000_000L;

    private enum Mode { SET, FAIL, EMPTY, NO_JWK, ARRAY, RSA_ONLY }

    private static long secs(long s) {
        return Duration.ofSeconds(s).toNanos();
    }

    private static final class Fixture implements AutoCloseable {
        final OctetKeyPair held;
        final AtomicInteger fetches = new AtomicInteger();
        final AtomicReference<Mode> mode = new AtomicReference<>(Mode.SET);
        final AtomicLong now = new AtomicLong(T0);
        final MockWebServer server = new MockWebServer();
        final JwksVerifier verifier;

        Fixture() throws Exception {
            held = new OctetKeyPairGenerator(Curve.Ed25519).keyID("held").generate();
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    fetches.incrementAndGet();
                    return switch (mode.get()) {
                        case FAIL -> new MockResponse().setResponseCode(500);
                        case EMPTY -> json("{\"keys\":[]}");
                        case ARRAY -> json("{\"keys\":[0,null]}");
                        case RSA_ONLY -> json("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}");
                        case NO_JWK -> json("{\"keys\":[{}]}");
                        case SET -> json(new JWKSet(List.of(held.toPublicJWK())).toString());
                    };
                }
            });
            server.start();
            verifier = new JwksVerifier(server.url("/").toString());
            verifier.setClockForTesting(now::get);
            // Fill the cache at t0.
            assertEquals("user-1", verifier.verifyAccessToken(token("held"), TENANT).getSubject());
            assertEquals(1, fetches.get());
        }

        private static MockResponse json(String body) {
            return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody(body);
        }

        String token(String kid) throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user-1").claim("tenant_id", TENANT)
                    .expirationTime(new Date(System.currentTimeMillis() + 900_000L)).build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(new JOSEObjectType("at+jwt"))
                    .keyID(kid).build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new Ed25519Signer(held));
            return jwt.serialize();
        }

        void at(long secondsAfterT0) {
            now.set(T0 + secs(secondsAfterT0));
        }

        boolean accepts(String kid) throws Exception {
            try {
                verifier.verifyAccessToken(token(kid), TENANT);
                return true;
            } catch (AuthError e) {
                return false;
            }
        }

        @Override
        public void close() throws Exception {
            server.close();
        }
    }

    private static final long TTL = JwksVerifier.JWKS_TTL.toSeconds();

    @Test
    void conformance_failingRefresh_heldKidVerifiesUntilTtlPlus300ThenIsRefused_thenOneFetchRestoresIt()
            throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.FAIL);

            f.at(TTL + 1);
            assertEquals(true, f.accepts("held"), "held kid accepted at t0 + TTL + 1 s");
            assertEquals(2, f.fetches.get(), "one failed refresh was attempted");

            f.at(TTL + 250);
            assertEquals(false, f.accepts("unknown"), "unknown kid refused at t0 + TTL + 250 s");
            assertEquals(true, f.accepts("held"), "held kid still accepted at t0 + TTL + 250 s");

            f.at(TTL + 301);
            assertEquals(false, f.accepts("held"), "held kid refused at t0 + TTL + 301 s");

            f.mode.set(Mode.SET);
            f.at(TTL + 301 + 61); // past the unknown-kid window
            int before = f.fetches.get();
            assertEquals(true, f.accepts("held"), "held kid accepted again after a successful fetch");
            assertEquals(1, f.fetches.get() - before, "exactly one fetch");
        }
    }

    @Test
    void conformance_emptyKeySetIsAFailedRefresh_heldKidStaysAcceptedAndTheAnchorDoesNotMove() throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.EMPTY);

            f.at(TTL + 1);
            assertEquals(true, f.accepts("held"), "held kid accepted at t0 + TTL + 1 s after a 200 {\"keys\":[]}");
            assertEquals(2, f.fetches.get(), "the empty answer was fetched once");

            // The empty answer did not move the anchor: the bound still runs from t0.
            f.at(TTL + 250);
            assertEquals(true, f.accepts("held"), "held kid still accepted at t0 + TTL + 250 s");
            f.at(TTL + 301);
            assertEquals(false, f.accepts("held"), "held kid refused at t0 + TTL + 301 s: the anchor did not move");
        }
    }

    @Test
    void aKeysArrayWithNoJwkObjectIsAFailedRefreshToo() throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.NO_JWK);
            f.at(TTL + 1);
            assertEquals(true, f.accepts("held"), "{\"keys\":[{}]} leaves the held kid accepted");
            f.at(TTL + 301);
            assertEquals(false, f.accepts("held"), "and does not move the anchor");
        }
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.ARRAY);
            f.at(TTL + 1);
            assertEquals(true, f.accepts("held"), "{\"keys\":[0,null]} leaves the held kid accepted");
        }
    }

    /** Pin: a well-formed JWK this SDK cannot use still counts as a key (contract: "at least one key"). */
    @Test
    void aWellFormedButUnusableJwkCountsAsASuccessfulFetch() throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.RSA_ONLY);
            f.at(TTL + 1);
            assertEquals(false, f.accepts("held"), "the RSA-only set replaced the held set (a success)");
            f.mode.set(Mode.SET);
            f.at(TTL + 70);
            assertEquals(true, f.accepts("held"));
        }
    }

    @Test
    void aBackwardsClockMeansRefreshDueNeverFresh() throws Exception {
        try (Fixture f = new Fixture()) {
            f.now.set(T0 - secs(10));
            int before = f.fetches.get();
            assertEquals(true, f.accepts("held"));
            assertEquals(before + 1, f.fetches.get(), "negative age triggers a refresh");
        }
    }

    @Test
    void aBackwardsClockWithAFailingRefreshRefusesTheHeldKeys() throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.FAIL);
            f.now.set(T0 - secs(10));
            assertEquals(false, f.accepts("held"), "held keys are not trusted while the age is negative");
        }
    }

    @Test
    void anUnknownKidRefreshThatFailsNeverExtendsTheStaleWindow() throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.FAIL);
            f.at(TTL + 100);
            assertEquals(false, f.accepts("unknown"));
            f.at(TTL + 299);
            assertEquals(false, f.accepts("unknown"));
            assertEquals(true, f.accepts("held"));
            f.at(TTL + 301);
            assertEquals(false, f.accepts("held"));
        }
    }

    @Test
    void aFailedAttemptCountsTowardTheUnknownKidWindow() throws Exception {
        try (Fixture f = new Fixture()) {
            f.mode.set(Mode.FAIL);
            f.at(TTL + 10);
            for (int i = 0; i < 20; i++) {
                f.accepts("unknown-" + i);
            }
            assertEquals(2, f.fetches.get(), "twenty unknown kids in one window cost one fetch");
        }
    }
}
