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

import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;10.4 — the optional session-revocation feed (contract
 * 1.44, AXIAM threats T-39 and T-143).
 *
 * <p>Two things are under test and they are separable: what the poller does
 * with a document, and what attaching one changes about a verification. The
 * second is the shorter half and the one that matters — the feed may only ever
 * turn an accept into a reject, and only for a token that names a session.
 *
 * <p>Every negative is paired with its I4 twin: a verifier built as it was
 * before 1.44, a token with no session behind it, a feed that cannot be read.
 * A guard that started denying requests because an advisory document went
 * missing would be a worse failure than the fifteen-minute window &sect;10.2
 * records, and those twins are what rule it out.
 */
class RevocationFeedTest {

    private static final String REVOKED_SID = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b";
    private static final String LIVE_SID = "11111111-2222-3333-4444-555555555555";
    private static final String TENANT = "tenant-a";

    private final AtomicInteger feedFetches = new AtomicInteger();

    // ── The entry format ──────────────────────────────────────────────────

    /**
     * The server computes this entry in {@code axiam_core::revocation_feed} and
     * every SDK recomputes it from a {@code sid} claim. A pinned vector is the
     * only thing keeping twelve implementations of one wire format in
     * agreement; a round trip through this class's own hash would agree with
     * itself while agreeing with nobody.
     */
    @Test
    void entryForMatchesThePinnedVector() {
        assertEquals("i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ", RevocationFeed.entryFor(REVOKED_SID));
    }

    /**
     * Hashed over the claim's exact string. An implementation that parsed the
     * sid as a UUID and re-rendered it would agree on canonical input and
     * disagree the moment a server issued anything else.
     */
    @Test
    void entryForHashesTheStringNotAParsedUuid() {
        assertFalse(RevocationFeed.entryFor(REVOKED_SID)
                        .equals(RevocationFeed.entryFor(REVOKED_SID.toUpperCase(java.util.Locale.ROOT))),
                "an upper-case sid hashed to the same entry: the input was normalised");
    }

    // ── The poller ────────────────────────────────────────────────────────

    @Test
    void aListedSessionIsReportedRevokedAndAnUnlistedOneIsNot() throws Exception {
        try (MockWebServer server = feedServer(feedDocument("SHA-256", RevocationFeed.entryFor(REVOKED_SID)))) {
            RevocationFeed feed = feedFor(server);

            assertTrue(feed.isRevoked(REVOKED_SID));
            assertFalse(feed.isRevoked(LIVE_SID));
        }
    }

    /**
     * &sect;10.4 rule 3 — every way the feed can be unusable behaves exactly as
     * no feed at all. The failure this forecloses is the opposite: a guard that
     * starts denying every request because a document it treats as advisory
     * became unreachable.
     */
    @Test
    void anUnusableFeedDeniesNothing() throws Exception {
        String oversized = IntStream.rangeClosed(0, RevocationFeed.MAX_ENTRIES)
                .mapToObj(i -> "\"" + RevocationFeed.entryFor("session-" + i) + "\"")
                .collect(Collectors.joining(",", "{\"alg\":\"SHA-256\",\"revoked\":[", "]}"));

        record Case(String name, MockResponse response) { }
        for (Case unusable : java.util.List.of(
                new Case("a 404 — the deployment does not publish the feed",
                        new MockResponse().setResponseCode(404)),
                new Case("a 500 — the feed is broken",
                        new MockResponse().setResponseCode(500)),
                new Case("a body that is not JSON",
                        new MockResponse().setResponseCode(200).setBody("not json")),
                new Case("an alg this build does not know",
                        feedDocument("SHA-512", RevocationFeed.entryFor(REVOKED_SID))),
                new Case("more entries than the cache bound",
                        new MockResponse().setResponseCode(200)
                                .setHeader("Content-Type", "application/json").setBody(oversized)))) {
            try (MockWebServer server = feedServer(unusable.response())) {
                assertFalse(feedFor(server).isRevoked(REVOKED_SID), unusable.name());
            }
        }
    }

    @Test
    void anUnreachableFeedDeniesNothing() throws Exception {
        MockWebServer server = feedServer(feedDocument("SHA-256", RevocationFeed.entryFor(REVOKED_SID)));
        RevocationFeed feed = feedFor(server);
        server.close();

        assertFalse(feed.isRevoked(REVOKED_SID), "an unreachable feed must deny nothing");
    }

    /**
     * An over-sized document drops the <em>whole</em> set rather than
     * truncating it. A truncated set is a guard that admits some revoked
     * sessions and reports none, which is worse than one that admits all of
     * them and says so.
     */
    @Test
    void anOversizedDocumentDropsEverythingRatherThanTruncating() throws Exception {
        String oversized = IntStream.rangeClosed(0, RevocationFeed.MAX_ENTRIES)
                .mapToObj(i -> "\"" + (i == 0 ? RevocationFeed.entryFor(REVOKED_SID)
                        : RevocationFeed.entryFor("session-" + i)) + "\"")
                .collect(Collectors.joining(",", "{\"alg\":\"SHA-256\",\"revoked\":[", "]}"));

        try (MockWebServer server = feedServer(new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json").setBody(oversized))) {
            assertFalse(feedFor(server).isRevoked(REVOKED_SID),
                    "the first entry of an oversized document must not be honoured");
        }
    }

    /**
     * A blip must not un-revoke a session the guard already knows about: the
     * previous set stays in place across a failed refresh.
     */
    @Test
    void aFailedPollKeepsThePreviousSet() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    return feedFetches.incrementAndGet() == 1
                            ? feedDocument("SHA-256", RevocationFeed.entryFor(REVOKED_SID))
                            : new MockResponse().setResponseCode(500);
                }
            });
            server.start();

            RevocationFeed feed = feedFor(server);
            feed.refresh();
            feed.refresh();

            assertTrue(feed.isRevoked(REVOKED_SID),
                    "a failed refresh dropped a revocation the poller already knew about");
        }
    }

    // ── §10.4 rule 2 — the poll interval ──────────────────────────────────

    @Test
    void repeatedChecksInsideOneIntervalDoNotRefetch() throws Exception {
        try (MockWebServer server = feedServer(feedDocument("SHA-256"))) {
            RevocationFeed feed = feedFor(server);
            for (int i = 0; i < 5; i++) {
                feed.isRevoked(LIVE_SID);
            }
            assertEquals(1, feedFetches.get(), "five checks inside one interval must make one fetch");
        }
    }

    /**
     * Once the interval has elapsed, the next check refetches. Asserted through
     * an injected clock rather than by sleeping — a test that really waited
     * fifteen seconds is a test nobody runs.
     */
    @Test
    void anElapsedIntervalRefetches() throws Exception {
        try (MockWebServer server = feedServer(feedDocument("SHA-256"))) {
            AtomicLong clock = new AtomicLong(1_000_000L);
            RevocationFeed feed = new RevocationFeed(new OkHttpClient(), server.url("/").toString(),
                    RevocationFeed.DEFAULT_POLL_INTERVAL, clock::get);

            feed.isRevoked(LIVE_SID);
            clock.addAndGet(RevocationFeed.DEFAULT_POLL_INTERVAL.toMillis() + 1_000L);
            feed.isRevoked(LIVE_SID);

            assertEquals(2, feedFetches.get());
        }
    }

    /**
     * The floor is applied by clamping, not by refusing: a caller who asks for
     * something faster gets the fastest thing on offer.
     */
    @Test
    void aShorterIntervalIsClampedRatherThanRefused() {
        RevocationFeed clamped = new RevocationFeed(new OkHttpClient(), "https://iam.example.com",
                Duration.ofMillis(1));
        assertEquals(RevocationFeed.MIN_POLL_INTERVAL, clamped.pollInterval());

        RevocationFeed kept = new RevocationFeed(new OkHttpClient(), "https://iam.example.com",
                Duration.ofMinutes(2));
        assertEquals(Duration.ofMinutes(2), kept.pollInterval());
    }

    /**
     * A feed that is down must not be retried on every request, which would put
     * the request path back on the network — the cost &sect;10.4 exists to
     * avoid. The interval is measured from the last <em>attempt</em>, not the
     * last success.
     */
    @Test
    void aDownFeedIsNotRetriedOnEveryRequest() throws Exception {
        try (MockWebServer server = feedServer(new MockResponse().setResponseCode(500))) {
            RevocationFeed feed = feedFor(server);
            for (int i = 0; i < 5; i++) {
                feed.isRevoked(LIVE_SID);
            }
            assertEquals(1, feedFetches.get(), "five checks against a down feed must make one fetch");
        }
    }

    /** A token with no session behind it never reaches the wire, let alone the set. */
    @Test
    void aBlankSidIsNeverMatched() throws Exception {
        try (MockWebServer server = feedServer(feedDocument("SHA-256", RevocationFeed.entryFor("")))) {
            RevocationFeed feed = feedFor(server);

            assertFalse(feed.isRevoked(""), "an empty sid must never match");
            assertFalse(feed.isRevoked(null), "an absent sid must never match");
            assertEquals(0, feedFetches.get(), "a sid-less token must not even trigger a fetch");
        }
    }

    @Test
    void theFeedPathIsAppendedToTheBaseUrl() {
        assertEquals("https://iam.example.com/oauth2/revocations",
                new RevocationFeed(new OkHttpClient(), "https://iam.example.com/").feedUrl());
    }

    // ── What attaching one changes about a verification ───────────────────

    @Test
    void aRevokedSessionIsRejected() throws Exception {
        OctetKeyPair key = generateEd25519KeyPair("key-1");
        try (MockWebServer jwks = jwksServer(key); MockWebServer feedHost =
                feedServer(feedDocument("SHA-256", RevocationFeed.entryFor(REVOKED_SID)))) {
            JwksVerifier verifier = verifierWith(jwks, feedFor(feedHost));
            String token = signEdDsa(key, claims(REVOKED_SID));

            AuthError refused = assertThrows(AuthError.class, () -> verifier.verifyAccessToken(token, TENANT));
            assertTrue(refused.getMessage().contains("revoked"), refused.getMessage());
            // Its own report: "the session is gone" is not "this credential was
            // never valid", and a guard that conflated them would tell a
            // logged-out user their token had expired.
            assertFalse(refused.getMessage().contains("expired"), refused.getMessage());
        }
    }

    @Test
    void aSessionTheFeedDoesNotListIsAdmitted() throws Exception {
        OctetKeyPair key = generateEd25519KeyPair("key-1");
        try (MockWebServer jwks = jwksServer(key); MockWebServer feedHost =
                feedServer(feedDocument("SHA-256", RevocationFeed.entryFor(REVOKED_SID)))) {
            JwksVerifier verifier = verifierWith(jwks, feedFor(feedHost));

            assertNotNull(verifier.verifyAccessToken(signEdDsa(key, claims(LIVE_SID)), TENANT));
        }
    }

    /**
     * The feed can only ever turn an accept into a reject: a token that fails
     * &sect;10.1 still fails for its own reason, so a feed listing nothing can
     * never rescue an expired token.
     */
    @Test
    void theFeedNeverTurnsARejectIntoAnAccept() throws Exception {
        OctetKeyPair key = generateEd25519KeyPair("key-1");
        try (MockWebServer jwks = jwksServer(key); MockWebServer feedHost = feedServer(feedDocument("SHA-256"))) {
            JwksVerifier verifier = verifierWith(jwks, feedFor(feedHost));
            JWTClaimsSet expired = new JWTClaimsSet.Builder()
                    .subject("user-1")
                    .claim("tenant_id", TENANT)
                    .claim("sid", LIVE_SID)
                    .expirationTime(new Date(System.currentTimeMillis() - 900_000))
                    .build();

            AuthError refused = assertThrows(AuthError.class,
                    () -> verifier.verifyAccessToken(signEdDsa(key, expired), TENANT));
            assertTrue(refused.getMessage().contains("expired"), refused.getMessage());
        }
    }

    // ── I4 — configured as today, behaves as today ────────────────────────

    /**
     * The default. A verifier built as it was before contract 1.44 accepts
     * exactly what it accepted then, including a token whose session a feed
     * WOULD have listed — the &sect;10.2 posture this narrows rather than
     * replaces.
     */
    @Test
    void noFeedAttachedIsUnchangedBehaviour() throws Exception {
        OctetKeyPair key = generateEd25519KeyPair("key-1");
        try (MockWebServer jwks = jwksServer(key)) {
            JwksVerifier verifier = new JwksVerifier(jwks.url("/").toString());

            assertDoesNotThrow(() -> verifier.verifyAccessToken(signEdDsa(key, claims(REVOKED_SID)), TENANT));
        }
    }

    /**
     * A token with no session behind it is never matched against the feed, even
     * when the document happens to list the hash of the empty string. Hashing
     * {@code jti} instead would match nothing while looking like it worked.
     */
    @Test
    void aTokenWithNoSessionIsNeverMatched() throws Exception {
        OctetKeyPair key = generateEd25519KeyPair("key-1");
        try (MockWebServer jwks = jwksServer(key); MockWebServer feedHost =
                feedServer(feedDocument("SHA-256", RevocationFeed.entryFor("")))) {
            JwksVerifier verifier = verifierWith(jwks, feedFor(feedHost));

            assertDoesNotThrow(() -> verifier.verifyAccessToken(signEdDsa(key, claims(null)), TENANT));
        }
    }

    /**
     * &sect;10.4 rule 3 at the verifier, not just at the poller: an unreachable
     * feed denies nothing. This is what keeps the feature safe to turn on — the
     * alternative is a guard that stops serving when an advisory document goes
     * missing.
     */
    @Test
    void anUnreachableFeedDeniesNothingAtTheVerifier() throws Exception {
        OctetKeyPair key = generateEd25519KeyPair("key-1");
        MockWebServer feedHost = feedServer(feedDocument("SHA-256", RevocationFeed.entryFor(REVOKED_SID)));
        RevocationFeed feed = feedFor(feedHost);
        feedHost.close();

        try (MockWebServer jwks = jwksServer(key)) {
            JwksVerifier verifier = verifierWith(jwks, feed);

            assertDoesNotThrow(() -> verifier.verifyAccessToken(signEdDsa(key, claims(REVOKED_SID)), TENANT));
        }
    }

    // ── Harness ───────────────────────────────────────────────────────────

    private MockWebServer feedServer(MockResponse response) throws Exception {
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                feedFetches.incrementAndGet();
                return response;
            }
        });
        server.start();
        return server;
    }

    private RevocationFeed feedFor(MockWebServer server) {
        return new RevocationFeed(new OkHttpClient(), server.url("/").toString());
    }

    private static MockResponse feedDocument(String alg, String... entries) {
        String revoked = java.util.Arrays.stream(entries)
                .map(e -> "\"" + e + "\"")
                .collect(Collectors.joining(",", "[", "]"));
        return new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"alg\":\"" + alg + "\",\"revoked\":" + revoked + "}");
    }

    private static MockWebServer jwksServer(OctetKeyPair key) throws Exception {
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(java.util.List.of(key.toPublicJWK())).toString());
            }
        });
        server.start();
        return server;
    }

    private static JwksVerifier verifierWith(MockWebServer jwks, RevocationFeed feed) {
        return new JwksVerifier(jwks.url("/").toString(), JwksVerifier.LocalVerificationPolicy.defaults(), feed);
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static JWTClaimsSet claims(@Nullable String sid) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", TENANT)
                .expirationTime(new Date(System.currentTimeMillis() + 900_000));
        // Omitted entirely when null, so "a token with no session behind it" —
        // client credentials, an RPT, a token exchange — stays expressible.
        if (sid != null) {
            builder = builder.claim("sid", sid);
        }
        return builder.build();
    }

    private static String signEdDsa(OctetKeyPair keyPair, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(keyPair));
        return jwt.serialize();
    }
}
