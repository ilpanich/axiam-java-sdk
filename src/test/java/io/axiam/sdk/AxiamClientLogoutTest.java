package io.axiam.sdk;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.oidc.VerifiedLogoutToken;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RP-initiated and back-channel logout — CONTRACT.md &sect;12.7.
 *
 * <p>The &sect;12.7.6 required tests. The {@code verifyLogoutToken} half
 * carries the security weight: its input arrives unsolicited, from the
 * network, and instructs the RP to terminate a session — so each rejection
 * test names the attack it prevents rather than merely asserting an error.
 */
class AxiamClientLogoutTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String CLIENT_ID = "my-app";
    private static final String ID_TOKEN = "the-users-id-token";
    private static final String LOGOUT_SID = "session-abc";
    private static final String LOGOUT_JTI = "logout-token-jti-1";
    private static final String BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private static AxiamClient client(String base) {
        return AxiamClient.builder(base, TENANT_ID).oidcClientId(CLIENT_ID).build();
    }

    /** A VALID logout claim set; {@code tweak} breaks exactly one §12.7.3 rule. */
    private static JWTClaimsSet logoutClaims(String issuer, Consumer<JWTClaimsSet.Builder> tweak) {
        long now = System.currentTimeMillis() / 1000L;
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(CLIENT_ID)
                .subject("user-1")
                .jwtID(LOGOUT_JTI)
                .issueTime(new Date(now * 1000L))
                .expirationTime(new Date((now + 120) * 1000L))
                .claim("sid", LOGOUT_SID)
                .claim("events", Map.of(BACKCHANNEL_EVENT, Map.of()));
        tweak.accept(builder);
        return builder.build();
    }

    // -----------------------------------------------------------------------
    // §12.7.2 logoutUrl
    // -----------------------------------------------------------------------

    @Test
    void logoutUrlUsesTheDiscoveredEndpoint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.start();

            try (AxiamClient c = client(base)) {
                String url = c.logoutUrl(Sensitive.of(ID_TOKEN));

                // §12.7.2 rule 1: the endpoint comes from discovery. Code that
                // builds "{issuer}/oauth2/end_session" works against AXIAM and
                // breaks against every other OP the same app is pointed at.
                assertTrue(url.contains("/oauth2/end_session"));
                HttpUrl parsed = HttpUrl.parse(url);
                assertNotNull(parsed);
                assertEquals(ID_TOKEN, parsed.queryParameter("id_token_hint"));
            }
        }
    }

    @Test
    void logoutUrlOmitsWhatWasNotSupplied() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.start();

            try (AxiamClient c = client(base)) {
                HttpUrl bare = HttpUrl.parse(c.logoutUrl(Sensitive.of(ID_TOKEN)));
                assertNotNull(bare);
                assertNull(bare.queryParameter("post_logout_redirect_uri"));
                assertNull(bare.queryParameter("state"));

                HttpUrl full = HttpUrl.parse(c.logoutUrl(Sensitive.of(ID_TOKEN),
                        "https://app.example.com/bye", "caller-generated-state", null));
                assertNotNull(full);
                assertEquals("https://app.example.com/bye", full.queryParameter("post_logout_redirect_uri"));
                // §12.7.2 rule 2: passed through unmodified — the SDK never
                // invents one, because the value only means something to the
                // caller.
                assertEquals("caller-generated-state", full.queryParameter("state"));
            }
        }
    }

    @Test
    void logoutUrlDoesNotPreValidateTheRedirect() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.start();

            try (AxiamClient c = client(base)) {
                // §12.7.2 rule 3: the allow-list lives in the client's
                // server-side registration. A client-side copy would drift and
                // reject a URI an operator had just registered.
                HttpUrl url = HttpUrl.parse(c.logoutUrl(Sensitive.of(ID_TOKEN),
                        "https://somewhere-else.example/x", null, null));
                assertNotNull(url);
                assertEquals("https://somewhere-else.example/x",
                        url.queryParameter("post_logout_redirect_uri"));
            }
        }
    }

    @Test
    void logoutUrlErrorsWhenNoEndSessionEndpoint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponseWithoutOptionalEndpoints(base));
            server.start();

            try (AxiamClient c = client(base)) {
                AuthError error = assertThrows(AuthError.class,
                        () -> c.logoutUrl(Sensitive.of("super-secret-id-token")));
                assertTrue(error.getMessage().contains("end_session_endpoint"));
                assertFalse(error.getMessage().contains("super-secret-id-token"),
                        "the ID token must never appear in an error");
            }
        }
    }

    // -----------------------------------------------------------------------
    // §12.7.3 verifyLogoutToken
    // -----------------------------------------------------------------------

    /** Runs {@code assertion} against a client whose JWKS publishes {@code key}. */
    private static void withLogoutFixture(OctetKeyPair key, LogoutAssertion assertion) throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
            server.start();

            String issuer = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
            try (AxiamClient c = client(base)) {
                assertion.run(c, issuer);
            }
        }
    }

    @FunctionalInterface
    private interface LogoutAssertion {
        void run(AxiamClient client, String issuer) throws Exception;
    }

    @Test
    void aValidLogoutTokenSurfacesSidSubAndJti() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String token = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> { }));
            VerifiedLogoutToken verified = c.verifyLogoutToken(token, null);

            // Not a bare boolean: the RP has to know WHICH session to end, and
            // a verifier that only says "valid" forces the caller to re-parse
            // the token themselves with none of these checks.
            assertEquals(LOGOUT_SID, verified.sid());
            assertEquals("user-1", verified.sub());
            assertEquals(LOGOUT_JTI, verified.jti());
        });
    }

    @Test
    void anIdTokenReplayedAsALogoutTokenIsRejected() throws Exception {
        // The attack rules 3 and 4 exist to stop, asserted with a real,
        // otherwise-valid ID token rather than a synthetic mutation: correctly
        // signed by a published key, right issuer and audience, unexpired.
        // Only the missing `events` and the present `nonce` distinguish it.
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String idToken = OidcTestSupport.signEdDsa(key,
                    OidcTestSupport.validIdTokenClaims(issuer, CLIENT_ID, "the-request-nonce"));
            assertThrows(AuthError.class, () -> c.verifyLogoutToken(idToken, null));
        });
    }

    @Test
    void aTokenWithoutTheBackchannelEventIsRejected() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String noEvents = OidcTestSupport.signEdDsa(key,
                    logoutClaims(issuer, b -> b.claim("events", null)));
            AuthError error = assertThrows(AuthError.class, () -> c.verifyLogoutToken(noEvents, null));
            assertTrue(error.getMessage().contains("events"));

            String otherEvent = OidcTestSupport.signEdDsa(key, logoutClaims(issuer,
                    b -> b.claim("events", Map.of("http://schemas.openid.net/event/other", Map.of()))));
            assertThrows(AuthError.class, () -> c.verifyLogoutToken(otherEvent, null));
        });
    }

    @Test
    void aNonceIsRejectedNotIgnored() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String token = OidcTestSupport.signEdDsa(key,
                    logoutClaims(issuer, b -> b.claim("nonce", "n-0S6_WzA2Mj")));
            AuthError error = assertThrows(AuthError.class, () -> c.verifyLogoutToken(token, null));
            assertTrue(error.getMessage().contains("nonce"));
        });
    }

    @Test
    void aTokenNamingNeitherSidNorSubIsRejected() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String token = OidcTestSupport.signEdDsa(key,
                    logoutClaims(issuer, b -> b.claim("sid", null).subject(null)));
            AuthError error = assertThrows(AuthError.class, () -> c.verifyLogoutToken(token, null));
            assertTrue(error.getMessage().contains("identifies no session"));
        });
    }

    @Test
    void subOnlyIsAcceptedButSidIsPreferred() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String subOnly = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> b.claim("sid", null)));
            VerifiedLogoutToken verified = c.verifyLogoutToken(subOnly, null);
            assertNull(verified.sid());
            assertEquals("user-1", verified.sub());

            // With sid present the RP must end THAT session only — falling back
            // to "every session for sub" is over-reach the server itself
            // refuses.
            String both = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> { }));
            assertEquals(LOGOUT_SID, c.verifyLogoutToken(both, null).sid());
        });
    }

    @Test
    void aTokenForAnotherClientOrIssuerIsRejected() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String wrongAud = OidcTestSupport.signEdDsa(key,
                    logoutClaims(issuer, b -> b.audience("some-other-rp")));
            AuthError audError = assertThrows(AuthError.class, () -> c.verifyLogoutToken(wrongAud, null));
            assertTrue(audError.getMessage().contains("audience"));

            String wrongIss = OidcTestSupport.signEdDsa(key,
                    logoutClaims(issuer, b -> b.issuer("https://evil.example.com")));
            AuthError issError = assertThrows(AuthError.class, () -> c.verifyLogoutToken(wrongIss, null));
            assertTrue(issError.getMessage().contains("issuer"));
        });
    }

    @Test
    void aTokenSignedByAnUnpublishedKeyIsRejected() throws Exception {
        OctetKeyPair published = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        OctetKeyPair rogue = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(published, (c, issuer) -> {
            // The signature is what makes the token a statement rather than a
            // request.
            String token = OidcTestSupport.signEdDsa(rogue, logoutClaims(issuer, b -> { }));
            Exception error = assertThrows(Exception.class, () -> c.verifyLogoutToken(token, null));
            assertFalse(error.getMessage() != null && error.getMessage().contains(token),
                    "an unverifiable logout token is exactly what a naive implementation logs");
        });
    }

    @Test
    void anExpiredOrStaleTokenIsRejected() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            long now = System.currentTimeMillis() / 1000L;

            // A long-lived logout token is a replayable session-termination
            // command.
            String expired = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> b
                    .issueTime(new Date((now - 700) * 1000L))
                    .expirationTime(new Date((now - 600) * 1000L))));
            assertThrows(AuthError.class, () -> c.verifyLogoutToken(expired, null));

            // exp still ahead, but issued a day ago: a captured delivery being
            // replayed rather than a live one.
            String stale = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> b
                    .issueTime(new Date((now - 86_400) * 1000L))
                    .expirationTime(new Date((now + 600) * 1000L))));
            AuthError error = assertThrows(AuthError.class, () -> c.verifyLogoutToken(stale, null));
            assertTrue(error.getMessage().contains("too old"));
        });
    }

    @Test
    void aTokenWithoutJtiIsRejected() throws Exception {
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String token = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> b.jwtID(null)));
            AuthError error = assertThrows(AuthError.class, () -> c.verifyLogoutToken(token, null));
            assertTrue(error.getMessage().contains("jti"),
                    "without jti the RP cannot dedup at-least-once redeliveries");
        });
    }

    @Test
    void verifyingTheSameTokenTwiceDoesNotRaise() throws Exception {
        // §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid
        // token legitimately arrives twice — that is a retry, not an attack. An
        // SDK that dedupped internally would have no durable store and would
        // silently drop a real second logout after a restart, so jti is
        // surfaced for the RP to dedup on and never consumed here.
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        withLogoutFixture(key, (c, issuer) -> {
            String token = OidcTestSupport.signEdDsa(key, logoutClaims(issuer, b -> { }));
            VerifiedLogoutToken first = c.verifyLogoutToken(token, null);
            VerifiedLogoutToken second = c.verifyLogoutToken(token, null);
            assertEquals(first, second);
            assertEquals(LOGOUT_JTI, first.jti());
        });
    }
}
