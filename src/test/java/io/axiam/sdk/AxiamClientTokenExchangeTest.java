package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.ExchangedToken;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Token Exchange (RFC 8693) — CONTRACT.md &sect;15.
 *
 * <p>Most of &sect;15 is a list of things an SDK must <em>not</em> helpfully
 * do, so most of these tests assert an absence: no defaulted
 * {@code actorToken}, no auto-narrow after {@code invalid_scope}, no
 * synthesised refresh token, no adoption.
 */
class AxiamClientTokenExchangeTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String SUBJECT_TOKEN = "subject-token-value";
    private static final String ACTOR_TOKEN = "actor-token-value";
    private static final String ISSUED_TOKEN = "issued-narrow-token";

    private static MockResponse exchangeResponse(String scope, boolean withRefreshToken) {
        StringBuilder body = new StringBuilder("{")
                .append("\"access_token\":\"").append(ISSUED_TOKEN).append("\",")
                .append("\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",")
                .append("\"token_type\":\"Bearer\",")
                .append("\"expires_in\":300");
        if (scope != null) {
            body.append(",\"scope\":\"").append(scope).append("\"");
        }
        if (withRefreshToken) {
            body.append(",\"refresh_token\":\"should-not-exist\"");
        }
        body.append("}");
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body.toString());
    }

    private static AxiamClient.Builder confidential(String base) {
        return AxiamClient.builder(base, TENANT_ID)
                .oidcClientId("api-gateway")
                .oidcClientSecret("gateway-secret");
    }

    @Test
    void exchangeSendsTheRfc8693GrantAndAuthenticates() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse("orders:read", false));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                ExchangedToken result = client.tokenExchange(Sensitive.of(SUBJECT_TOKEN), null,
                        List.of("orders:read", "orders:write"), "orders-service", null, null, null);

                server.takeRequest();
                String body = server.takeRequest().getBody().readUtf8();

                assertTrue(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"));
                assertTrue(body.contains("subject_token=" + SUBJECT_TOKEN));
                assertTrue(body.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"));
                assertTrue(body.contains("scope=orders%3Aread+orders%3Awrite"));
                assertTrue(body.contains("audience=orders-service"));
                assertTrue(body.contains("client_secret=gateway-secret"),
                        "§15.1: the exchanging client is confidential and authenticates");

                assertEquals(ISSUED_TOKEN, result.accessToken().expose());
                assertEquals("urn:ietf:params:oauth:token-type:access_token", result.issuedTokenType(),
                        "§15.2 rule 6: issued_token_type is surfaced, not dropped");
            }
        }
    }

    @Test
    void aPublicClientFailsBeforeAnyWireCall() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("api-gateway").build()) {
                assertThrows(AuthError.class,
                        () -> client.tokenExchange(Sensitive.of(SUBJECT_TOKEN)));
                // Only discovery went out.
                assertEquals(1, server.getRequestCount());
            }
        }
    }

    @Test
    void absentActorTokenIsNeverDefaulted() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse("orders:read", false));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                client.tokenExchange(Sensitive.of(SUBJECT_TOKEN));

                server.takeRequest();
                String body = server.takeRequest().getBody().readUtf8();

                // §15.2 rule 1: passing no actor token asks for IMPERSONATION.
                // An SDK that helpfully substituted its own session token would
                // silently turn that into a delegation — a different operation
                // with different risk.
                assertFalse(body.contains("actor_token"));
            }
        }
    }

    @Test
    void actorTokenAndTypeAreSentAsAPair() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse(null, false));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                client.tokenExchange(Sensitive.of(SUBJECT_TOKEN), Sensitive.of(ACTOR_TOKEN),
                        null, null, null, null, null);

                server.takeRequest();
                String body = server.takeRequest().getBody().readUtf8();

                assertTrue(body.contains("actor_token=" + ACTOR_TOKEN));
                // RFC 8693 §2.1 requires the pair; the type alone is a
                // malformed request.
                assertTrue(body.contains("actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"));
            }
        }
    }

    @Test
    void theSixErrorCodesReachTheCallerUnchanged() throws Exception {
        // Including cross-tenant, which the server deliberately collapses into
        // invalid_grant — the SDK must not re-derive the distinction it
        // withheld (that is a tenant-enumeration signal).
        for (String code : List.of("invalid_request", "invalid_grant", "invalid_scope",
                "invalid_target", "unauthorized_client")) {
            try (MockWebServer server = new MockWebServer()) {
                String base = server.url("/").toString();
                server.enqueue(OidcTestSupport.discoveryResponse(base));
                server.enqueue(OidcTestSupport.oauthError(400, code));
                server.start();

                try (AxiamClient client = confidential(base).build()) {
                    OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                            () -> client.tokenExchange(Sensitive.of(SUBJECT_TOKEN), null,
                                    List.of("orders:read", "orders:admin"), null, null, null, null));

                    assertEquals(code, error.error());
                    // §15.2 rules 2-3: no retry, no downgrade, no
                    // auto-narrowing. The server refuses rather than silently
                    // narrowing precisely so the caller finds out HERE.
                    assertEquals(2, server.getRequestCount());
                }
            }
        }
    }

    @Test
    void aServerSentRefreshTokenIsNotSurfaced() throws Exception {
        // Deliberately hostile fixture: RFC 8693 issues no refresh token, so
        // the record has no component for one and there is nothing to
        // synthesise.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse("orders:read", true));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                ExchangedToken result = client.tokenExchange(Sensitive.of(SUBJECT_TOKEN));
                assertFalse(result.toString().contains("should-not-exist"));
                assertEquals(ISSUED_TOKEN, result.accessToken().expose());
            }
        }
    }

    @Test
    void theGrantedScopeIsReadableWhenNarrowerThanRequested() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse("orders:read", false));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                ExchangedToken result = client.tokenExchange(Sensitive.of(SUBJECT_TOKEN), null,
                        List.of("orders:read", "orders:write"), null, null, null, null);

                // §15.2 rule 7: the response scope is the GRANTED set and may
                // be narrower than requested even on success.
                assertEquals("orders:read", result.scope());
            }
        }
    }

    @Test
    void anAbsentScopeIsNull() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse(null, false));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                assertNull(client.tokenExchange(Sensitive.of(SUBJECT_TOKEN)).scope());
            }
        }
    }

    @Test
    void theIssuedTokenIsRedacted() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(exchangeResponse("orders:read", false));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                ExchangedToken result = client.tokenExchange(Sensitive.of(SUBJECT_TOKEN));
                assertFalse(result.toString().contains(ISSUED_TOKEN),
                        "§15.5: the issued token is a bearer credential and must not render");
                assertFalse(result.accessToken().toString().contains(ISSUED_TOKEN));
            }
        }
    }

    @Test
    void aFailedExchangeNeverEchoesTheSubjectToken() throws Exception {
        // §15.5 calls this out specifically: an exchange failure is exactly
        // when a naive implementation logs the request body.
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.oauthError(400, "invalid_grant"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.tokenExchange(Sensitive.of(SUBJECT_TOKEN), Sensitive.of(ACTOR_TOKEN),
                                null, null, null, null, null));

                assertFalse(error.getMessage().contains(SUBJECT_TOKEN));
                assertFalse(error.getMessage().contains(ACTOR_TOKEN));
            }
        }
    }
}
