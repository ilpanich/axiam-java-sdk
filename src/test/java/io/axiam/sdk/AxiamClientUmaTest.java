package io.axiam.sdk;

import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.RequestedPermission;
import io.axiam.sdk.oidc.RequestingPartyToken;
import io.axiam.sdk.oidc.ResourceSet;
import io.axiam.sdk.oidc.UmaChallenge;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * UMA 2.0 — CONTRACT.md &sect;20.7 required assertions.
 *
 * <p>Most of &sect;20, like &sect;15, is a list of things an SDK must
 * <em>not</em> helpfully do, so most of these tests assert an absence. The
 * centrepiece is &sect;20.2 rule 6: a permission ticket must never be retried.
 *
 * <p>That rule is the one &sect;16 exception in the contract, and the only way
 * to assert it is to count requests. A ticket is consumed <em>before</em> the
 * request is evaluated, so a failed exchange has already spent it — and under
 * concurrency a retry is precisely the second redemption that
 * ilpanich/axiam#302's measured residual describes. "Exactly one request" is a
 * security assertion here, not a performance one.
 *
 * <p>Every test is named after the thing it stops.
 */
class AxiamClientUmaTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String PAT = "pat-token-value";
    private static final String TICKET = "ticket-value";
    private static final String CLAIM_TOKEN = "claim-token-value";
    private static final UUID RESOURCE_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");

    private static AxiamClient.Builder confidential(String base) {
        return AxiamClient.builder(base, TENANT_ID)
                .oidcClientId("resource-server-1")
                .oidcClientSecret("rs-secret");
    }

    private static MockResponse json(int code, String body) {
        return new MockResponse()
                .setResponseCode(code)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    private static MockResponse rptResponse() {
        return json(200, "{\"access_token\":\"rpt-value\",\"token_type\":\"Bearer\",\"expires_in\":300}");
    }

    // -----------------------------------------------------------------------
    // §20.2 rule 6 — the ticket grant is never retried
    // -----------------------------------------------------------------------

    /**
     * A {@code 500} must not be retried. The ticket is spent whether or not the
     * exchange succeeded, so a retry cannot succeed — and it is the concurrent
     * redemption ilpanich/axiam#302 measures.
     */
    @Test
    void a5xxOnTheTicketGrantIsNotRetried() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(500));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                assertThrows(RuntimeException.class, () -> client.umaExchangeTicket(
                        Sensitive.of(TICKET), Sensitive.of(CLAIM_TOKEN), null, null));
            }

            // Discovery plus exactly one token request — no retry.
            assertEquals(2, server.getRequestCount(),
                    "the ticket grant must issue exactly one request — retrying a spent "
                            + "ticket is the concurrent redemption ilpanich/axiam#302 describes");
        }
    }

    /** {@code invalid_grant} is what a replayed ticket gets, and it is not retried either. */
    @Test
    void anInvalidGrantOnTheTicketGrantIsNotRetried() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(json(400, "{\"error\":\"invalid_grant\","
                    + "\"error_description\":\"permission ticket is invalid, expired, or already used\"}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.umaExchangeTicket(Sensitive.of(TICKET),
                                Sensitive.of(CLAIM_TOKEN), null, null));
                assertEquals("invalid_grant", error.error());
            }

            assertEquals(2, server.getRequestCount());
        }
    }

    /**
     * {@code access_denied} arrives as <strong>403</strong> on this grant
     * (UMA 2.0 &sect;3.3.6), unlike RFC 8628's, which is a 400. The SDK
     * dispatches on the {@code error} field, so the code reaches the caller
     * either way — and the refusal is not auto-narrowed into a smaller ticket
     * request (&sect;20.2 rule 3).
     */
    @Test
    void accessDeniedSurfacesAsItselfAndIsNotAutoNarrowed() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(json(403, "{\"error\":\"access_denied\","
                    + "\"error_description\":\"the requesting party is not authorized for "
                    + "every requested permission\"}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                OAuthProtocolError error = assertThrows(OAuthProtocolError.class,
                        () -> client.umaExchangeTicket(Sensitive.of(TICKET),
                                Sensitive.of(CLAIM_TOKEN), null, null));
                assertEquals("access_denied", error.error(),
                        "the 403 must not be flattened into a generic authorization error");
            }

            assertEquals(2, server.getRequestCount(),
                    "a refused ticket must not be re-requested with fewer scopes");
        }
    }

    // -----------------------------------------------------------------------
    // The ticket grant's wire shape
    // -----------------------------------------------------------------------

    @Test
    void theGrantSendsTheRequiredClaimTokenAndFormat() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(rptResponse());
            server.start();

            RequestingPartyToken rpt;
            try (AxiamClient client = confidential(base).build()) {
                rpt = client.umaExchangeTicket(Sensitive.of(TICKET), Sensitive.of(CLAIM_TOKEN),
                        null, null);
            }

            server.takeRequest();
            RecordedRequest grant = server.takeRequest();
            String body = grant.getBody().readUtf8();
            assertTrue(body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket"),
                    "unexpected body: " + body);
            assertTrue(body.contains("ticket=" + TICKET), "unexpected body: " + body);
            assertTrue(body.contains("claim_token=" + CLAIM_TOKEN), "unexpected body: " + body);
            assertTrue(body.contains("claim_token_format="), "unexpected body: " + body);

            assertEquals("rpt-value", rpt.accessToken().expose());
            assertEquals(300, rpt.expiresIn());
        }
    }

    /**
     * &sect;20.2 rule 5: the grant issues no refresh token, so the record has
     * no component for one — an application that wants a fresh RPT re-runs the
     * grant. Asserted structurally, because a field that does not exist cannot
     * be populated by a server that sends one anyway.
     */
    @Test
    void theRptRecordCannotCarryARefreshToken() {
        assertTrue(java.util.Arrays.stream(RequestingPartyToken.class.getRecordComponents())
                        .noneMatch(c -> c.getName().toLowerCase(java.util.Locale.ROOT)
                                .contains("refresh")),
                "RequestingPartyToken must have no refresh-token component");
    }

    // -----------------------------------------------------------------------
    // The Protection API
    // -----------------------------------------------------------------------

    /**
     * The UMA {@code _id} <strong>is</strong> the AXIAM resource id — there is
     * no parallel identifier to translate through.
     */
    @Test
    void aRegisteredIdIsUsableAsATicketResourceId() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(json(201, "{\"_id\":\"" + RESOURCE_ID + "\",\"name\":\"invoice-7\","
                    + "\"type\":\"document\",\"resource_scopes\":[\"view\"]}"));
            server.enqueue(json(201, "{\"ticket\":\"" + TICKET + "\"}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                ResourceSet registered = client.umaRegisterResource(Sensitive.of(PAT),
                        ResourceSet.of("invoice-7", "document", List.of("view")));
                assertEquals(RESOURCE_ID, registered.id());

                Sensitive ticket = client.umaRequestTicket(Sensitive.of(PAT),
                        List.of(RequestedPermission.of(registered.id(), List.of("view"))));
                assertEquals(TICKET, ticket.expose());
            }

            server.takeRequest();
            RecordedRequest perm = server.takeRequest();
            String body = perm.getBody().readUtf8();
            assertTrue(body.contains("\"resource_id\":\"" + RESOURCE_ID + "\""),
                    "unexpected body: " + body);
        }
    }

    @Test
    void thePatIsSentAsABearerToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(json(201, "{\"ticket\":\"" + TICKET + "\"}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                client.umaRequestTicket(Sensitive.of(PAT),
                        List.of(RequestedPermission.of(RESOURCE_ID, List.of("view"))));
            }

            RecordedRequest request = server.takeRequest();
            assertEquals("Bearer " + PAT, request.getHeader("Authorization"));
        }
    }

    /**
     * &sect;20.2 rule 8: an update replaces the scope list. Only one response is
     * enqueued, so a read-modify-write implementation would hang or fail here
     * rather than pass quietly.
     */
    @Test
    void anUpdateSendsOnlyTheScopesGivenAndDoesNotReadFirst() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(json(200, "{\"_id\":\"" + RESOURCE_ID + "\",\"name\":\"invoice-7\","
                    + "\"resource_scopes\":[\"view\"]}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                client.umaUpdateResource(Sensitive.of(PAT), RESOURCE_ID,
                        ResourceSet.of("invoice-7", "document", List.of("view")));
            }

            assertEquals(1, server.getRequestCount(), "no read-before-write");
            RecordedRequest request = server.takeRequest();
            assertEquals("PUT", request.getMethod());
            assertTrue(request.getBody().readUtf8().contains("\"resource_scopes\":[\"view\"]"));
        }
    }

    /**
     * Omitting the key would leave the server's copy untouched, which would
     * make clearing a scope set impossible through the SDK.
     */
    @Test
    void anUpdateThatDropsEveryScopeStillSendsTheKey() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(json(200, "{\"_id\":\"" + RESOURCE_ID + "\",\"name\":\"invoice-7\","
                    + "\"resource_scopes\":[]}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                client.umaUpdateResource(Sensitive.of(PAT), RESOURCE_ID,
                        ResourceSet.of("invoice-7"));
            }

            RecordedRequest request = server.takeRequest();
            assertTrue(request.getBody().readUtf8().contains("\"resource_scopes\":[]"));
        }
    }

    @Test
    void aNonPatRefusalReachesTheCaller() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(json(403, "{\"error\":\"authorization_denied\","
                    + "\"message\":\"the protection API requires the 'uma_protection' scope\"}"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                assertThrows(RuntimeException.class, () -> client.umaRequestTicket(
                        Sensitive.of("not-a-pat"),
                        List.of(RequestedPermission.of(RESOURCE_ID, List.of("view")))));
            }

            assertEquals(1, server.getRequestCount());
        }
    }

    @Test
    void theListingReturnsIds() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(json(200, "[\"" + RESOURCE_ID + "\"]"));
            server.start();

            try (AxiamClient client = confidential(base).build()) {
                assertEquals(List.of(RESOURCE_ID), client.umaListResources(Sensitive.of(PAT)));
            }
        }
    }

    // -----------------------------------------------------------------------
    // §20.3 the challenge helpers
    // -----------------------------------------------------------------------

    @Test
    void parsesAWellFormedChallenge() {
        UmaChallenge parsed = UmaChallenge.parse(
                "UMA realm=\"example\", as_uri=\"https://id.example\", ticket=\"" + TICKET + "\"");
        assertNotNull(parsed);
        assertEquals("example", parsed.realm());
        assertEquals("https://id.example", parsed.asUri());
        assertNotNull(parsed.ticket());
        assertEquals(TICKET, parsed.ticket().expose());
    }

    @Test
    void rejectsASchemeThatMerelyStartsWithUma() {
        assertNull(UmaChallenge.parse("Bearer realm=\"example\""));
        assertNull(UmaChallenge.parse("UMAX realm=\"example\""));
    }

    @Test
    void theChallengeRoundTripsThroughTheEmitHalf() {
        String header = UmaChallenge.header("example", "https://id.example", Sensitive.of(TICKET));
        UmaChallenge parsed = UmaChallenge.parse(header);
        assertNotNull(parsed);
        assertEquals("https://id.example", parsed.asUri());
        assertNotNull(parsed.ticket());
        assertEquals(TICKET, parsed.ticket().expose());
    }

    /** &sect;20.6: the ticket's 60-second life is exactly what invites logging it. */
    @Test
    void theTicketIsRedactedInToString() {
        UmaChallenge parsed = UmaChallenge.parse("UMA ticket=\"super-secret-ticket\"");
        assertNotNull(parsed);
        assertFalse(parsed.toString().contains("super-secret-ticket"),
                "the ticket must be redacted in toString, got: " + parsed);
    }
}
