package io.axiam.sdk;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Decision reason codes — CONTRACT.md &sect;11 rule 9 (B1 deny-override).
 *
 * <p>The rule exists because the two refusals mean <strong>opposite things to
 * the person on the other end</strong>: {@code no_grant} says <em>ask an admin
 * for access</em>, {@code denied_by_rule} says <em>an admin has already
 * decided</em>. An application that cannot tell them apart sends users to
 * raise tickets that will be refused.
 */
class AxiamClientReasonCodeTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String RESOURCE_ID = "11111111-2222-3333-4444-555555555555";

    private static MockResponse json(String body) {
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    private static AxiamClient.AccessResult check(String body) throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json(body));
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                return client.checkAccess("read", RESOURCE_ID);
            }
        }
    }

    @Test
    void anAllowSurfacesTheAllowedReasonCode() throws Exception {
        AxiamClient.AccessResult result = check("{\"allowed\":true,\"reason_code\":\"allowed\"}");
        assertTrue(result.allowed());
        assertEquals("allowed", result.reasonCode());
    }

    @Test
    void noGrantAndDeniedByRuleAreNotCollapsed() throws Exception {
        AxiamClient.AccessResult noGrant = check("{\"allowed\":false,\"reason_code\":\"no_grant\"}");
        AxiamClient.AccessResult byRule = check("{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}");

        // Both are refusals…
        assertFalse(noGrant.allowed());
        assertFalse(byRule.allowed());
        // …and the SDK must not reduce them to that shared false.
        assertEquals("no_grant", noGrant.reasonCode());
        assertEquals("denied_by_rule", byRule.reasonCode());
        assertNotEquals(noGrant.reasonCode(), byRule.reasonCode());
    }

    @Test
    void anUnknownReasonCodeIsSurfacedVerbatimAndChangesNothing() throws Exception {
        // §11 rule 9: an SDK that does not recognise a code MUST surface it
        // unchanged and MUST NOT let it affect the outcome, which `allowed`
        // carries alone. This is what lets the server add a fourth code
        // without breaking every deployed SDK.
        AxiamClient.AccessResult denied =
                check("{\"allowed\":false,\"reason_code\":\"denied_by_some_future_thing\"}");
        assertFalse(denied.allowed());
        assertEquals("denied_by_some_future_thing", denied.reasonCode());

        AxiamClient.AccessResult allowed =
                check("{\"allowed\":true,\"reason_code\":\"something-unrecognised\"}");
        assertTrue(allowed.allowed(), "an unknown code must not flip an allow");
    }

    @Test
    void anOlderServerOmittingTheFieldIsNotAnError() throws Exception {
        // A newer SDK against an older server: the field is simply absent, and
        // that MUST degrade to today's behaviour rather than failing to parse.
        AxiamClient.AccessResult denied = check("{\"allowed\":false}");
        assertFalse(denied.allowed());
        assertNull(denied.reasonCode());

        AxiamClient.AccessResult allowed = check("{\"allowed\":true,\"reason\":\"role grants it\"}");
        assertTrue(allowed.allowed());
        assertNull(allowed.reasonCode());
        assertEquals("role grants it", allowed.reason());
    }

    @Test
    void canStillReturnsFalseForBothRefusals() throws Exception {
        // §11 rule 9 is about REPORTING, not enforcement: `can` is the "just
        // tell me yes or no" helper and both refusals answer false
        // identically. An SDK must not start varying enforcement on the code.
        for (String code : List.of("no_grant", "denied_by_rule")) {
            try (MockWebServer server = new MockWebServer()) {
                server.enqueue(json("{\"allowed\":false,\"reason_code\":\"" + code + "\"}"));
                server.start();
                try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                    assertFalse(client.can("read", RESOURCE_ID));
                }
            }
        }
    }

    @Test
    void batchCheckSurfacesAReasonCodePerDecision() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(json("{\"results\":["
                    + "{\"allowed\":true,\"reason_code\":\"allowed\"},"
                    + "{\"allowed\":false,\"reason_code\":\"no_grant\"},"
                    + "{\"allowed\":false,\"reason_code\":\"denied_by_rule\"}]}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                List<AxiamClient.AccessResult> results = client.batchCheck(List.of(
                        new AxiamClient.AccessCheck("read", RESOURCE_ID, null),
                        new AxiamClient.AccessCheck("write", RESOURCE_ID, null),
                        new AxiamClient.AccessCheck("delete", RESOURCE_ID, null)));

                assertEquals(3, results.size());
                assertEquals("allowed", results.get(0).reasonCode());
                assertEquals("no_grant", results.get(1).reasonCode());
                assertEquals("denied_by_rule", results.get(2).reasonCode());
            }
        }
    }
}
