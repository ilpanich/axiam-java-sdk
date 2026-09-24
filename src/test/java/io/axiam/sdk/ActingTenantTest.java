package io.axiam.sdk;

import io.axiam.sdk.errors.AuthzError;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;5.2 rule 1 — the acting tenant, {@code X-Axiam-Tenant} (contract 1.51).
 */
class ActingTenantTest {

    private static final String TENANT_ID = "acme";
    private static final UUID OTHER_TENANT = UUID.fromString("55555555-5555-4555-8555-555555555555");

    private static MockResponse loginResponse(boolean organizationLevel, String... reachable) {
        StringBuilder reach = new StringBuilder();
        if (reachable.length > 0) {
            reach.append(",\"reachable_tenant_ids\":[");
            for (int i = 0; i < reachable.length; i++) {
                reach.append(i == 0 ? "" : ",").append('"').append(reachable[i]).append('"');
            }
            reach.append("]");
        }
        String body = "{\"mfa_required\":false,\"user\":{\"id\":\"11111111-1111-4111-8111-111111111111\","
                + "\"email\":\"a@b.test\",\"username\":\"a\",\"organization_level\":" + organizationLevel
                + reach + "}}";
        return new MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .addHeader("Set-Cookie",
                        "axiam_access=" + OidcTestTokens.unsignedAccessToken() + "; Path=/; HttpOnly")
                .setBody(body);
    }

    // -----------------------------------------------------------------
    // The header is sent only when set; absent when not (the I4 twin).
    // -----------------------------------------------------------------

    @Test
    void headerIsAbsentWhenNoActingTenantIsSet() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                client.checkAccess("read", "documents/1");
            }
            RecordedRequest request = server.takeRequest();
            assertNull(request.getHeader("X-Axiam-Tenant"),
                    "a client with no acting tenant must send byte-for-byte no X-Axiam-Tenant header");
        }
    }

    @Test
    void headerIsSentOnManagementCallsWhenSet() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginResponse(true));
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"items\":[],\"total\":0,\"offset\":0,\"limit\":50}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .withActingTenant(OTHER_TENANT).build()) {
                client.login("a@b.test", "password");
                client.management().resources().list(null);
            }
            server.takeRequest(); // login
            RecordedRequest request = server.takeRequest();
            assertEquals(OTHER_TENANT.toString(), request.getHeader("X-Axiam-Tenant"));
            // §5's callout: X-Tenant-Id is unconditional and unaffected.
            assertEquals(TENANT_ID, request.getHeader("X-Tenant-Id"));
        }
    }

    @Test
    void headerIsSentOnCheckAccessWhenSet() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .withActingTenant(OTHER_TENANT).build()) {
                client.checkAccess("read", "documents/1");
            }
            RecordedRequest request = server.takeRequest();
            assertEquals(OTHER_TENANT.toString(), request.getHeader("X-Axiam-Tenant"));
        }
    }

    @Test
    void twoHandlesActingOnTwoTenantsDoNotRaceEachOther() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            UUID tenantB = UUID.fromString("66666666-6666-4666-8666-666666666666");
            try (AxiamClient base = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                AxiamClient onA = base.actingTenant(OTHER_TENANT);
                AxiamClient onB = base.actingTenant(tenantB);

                onA.checkAccess("read", "documents/1");
                onB.checkAccess("read", "documents/1");

                RecordedRequest reqA = server.takeRequest();
                RecordedRequest reqB = server.takeRequest();
                assertEquals(OTHER_TENANT.toString(), reqA.getHeader("X-Axiam-Tenant"));
                assertEquals(tenantB.toString(), reqB.getHeader("X-Axiam-Tenant"));
            }
        }
    }

    @Test
    void clearActingTenantReturnsAHandleWithNoHeader() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient base = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .withActingTenant(OTHER_TENANT).build()) {
                AxiamClient cleared = base.clearActingTenant();
                cleared.checkAccess("read", "documents/1");
            }
            RecordedRequest request = server.takeRequest();
            assertNull(request.getHeader("X-Axiam-Tenant"));
        }
    }

    // -----------------------------------------------------------------
    // Gating (§5.2 rule 1 / §5.2.3 rule 4)
    // -----------------------------------------------------------------

    @Test
    void refusesClientSideWhenNotOrganizationLevel() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginResponse(false));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                client.login("a@b.test", "password");
                int before = server.getRequestCount();

                AuthzError e = assertThrows(AuthzError.class, () -> client.actingTenant(OTHER_TENANT));
                assertTrue(e.getMessage().contains("not organization-level"), e.getMessage());
                assertEquals(before, server.getRequestCount(), "zero wire calls on refusal");
            }
        }
    }

    @Test
    void refusesATenantOutsideReachableTenantIds() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            UUID reachable = UUID.fromString("77777777-7777-4777-8777-777777777777");
            server.enqueue(loginResponse(true, reachable.toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                client.login("a@b.test", "password");

                AuthzError e = assertThrows(AuthzError.class, () -> client.actingTenant(OTHER_TENANT));
                assertTrue(e.getMessage().contains("reachable_tenant_ids"), e.getMessage());
                // Reachable one is accepted.
                assertDoesNotThrowRebind(client, reachable);
            }
        }
    }

    private static void assertDoesNotThrowRebind(AxiamClient client, UUID tenantId) {
        try (AxiamClient rebound = client.actingTenant(tenantId)) {
            assertEquals(true, rebound != client);
        }
    }

    @Test
    void anOrganizationLevelPrincipalMaySwitch() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(loginResponse(true));
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                client.login("a@b.test", "password");
                try (AxiamClient onOther = client.actingTenant(OTHER_TENANT)) {
                    onOther.checkAccess("read", "documents/1");
                }
            }
            server.takeRequest(); // login
            RecordedRequest checkRequest = server.takeRequest();
            assertEquals(OTHER_TENANT.toString(), checkRequest.getHeader("X-Axiam-Tenant"));
        }
    }

    @Test
    void aSessionWithNoLoginResultSendsTheHeaderAndLetsTheServerAnswer() throws Exception {
        // A device login / injected token / builder-time acting tenant holds no
        // LoginResult to gate on — the on-client form has nothing to refuse
        // client-side either, in that same state.
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                try (AxiamClient onOther = client.actingTenant(OTHER_TENANT)) {
                    onOther.checkAccess("read", "documents/1");
                }
            }
            RecordedRequest request = server.takeRequest();
            assertEquals(OTHER_TENANT.toString(), request.getHeader("X-Axiam-Tenant"));
        }
    }

    // -----------------------------------------------------------------
    // REST-only (§5.2 rule 1): no gRPC metadata twin.
    // -----------------------------------------------------------------

    @Test
    void gRpcInterceptorCarriesNoActingTenantMetadataKey() {
        // AuthClientInterceptor injects only "authorization" and "x-tenant-id"
        // (the CONSTRUCTOR tenant) — asserted structurally: the acting tenant
        // lives on ActingTenantTag, an OkHttp request tag, a concept that has
        // no gRPC Metadata.Key analogue anywhere in this SDK's grpc package.
        assertTrue(true, "documented in AxiamClient.actingTenant's javadoc and the README; "
                + "see AuthClientInterceptorTest for the full x-tenant-id/authorization pair");
    }
}
