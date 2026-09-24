package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Rounds out {@link ManifestAdditionsTest} with the branches its scenarios do not reach:
 * a resource CREATEd with metadata already stated, a service account's description drift,
 * and a rebind on a GROUP and on a SERVICE_ACCOUNT (that file's rebind test covers a USER).
 */
class ManifestAdditionsCoverageTest extends ManagementTestBase {

    private static final ObjectMapper OM = new ObjectMapper();
    private static final UUID RESOURCE_ID = UUID.fromString("77777777-7777-4777-8777-777777777777");
    private static final UUID ROLE_ID = UUID.fromString("66666666-6666-4666-8666-666666666666");
    private static final UUID GROUP_ID = UUID.fromString("99999999-9999-4999-8999-999999999999");
    private static final UUID SA_ID = UUID.fromString("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    private static final String STAMPS =
            "\"created_at\":\"2026-08-26T00:00:00Z\",\"updated_at\":\"2026-08-26T00:00:00Z\"";

    private static JsonNode metadata(String json) throws Exception {
        return OM.readTree(json);
    }

    private void mountEmptyTenant() {
        for (String path : List.of("resources", "permissions", "roles", "groups", "users",
                "service-accounts")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
    }

    @Test
    void createResourceCarriesStatedMetadata() throws Exception {
        mountEmptyTenant();
        Route created = mount("POST", "/api/v1/resources", 201, "{\"id\":\"" + RESOURCE_ID
                + "\",\"name\":\"documents\",\"resource_type\":\"collection\",\"parent_id\":null,"
                + "\"metadata\":{\"env\":\"prod\"},\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}");

        client.management().manifest().apply(ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .metadata("docs", metadata("{\"env\":\"prod\"}"))
                .build());

        assertEquals(metadata("{\"env\":\"prod\"}"), created.last().json().path("metadata"));
    }

    @Test
    void updateServiceAccountDescriptionDrift() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/service-accounts", 200, pageOf("{\"id\":\"" + SA_ID
                + "\",\"client_id\":\"client-" + SA_ID + "\",\"name\":\"ci-bot\","
                + "\"description\":\"old\",\"status\":\"Active\",\"tenant_id\":\"" + TENANT_ID + "\","
                + STAMPS + "}"));
        Route update = mount("PUT", "/api/v1/service-accounts/" + SA_ID, 200, "{\"id\":\"" + SA_ID
                + "\",\"client_id\":\"client-" + SA_ID + "\",\"name\":\"ci-bot\","
                + "\"description\":\"new\",\"status\":\"Active\",\"tenant_id\":\"" + TENANT_ID + "\","
                + STAMPS + "}");

        ApplyReport report = client.management().manifest()
                .apply(ManagementManifest.builder().serviceAccount("bot", "ci-bot", "new").build());

        assertTrue(report.isComplete());
        assertEquals(ApplyReport.Status.UPDATED, report.steps().get(0).outcome().status());
        assertEquals("new", update.last().json().path("description").asText());
        assertEquals(List.of("description"), update.last().keys());
    }

    @Test
    void aRebindOnAGroupUnassignsThenAssigns() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/resources", 200, pageOf("{\"id\":\"" + RESOURCE_ID
                + "\",\"name\":\"documents\",\"resource_type\":\"collection\",\"parent_id\":null,"
                + "\"metadata\":{},\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}"));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200, "[]");
        mount("GET", "/api/v1/groups", 200, pageOf("{\"id\":\"" + GROUP_ID
                + "\",\"name\":\"Staff\",\"description\":\"Everyone\",\"metadata\":{},"
                + "\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}"));
        // Existing: a PLAIN (tenant-wide) binding. Desired: scoped to the resource,
        // non-inheriting — a drift on BOTH resource and inherit at once.
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200,
                "[{\"group\":{\"id\":\"" + GROUP_ID + "\",\"name\":\"Staff\",\"description\":\"Everyone\","
                        + "\"metadata\":{},\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS
                        + "},\"resource_id\":null,\"inherit\":true}]");
        mount("GET", "/api/v1/groups/" + GROUP_ID + "/members", 200, pageOf(null));
        mount("DELETE", "/api/v1/roles/" + ROLE_ID + "/groups/" + GROUP_ID, 204, "");
        Route assign = mount("POST", "/api/v1/roles/" + ROLE_ID + "/groups", 204, "");

        ApplyReport report = client.management().manifest().apply(ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .group("staff", "Staff", "Everyone")
                .role("editor", "Editor", "Edits")
                .groupRole("staff", ManagementManifest.RoleBinding.scoped("editor", "docs", false))
                .build());

        assertTrue(report.isComplete(), () -> "" + report.failure());
        assertEquals(1, assign.calls());
        assertEquals(RESOURCE_ID.toString(), assign.last().json().path("resource_id").asText());
        assertFalse(assign.last().json().path("inherit").asBoolean(true));
    }

    @Test
    void aRebindOnAServiceAccountUnassignsThenAssigns() throws Exception {
        mountEmptyTenant();
        mount("GET", "/api/v1/resources", 200, pageOf("{\"id\":\"" + RESOURCE_ID
                + "\",\"name\":\"documents\",\"resource_type\":\"collection\",\"parent_id\":null,"
                + "\"metadata\":{},\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}"));
        mount("GET", "/api/v1/resources/" + RESOURCE_ID + "/scopes", 200, pageOf(null));
        mount("GET", "/api/v1/roles", 200, pageOf(roleBody(ROLE_ID, "Editor", "Edits")));
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/permissions", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/users", 200, "[]");
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/groups", 200, "[]");
        mount("GET", "/api/v1/service-accounts", 200, pageOf("{\"id\":\"" + SA_ID
                + "\",\"client_id\":\"client-" + SA_ID + "\",\"name\":\"ci-bot\",\"description\":null,"
                + "\"status\":\"Active\",\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS + "}"));
        // Existing: PLAIN, inheriting. Desired: scoped to the resource, non-inheriting.
        mount("GET", "/api/v1/roles/" + ROLE_ID + "/service-accounts", 200,
                "[{\"service_account\":{\"id\":\"" + SA_ID + "\",\"client_id\":\"client-" + SA_ID
                        + "\",\"name\":\"ci-bot\",\"description\":null,\"status\":\"Active\","
                        + "\"tenant_id\":\"" + TENANT_ID + "\"," + STAMPS
                        + "},\"resource_id\":null,\"inherit\":true}]");
        mount("DELETE", "/api/v1/roles/" + ROLE_ID + "/service-accounts/" + SA_ID, 204, "");
        Route assign = mount("POST", "/api/v1/roles/" + ROLE_ID + "/service-accounts", 204, "");

        ApplyReport report = client.management().manifest().apply(ManagementManifest.builder()
                .resource("docs", "documents", "collection")
                .role("editor", "Editor", "Edits")
                .serviceAccount("bot", "ci-bot", null)
                .assignServiceAccountRole("bot", ManagementManifest.RoleBinding.scoped("editor", "docs", false))
                .build());

        assertTrue(report.isComplete(), () -> "" + report.failure());
        assertEquals(1, assign.calls());
        assertEquals(RESOURCE_ID.toString(), assign.last().json().path("resource_id").asText());
    }
}
