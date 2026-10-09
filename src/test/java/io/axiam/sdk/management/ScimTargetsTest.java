package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.internal.ManagementTransport;
import io.axiam.sdk.management.models.DeprovisionPolicy;
import io.axiam.sdk.management.models.ScimReconcileAccepted;
import io.axiam.sdk.management.models.ScimTargetAuthBearer;
import io.axiam.sdk.management.models.ScimTargetAuthOauth2ClientCredentials;
import io.axiam.sdk.management.models.ScimTargetAuthUnknown;
import io.axiam.sdk.management.models.ScimTargetInput;
import io.axiam.sdk.management.models.ScimTargetResponse;
import io.axiam.sdk.management.models.ScimTargetScopeAllUsers;
import io.axiam.sdk.management.models.ScimTargetScopeGroups;
import io.axiam.sdk.management.models.UserNameSource;
import io.axiam.sdk.testutil.Redaction;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code scim_targets} management namespace &mdash; CONTRACT.md &sect;31.8's
 * six required tests. The credential is generated at run time.
 */
class ScimTargetsTest extends ManagementTestBase {

    private static final String TARGETS = "/api/v1/scim-targets";

    private static String credential() {
        return "scim-" + UUID.randomUUID().toString().replace("-", "");
    }

    private static ObjectNode targetBody() {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("name", "Downstream");
        b.put("base_url", "https://idp.example/scim/v2");
        b.put("enabled", true);
        b.putObject("auth").put("type", "bearer");
        b.putObject("scope").put("type", "all_users");
        b.put("push_groups", false);
        b.put("user_name_from", "username");
        b.put("deprovision", "deactivate");
        b.put("created_at", "2026-10-05T00:00:00Z");
        b.put("updated_at", "2026-10-05T00:00:00Z");
        ObjectNode state = b.putObject("state");
        state.putNull("last_success_at");
        state.putNull("last_failure_at");
        state.putNull("last_failure_reason");
        state.put("consecutive_failures", 0);
        state.put("dead_lettered_total", 0);
        state.putNull("last_reconciled_at");
        return b;
    }

    private static ScimTargetInput input(String credential) {
        return new ScimTargetInput(new ScimTargetAuthBearer("bearer"), "https://idp.example/scim/v2",
                credential == null ? null : Sensitive.of(credential), null, null, "Downstream", null,
                new ScimTargetScopeAllUsers("all_users"), null);
    }

    private static JsonNode wire(Object body) throws Exception {
        return JSON.readTree(new String(ManagementTransport.encodeBody("test", body), StandardCharsets.UTF_8));
    }

    // ── 1. Redaction ─────────────────────────────────────────────────────

    @Test
    void theCredentialIsOnTheWireAndInNoRendering() throws Exception {
        String c = credential();
        ScimTargetInput body = input(c);
        Redaction.assertNoFragment("input rendering", body + " " + JSON.writeValueAsString(body), c);

        Route post = mount("POST", TARGETS, 400,
                "{\"error\":\"validation_error\",\"message\":\"base_url: refused\"}");
        ValidationError e = assertThrows(ValidationError.class, () -> client.scimTargets().create(body));
        Redaction.assertNoFragment("error", e + " " + e.getMessage(), c);
        assertTrue(c.equals(post.last().json().path("credential").asText()), "the credential is in the body");
    }

    // ── 2. No credential on the response ─────────────────────────────────

    @Test
    void aCredentialInAResponseIsDropped() throws Exception {
        String leaked = credential();
        UUID id = UUID.randomUUID();
        ObjectNode body = targetBody();
        body.put("credential", leaked);
        body.put("credential_set", true);
        mount("GET", TARGETS + "/" + id, 200, body.toString());
        ScimTargetResponse t = client.scimTargets().get(id);
        Redaction.assertNoFragment("decoded target", t + " " + JSON.writeValueAsString(t), leaked);
        assertFalse(Arrays.stream(ScimTargetResponse.class.getRecordComponents())
                .anyMatch(rc -> rc.getName().startsWith("credential")), "no accessor for a credential");
        assertEquals("Downstream", t.name());
    }

    // ── 3. Replacement and the omitted credential ────────────────────────

    @Test
    void updateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", TARGETS + "/" + id, 200, targetBody().toString());
        String c = credential();
        client.scimTargets().update(id, input(null));
        assertFalse(put.last().json().has("credential"), "no credential key");
        client.scimTargets().update(id, input(c));
        assertTrue(c.equals(put.last().json().path("credential").asText()), "the credential is sent");
        // name, base_url, auth and scope are positional components: an input
        // without them does not compile.
        assertEquals(9, ScimTargetInput.class.getRecordComponents().length);

        assertEquals(JSON.readTree("{\"type\":\"bearer\"}"), wire(new ScimTargetAuthBearer("bearer")));
        assertEquals(JSON.readTree("{\"type\":\"oauth2_client_credentials\",\"client_id\":\"axiam\","
                        + "\"scope\":\"scim\",\"token_url\":\"https://idp.example/token\"}"),
                wire(new ScimTargetAuthOauth2ClientCredentials("oauth2_client_credentials", "axiam", "scim",
                        "https://idp.example/token")));
        assertEquals(JSON.readTree("{\"type\":\"all_users\"}"), wire(new ScimTargetScopeAllUsers("all_users")));
        UUID group = UUID.randomUUID();
        assertEquals(JSON.readTree("{\"type\":\"groups\",\"group_ids\":[\"" + group + "\"]}"),
                wire(new ScimTargetScopeGroups("groups", List.of(group))));
    }

    // ── 4. Open decoding and pagination ──────────────────────────────────

    @Test
    void unknownValuesDecodeAndThePagerCarriesSearch() throws Exception {
        ObjectNode odd = targetBody();
        ObjectNode auth = odd.putObject("auth");
        auth.put("type", "mtls");
        auth.put("certificate_id", UUID.randomUUID().toString());
        odd.put("deprovision", "archive");
        odd.put("user_name_from", "employee_number");
        odd.putNull("state");
        ObjectNode failing = targetBody();
        ObjectNode state = (ObjectNode) failing.path("state");
        state.put("last_failure_at", "2026-10-05T01:00:00Z");
        state.put("last_failure_reason", "a reason this SDK has never seen");
        state.put("consecutive_failures", 3);
        state.put("dead_lettered_total", 1);
        Route list = mountDynamic("GET", TARGETS, 200, r -> {
            int offset = Integer.parseInt(r.query().getOrDefault("offset", "0"));
            String items = offset == 0 ? odd.toString() : offset == 1 ? failing.toString() : "";
            return "{\"items\":[" + items + "],\"total\":2,\"offset\":" + offset + ",\"limit\":1}";
        });

        Page<ScimTargetResponse> page = client.scimTargets().list(PageRequest.matching(1, "downstream"));
        assertEquals(2, page.total());
        ScimTargetResponse first = page.items().get(0);
        assertInstanceOf(ScimTargetAuthUnknown.class, first.auth());
        assertEquals(DeprovisionPolicy.UNKNOWN, first.deprovision());
        assertEquals(UserNameSource.UNKNOWN, first.userNameFrom());
        assertNull(first.state());
        List<ScimTargetResponse> all = client.scimTargets().listAll(PageRequest.matching(1, "downstream"));
        assertEquals("a reason this SDK has never seen", all.get(1).state().lastFailureReason());
        for (Recorded r : list.requests()) {
            assertEquals("downstream", r.query().get("search"), "the pager carries search on every page");
        }
        // An unknown variant decodes but is never sent.
        assertThrows(NetworkError.class, () -> ManagementTransport.encodeBody("test", first.auth()));
    }

    // ── 5. No retry ──────────────────────────────────────────────────────

    @Test
    void noWriteIsRetriedOn503() {
        UUID id = UUID.randomUUID();
        List<Route> routes = List.of(
                mount("POST", TARGETS, 503, ""),
                mount("PUT", TARGETS + "/" + id, 503, ""),
                mount("DELETE", TARGETS + "/" + id, 503, ""),
                mount("POST", TARGETS + "/" + id + "/reconcile", 503, ""));
        ScimTargetsApi t = client.scimTargets();
        for (Executable write : List.<Executable>of(
                () -> t.create(input(credential())),
                () -> t.update(id, input(null)),
                () -> t.delete(id),
                () -> t.reconcile(id))) {
            NetworkError e = assertThrows(NetworkError.class, write);
            assertFalse(e instanceof ValidationError);
        }
        for (Route r : routes) {
            assertEquals(1, r.calls(), "exactly one request per write");
        }
    }

    @Test
    void noWriteIsResentAfterADroppedConnection() throws Exception {
        UUID id = UUID.randomUUID();
        ScimTargetsApi t = client.scimTargets();
        assertSentOnceOverADroppedConnection("POST", TARGETS, () -> t.create(input(credential())));
        assertSentOnceOverADroppedConnection("PUT", TARGETS + "/" + id, () -> t.update(id, input(null)));
        assertSentOnceOverADroppedConnection("DELETE", TARGETS + "/" + id, () -> t.delete(id));
        assertSentOnceOverADroppedConnection("POST", TARGETS + "/" + id + "/reconcile", () -> t.reconcile(id));
    }

    // ── 6. Errors and reconcile ──────────────────────────────────────────

    @Test
    void statusesMapAndReconcileIsABodiless202() {
        UUID id = UUID.randomUUID();
        UUID other = UUID.randomUUID();
        mount("POST", TARGETS, 400, "{\"error\":\"validation_error\",\"message\":\"credential: required on create\"}");
        mount("PUT", TARGETS + "/" + id, 409,
                "{\"error\":\"conflict\",\"message\":\"the SCIM target changed since it was read\"}");
        mount("POST", TARGETS + "/" + other + "/reconcile", 409,
                "{\"error\":\"conflict\",\"message\":\"a run holds the claim\"}");
        mount("GET", TARGETS + "/" + id, 404, "{\"error\":\"not_found\",\"message\":\"no\"}");
        mount("DELETE", TARGETS + "/" + id, 401, "{\"error\":\"unauthorized\",\"message\":\"human only\"}");
        mount("POST", "/api/v1/auth/refresh", 401, "{\"error\":\"unauthorized\"}");
        Route reconcile = mount("POST", TARGETS + "/" + id + "/reconcile", 202,
                "{\"target_id\":\"" + id + "\",\"status\":\"started\"}");

        ScimTargetsApi t = client.scimTargets();
        ValidationError v = assertThrows(ValidationError.class, () -> t.create(input(null)));
        assertTrue(v.getMessage().contains("credential"));
        assertThrows(ConflictError.class, () -> t.update(id, input(null)));
        assertThrows(ConflictError.class, () -> t.reconcile(other));
        assertThrows(NotFoundError.class, () -> t.get(id));
        assertInstanceOf(AuthError.class, assertThrows(RuntimeException.class, () -> t.delete(id)));

        ScimReconcileAccepted accepted = t.reconcile(id);
        assertEquals(id, accepted.targetId());
        assertEquals("started", accepted.status());
        assertEquals("", reconcile.last().body(), "reconcile sends no body");
    }

    @Test
    void aReadConvertsIntoTheReplacementBodyWithoutACredential() throws Exception {
        ScimTargetResponse t = JSON.treeToValue(targetBody(), ScimTargetResponse.class);
        ScimTargetInput body = ReplacementBodies.from(t);
        assertNull(body.credential(), "absent keeps the stored credential");
        assertEquals(t.baseUrl(), body.baseUrl());
        assertEquals(Boolean.TRUE, body.enabled());
        assertEquals(t.auth(), body.auth());
    }
}
