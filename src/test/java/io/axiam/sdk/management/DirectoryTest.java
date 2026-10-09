package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.DirectoryConfig;
import io.axiam.sdk.management.models.DirectoryKind;
import io.axiam.sdk.management.models.DirectoryLinkResult;
import io.axiam.sdk.management.models.DirectorySyncStatus;
import io.axiam.sdk.management.models.LinkDirectoryAccount;
import io.axiam.sdk.management.models.SetDirectoryConfig;
import io.axiam.sdk.management.models.UpdateDirectoryConfig;
import io.axiam.sdk.testutil.Redaction;

import org.junit.jupiter.api.Test;

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
 * The {@code directory} management namespace &mdash; CONTRACT.md &sect;30.8's six
 * required tests. The bind secret is generated at run time: a literal would be
 * a credential in the repository and would let a redaction test pass by
 * coincidence.
 */
class DirectoryTest extends ManagementTestBase {

    private static final String DIRECTORY = "/api/v1/tenants/" + TENANT_ID + "/directory";

    private static String secret() {
        return "bind-" + UUID.randomUUID().toString().replace("-", "");
    }

    private static ObjectNode configBody() {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("enabled", true);
        b.put("kind", "active_directory");
        b.put("url", "ldaps://dc.corp.example");
        b.put("start_tls", false);
        b.put("bind_dn", "cn=svc,dc=corp");
        b.put("base_dn", "dc=corp");
        b.put("user_filter", "(sAMAccountName={username})");
        ObjectNode map = b.putObject("user_attribute_map");
        map.put("username", "sAMAccountName");
        map.put("email", "mail");
        map.put("display_name", "displayName");
        map.put("external_id", "objectGUID");
        b.putNull("group_base_dn");
        b.putNull("group_filter");
        b.put("group_member_attribute", "member");
        b.put("group_nesting_depth", 5);
        b.putArray("group_mappings");
        b.put("sync_interval_secs", 3600);
        b.put("jit_provisioning", false);
        b.putArray("trust_anchors_pem");
        b.put("created_at", "2026-10-04T00:00:00Z");
        b.put("updated_at", "2026-10-04T00:00:00Z");
        return b;
    }

    private static SetDirectoryConfig setBody(String bindSecret) {
        return new SetDirectoryConfig("dc=corp", "cn=svc,dc=corp",
                bindSecret == null ? null : Sensitive.of(bindSecret), true, null, null, null, null,
                null, null, DirectoryKind.ACTIVE_DIRECTORY, false, null, null, "ldaps://dc.corp.example",
                null, "(sAMAccountName={username})");
    }

    // ── 1. Redaction ─────────────────────────────────────────────────────

    @Test
    void theBindSecretReachesTheWireAndNoRendering() throws Exception {
        String s = secret();
        SetDirectoryConfig set = setBody(s);
        UpdateDirectoryConfig update = UpdateDirectoryConfig.builder().bindSecret(Sensitive.of(s)).build();
        for (String rendering : List.of(set.toString(), update.toString(),
                JSON.writeValueAsString(set), JSON.writeValueAsString(update))) {
            Redaction.assertNoFragment("directory body rendering", rendering, s);
        }

        Route put = mount("PUT", DIRECTORY, 400,
                "{\"error\":\"validation_error\",\"message\":\"url: plaintext LDAP is refused\"}");
        ValidationError e = assertThrows(ValidationError.class, () -> client.directory().set(set));
        Redaction.assertNoFragment("error", e + " " + e.getMessage(), s);
        assertTrue(s.equals(put.last().json().path("bind_secret").asText()), "but it is on the wire");
    }

    // ── 2. No secret on the response ─────────────────────────────────────

    @Test
    void aBindSecretInAResponseIsDropped() throws Exception {
        String leaked = secret();
        ObjectNode body = configBody();
        body.put("bind_secret", leaked);
        mount("GET", DIRECTORY, 200, body.toString());

        DirectoryConfig config = client.directory().get();
        Redaction.assertNoFragment("decoded config", config + " " + JSON.writeValueAsString(config), leaked);
        assertFalse(Arrays.stream(DirectoryConfig.class.getRecordComponents())
                        .anyMatch(c -> c.getName().toLowerCase(java.util.Locale.ROOT).contains("secret")),
                "the type has no accessor for a secret");
        assertEquals("ldaps://dc.corp.example", config.url());
    }

    // ── 3. Sparse update ─────────────────────────────────────────────────

    @Test
    void updateSendsExactlyTheMembersItWasGiven() throws Exception {
        Route patch = mount("PATCH", DIRECTORY, 200, configBody().toString());
        String s = secret();

        client.directory().update(UpdateDirectoryConfig.builder().enabled(false).build());
        assertEquals("{\"enabled\":false}", patch.last().body());

        client.directory().update(UpdateDirectoryConfig.builder()
                .url("ldaps://dc2.corp.example").bindSecret(Sensitive.of(s)).build());
        assertEquals(List.of("bind_secret", "url"), patch.last().keys());
        assertTrue(s.equals(patch.last().json().path("bind_secret").asText()), "the secret is sent");

        client.directory().update(UpdateDirectoryConfig.builder().groupFilter(null).build());
        assertEquals("{\"group_filter\":null}", patch.last().body());

        client.directory().update(UpdateDirectoryConfig.builder()
                .groupBaseDn("ou=groups,dc=corp").build());
        assertEquals("{\"group_base_dn\":\"ou=groups,dc=corp\"}", patch.last().body());
        assertEquals(4, patch.calls());
        assertEquals("PATCH", patch.last().method());
    }

    // ── 4. Replacement ───────────────────────────────────────────────────

    @Test
    void setSendsEveryRequiredMemberAndDecodes201And200() throws Exception {
        // SetDirectoryConfig's seven required members cannot be null: the
        // constructor refuses each one; what is left to check is the wire.
        assertEquals(17, SetDirectoryConfig.class.getRecordComponents().length);
        assertCannotBeBuiltWithout(setBody(null), "enabled", "kind", "url", "start_tls", "bind_dn", "base_dn",
                "user_filter");
        for (int status : new int[] {201, 200}) {
            Route put = mount("PUT", DIRECTORY, status, configBody().toString());
            DirectoryConfig config = client.directory().set(setBody(null));
            assertTrue(config.enabled());
            JsonNode sent = put.last().json();
            for (String required : List.of("enabled", "kind", "url", "start_tls", "bind_dn", "base_dn",
                    "user_filter")) {
                assertTrue(sent.has(required), "a required member is missing from the body");
            }
            assertFalse(sent.has("bind_secret"), "absent keeps the stored secret");
        }
    }

    // ── 5. No retry ──────────────────────────────────────────────────────

    @Test
    void noWriteIsRetriedOn503() {
        Route put = mount("PUT", DIRECTORY, 503, "");
        Route patch = mount("PATCH", DIRECTORY, 503, "");
        Route delete = mount("DELETE", DIRECTORY, 503, "");
        Route link = mount("POST", DIRECTORY + "/links", 503, "");
        DirectoryApi d = client.directory();
        List<RuntimeException> errors = List.of(
                assertThrows(RuntimeException.class, () -> d.set(setBody(secret()))),
                assertThrows(RuntimeException.class, () -> d.update(UpdateDirectoryConfig.builder().build())),
                assertThrows(RuntimeException.class, d::delete),
                assertThrows(RuntimeException.class,
                        () -> d.linkAccount(new LinkDirectoryAccount(UUID.randomUUID()))));
        for (RuntimeException e : errors) {
            assertInstanceOf(NetworkError.class, e);
            assertFalse(e instanceof ValidationError);
        }
        for (Route r : List.of(put, patch, delete, link)) {
            assertEquals(1, r.calls(), "exactly one request per write");
        }
    }

    @Test
    void noWriteIsResentAfterADroppedConnection() throws Exception {
        DirectoryApi d = client.directory();
        assertSentOnceOverADroppedConnection("PUT", DIRECTORY, () -> d.set(setBody(secret())));
        assertSentOnceOverADroppedConnection("PATCH", DIRECTORY,
                () -> d.update(UpdateDirectoryConfig.builder().build()));
        assertSentOnceOverADroppedConnection("DELETE", DIRECTORY, d::delete);
        assertSentOnceOverADroppedConnection("POST", DIRECTORY + "/links",
                () -> d.linkAccount(new LinkDirectoryAccount(UUID.randomUUID())));
    }

    // ── 6. Errors and link_account ───────────────────────────────────────

    @Test
    void errorsMapPerSection2AndLinkAccountSendsOnlyTheUserId() throws Exception {
        mount("PUT", DIRECTORY, 400, "{\"error\":\"validation_error\",\"message\":"
                + "\"url: changing the connection requires entering the bind secret again\"}");
        mount("PATCH", DIRECTORY, 409, "{\"error\":\"conflict\",\"message\":\"opaque_mode\"}");
        mount("GET", DIRECTORY, 404, "{\"error\":\"not_found\",\"message\":\"none\"}");

        ValidationError v = assertThrows(ValidationError.class, () -> client.directory().set(setBody(null)));
        assertTrue(v.getMessage().contains("bind secret again"));
        assertThrows(ConflictError.class,
                () -> client.directory().update(UpdateDirectoryConfig.builder().enabled(true).build()));
        assertThrows(NotFoundError.class, () -> client.directory().get());

        UUID user = UUID.randomUUID();
        Route link = mount("POST", DIRECTORY + "/links", 200, "{\"user_id\":\"" + user
                + "\",\"directory_external_id\":\"3f2a-objectguid\",\"webauthn_credentials_deleted\":2,"
                + "\"certificates_revoked\":1,\"was_already_linked\":false}");
        DirectoryLinkResult result = client.directory().linkAccount(new LinkDirectoryAccount(user));
        assertEquals("{\"user_id\":\"" + user + "\"}", link.last().body());
        assertEquals(user, result.userId());
        assertEquals("3f2a-objectguid", result.directoryExternalId());
        assertEquals(2L, result.webauthnCredentialsDeleted());
        assertEquals(1L, result.certificatesRevoked());
        assertFalse(result.wasAlreadyLinked());
    }

    @Test
    void syncStatusDecodesAnUnknownResultAndTheFirstRunNulls() {
        mount("GET", DIRECTORY + "/sync-status", 200, "{\"last_result\":\"something_new\","
                + "\"last_attempt_at\":null,\"last_full_run_at\":null,\"full_required\":true,"
                + "\"has_watermark\":false}");
        DirectorySyncStatus status = client.directory().getSyncStatus();
        assertEquals("something_new", status.lastResult());
        assertTrue(status.fullRequired() && !status.hasWatermark());
        assertNull(status.lastAttemptAt());
    }

    @Test
    void aReadConvertsIntoTheReplacementBodyWithoutASecret() throws Exception {
        DirectoryConfig config = JSON.treeToValue(configBody(), DirectoryConfig.class);
        SetDirectoryConfig body = ReplacementBodies.from(config);
        assertNull(body.bindSecret(), "absent keeps the stored secret");
        assertEquals(config.url(), body.url());
        assertEquals(5, body.groupNestingDepth());
        assertEquals(3600L, body.syncIntervalSecs());
        assertEquals(config.userAttributeMap(), body.userAttributeMap());
    }

    @Test
    void anExplicitNullStaysDistinctFromAnAbsentMember() throws Exception {
        UpdateDirectoryConfig decoded = JSON.readValue("{\"group_filter\":null}", UpdateDirectoryConfig.class);
        assertEquals(JsonNullable.ofNull(), decoded.groupFilter());
        assertNull(decoded.groupBaseDn(), "absent stays a Java null");
        UpdateDirectoryConfig withValue = JSON.readValue("{\"group_filter\":\"(x)\"}",
                UpdateDirectoryConfig.class);
        assertEquals("(x)", withValue.groupFilter().get());
        assertEquals(java.util.Optional.of("(x)"), withValue.groupFilter().asOptional());
        assertFalse(withValue.groupFilter().isNull());
        assertTrue(JsonNullable.of(null).isNull());
        assertEquals("JsonNullable[null]", JsonNullable.ofNull().toString());
        assertEquals("JsonNullable[(x)]", withValue.groupFilter().toString());
        assertEquals(JsonNullable.of("a").hashCode(), JsonNullable.of("a").hashCode());
        assertFalse(JsonNullable.of("a").equals("a"));
        assertEquals(new String(io.axiam.sdk.internal.ManagementTransport.encodeBody("t",
                UpdateDirectoryConfig.builder().groupFilter("(y)").build()),
                java.nio.charset.StandardCharsets.UTF_8), "{\"group_filter\":\"(y)\"}");
    }
}
