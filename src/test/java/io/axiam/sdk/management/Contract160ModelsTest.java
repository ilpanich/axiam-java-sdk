package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.management.models.CreateFederationConfigRequest;
import io.axiam.sdk.management.models.CreateNotificationRuleRequest;
import io.axiam.sdk.management.models.FederationConfigResponse;
import io.axiam.sdk.management.models.NotificationEventType;
import io.axiam.sdk.management.models.NotificationRuleResponse;
import io.axiam.sdk.management.models.UpdateFederationConfigRequest;
import io.axiam.sdk.management.models.UpdateNotificationRuleRequest;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;27.15 (contract 1.60): {@code window_minutes} on the notification
 * rules, and the federation configuration's {@code allow_sha1_signatures},
 * {@code idp_metadata_signing_cert_pem} and note 8's "an explicit {@code null}
 * clears" &mdash; each over the wire against the mocked server.
 */
class Contract160ModelsTest extends ManagementTestBase {

    private static final String RULES = "/api/v1/notification-rules";
    private static final String CONFIGS = "/api/v1/federation-configs";

    private static ObjectNode ruleBody(int windowMinutes) {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("name", "lockouts");
        b.put("description", "");
        b.put("enabled", true);
        b.putArray("events").add("account_locked");
        b.putArray("recipient_emails").add("secops@example.test");
        b.put("window_minutes", windowMinutes);
        b.put("created_at", "2026-10-10T00:00:00Z");
        b.put("updated_at", "2026-10-10T00:00:00Z");
        return b;
    }

    private static CreateNotificationRuleRequest rule(Integer windowMinutes) {
        return new CreateNotificationRuleRequest("", List.of(NotificationEventType.ACCOUNT_LOCKED), "lockouts",
                List.of("secops@example.test"), windowMinutes);
    }

    // ── §27.15 note 1: window_minutes ────────────────────────────────────

    /**
     * The one required test of &sect;27.15 note 1: {@code create} with
     * {@code window_minutes} sends it as given, {@code create} without it sends no such
     * key, and a response carrying it decodes it. Values outside 1&ndash;1440 are the
     * server's to refuse: the SDK passes them through, never clamped.
     */
    @Test
    void windowMinutesIsPassedThroughNeverClampedAndDecoded() throws Exception {
        Route create = mount("POST", RULES, 201, ruleBody(45).toString());
        NotificationRuleResponse made = client.notificationRules().create(rule(45));
        assertEquals(45, create.last().json().path("window_minutes").asInt());
        assertEquals(Integer.valueOf(45), made.windowMinutes(), "the response's value decodes");

        for (int outOfRange : new int[] {0, 1441, -5}) {
            client.notificationRules().create(rule(outOfRange));
            assertEquals(outOfRange, create.last().json().path("window_minutes").asInt(),
                    "sent as given, never clamped: " + outOfRange);
        }

        client.notificationRules().create(rule(null));
        assertFalse(create.last().json().has("window_minutes"), "unset: no such key");

        UUID id = UUID.randomUUID();
        Route update = mount("PUT", RULES + "/" + id, 200, ruleBody(1440).toString());
        client.notificationRules().update(id, UpdateNotificationRuleRequest.builder().windowMinutes(2000).build());
        assertEquals(List.of("window_minutes"), update.last().keys());
        assertEquals(2000, update.last().json().path("window_minutes").asInt());
    }

    // ── §27.15 notes 6 and 7: the two federation members ──────────────────

    private static ObjectNode configBody() {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("provider", "corp-idp");
        b.put("protocol", "Saml");
        b.put("provider_kind", "Generic");
        b.put("client_id", "axiam");
        b.putNull("attribute_map");
        b.put("enabled", true);
        ObjectNode exchange = b.putObject("token_exchange");
        exchange.put("enabled", false);
        exchange.putArray("accepted_audiences");
        exchange.put("max_token_age_secs", 300);
        exchange.putObject("scope_map");
        exchange.put("subject_mapping", "email");
        b.put("allow_tenant_inheritance", false);
        b.putArray("scopes");
        b.putArray("effective_scopes");
        b.putArray("allowed_issuer_tenants");
        b.putArray("allowed_algorithms");
        b.put("mints_client_secret", false);
        b.put("pkce_required", false);
        b.put("has_bundled_mark", false);
        b.put("created_at", "2026-10-10T00:00:00Z");
        b.put("updated_at", "2026-10-10T00:00:00Z");
        return b;
    }

    @Test
    void anOlderServersResponseWithoutTheNewMembersDecodesAsFalseAndNull() throws Exception {
        UUID id = UUID.randomUUID();
        mount("GET", CONFIGS + "/" + id, 200, configBody().toString());
        FederationConfigResponse old = client.federation().getConfig(id);
        assertFalse(old.allowSha1Signatures(), "absent decodes as false");
        assertNull(old.idpMetadataSigningCertPem());

        String pem = "-----BEGIN CERTIFICATE-----\n" + UUID.randomUUID() + "\n-----END CERTIFICATE-----\n";
        ObjectNode current = configBody();
        current.put("allow_sha1_signatures", true);
        current.put("idp_metadata_signing_cert_pem", pem);
        UUID other = UUID.randomUUID();
        mount("GET", CONFIGS + "/" + other, 200, current.toString());
        FederationConfigResponse now = client.federation().getConfig(other);
        assertTrue(now.allowSha1Signatures());
        assertEquals(pem, now.idpMetadataSigningCertPem());
    }

    @Test
    void theNewMembersAreSentOnlyWhenTheCallerSetsThem() throws Exception {
        Route create = mount("POST", CONFIGS, 201, configBody().toString());
        String secret = "s-" + UUID.randomUUID();
        client.federation().createConfig(createConfig(secret, null, null));
        JsonNode sent = create.last().json();
        assertFalse(sent.has("allow_sha1_signatures"), "unset: not sent");
        assertFalse(sent.has("idp_metadata_signing_cert_pem"), "unset: not sent");

        String pem = "-----BEGIN CERTIFICATE-----\n" + UUID.randomUUID() + "\n-----END CERTIFICATE-----\n";
        client.federation().createConfig(createConfig(secret, false, pem));
        sent = create.last().json();
        assertTrue(sent.path("allow_sha1_signatures").isBoolean());
        assertFalse(sent.path("allow_sha1_signatures").asBoolean(), "an explicit false is sent");
        assertEquals(pem, sent.path("idp_metadata_signing_cert_pem").asText());

        UUID id = UUID.randomUUID();
        Route update = mount("PUT", CONFIGS + "/" + id, 200, configBody().toString());
        client.federation().updateConfig(id, UpdateFederationConfigRequest.builder()
                .allowSha1Signatures(true).idpMetadataSigningCertPem(pem).build());
        assertEquals(List.of("allow_sha1_signatures", "idp_metadata_signing_cert_pem"), update.last().keys());
        assertTrue(update.last().json().path("allow_sha1_signatures").asBoolean());
        assertEquals(pem, update.last().json().path("idp_metadata_signing_cert_pem").asText());
    }

    private static CreateFederationConfigRequest createConfig(String secret, Boolean allowSha1, String metadataPem) {
        return new CreateFederationConfigRequest(allowSha1, null, null, null, null, null, null, null, null,
                "axiam", Sensitive.of(secret), metadataPem, null, "https://idp.example.test/metadata", "Saml",
                "corp-idp", null, null, null, null, null, null, null);
    }

    // ── §27.15 note 8: an explicit null clears, an omitted member is kept ─

    /**
     * &sect;27.15 note 8 with &sect;27.4 rule 5's exact key-set test: an
     * {@code update_config} that clears one member sends exactly that key, as JSON
     * {@code null}; one that sets nothing sends {@code {}}; and the ten nullable
     * members can each express "unset" and "set to {@code null}" apart.
     */
    @Test
    void anExplicitNullClearsAndAnOmittedMemberIsNotSent() throws Exception {
        UUID id = UUID.randomUUID();
        Route update = mount("PUT", CONFIGS + "/" + id, 200, configBody().toString());

        client.federation().updateConfig(id, UpdateFederationConfigRequest.builder()
                .idpMetadataSigningCertPem(null).build());
        assertEquals(List.of("idp_metadata_signing_cert_pem"), update.last().keys(), "exactly the cleared key");
        assertTrue(update.last().json().get("idp_metadata_signing_cert_pem").isNull(), "sent as JSON null");

        client.federation().updateConfig(id, UpdateFederationConfigRequest.builder()
                .metadataUrl(null).enabled(false).build());
        assertEquals(List.of("enabled", "metadata_url"), update.last().keys());
        assertTrue(update.last().json().get("metadata_url").isNull());

        client.federation().updateConfig(id, UpdateFederationConfigRequest.builder().build());
        assertEquals("{}", update.last().body(), "nothing set: nothing sent, nothing cleared");

        client.federation().updateConfig(id, UpdateFederationConfigRequest.builder()
                .appleTeamId(null).appleKeyId(null).build());
        assertEquals(List.of("apple_key_id", "apple_team_id"), update.last().keys(), "cleared together");

        List<String> clearable = List.of("apple_key_id", "apple_team_id", "authorization_endpoint", "button_icon",
                "idp_metadata_signing_cert_pem", "idp_signing_cert_pem", "metadata_url", "provider_slug",
                "token_endpoint", "userinfo_endpoint");
        for (java.lang.reflect.RecordComponent rc : UpdateFederationConfigRequest.class.getRecordComponents()) {
            String wire = rc.getName().replaceAll("([A-Z])", "_$1").toLowerCase(java.util.Locale.ROOT);
            assertEquals(clearable.contains(wire), rc.getType() == JsonNullable.class,
                    wire + ": nullable-and-clearable exactly when note 8 lists it");
        }
    }
}
