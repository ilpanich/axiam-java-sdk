package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.AcsEndpoint;
import io.axiam.sdk.management.models.IssueSamlIdpCredential;
import io.axiam.sdk.management.models.ParseSamlSpMetadata;
import io.axiam.sdk.management.models.SamlBinding;
import io.axiam.sdk.management.models.SamlIdpCredential;
import io.axiam.sdk.management.models.SamlIdpCredentialPromotion;
import io.axiam.sdk.management.models.SamlIdpCredentialStatus;
import io.axiam.sdk.management.models.SamlIdpInfo;
import io.axiam.sdk.management.models.SamlIdpSlot;
import io.axiam.sdk.management.models.SamlServiceProvider;
import io.axiam.sdk.management.models.SamlServiceProviderInput;
import io.axiam.sdk.testutil.Redaction;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The {@code saml} management namespace &mdash; CONTRACT.md &sect;29.8's eight required tests. */
class SamlTest extends ManagementTestBase {

    private static final String SAML = "/api/v1/tenants/" + TENANT_ID + "/saml";

    private static ObjectNode spBody() {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("enabled", true);
        b.put("display_name", "Payroll");
        b.put("entity_id", "https://payroll.example/sp");
        ObjectNode acs = b.putArray("acs_urls").addObject();
        acs.put("url", "https://payroll.example/acs");
        acs.put("binding", "http_post");
        acs.put("index", 0);
        acs.put("is_default", true);
        b.putNull("slo_url");
        b.putNull("slo_binding");
        b.put("name_id_format", "persistent");
        b.put("sign_responses", true);
        b.put("encrypt_assertions", false);
        b.putNull("sp_signing_cert_pem");
        b.putNull("sp_encryption_cert_pem");
        b.put("want_authn_requests_signed", false);
        b.put("allow_idp_initiated", false);
        b.putArray("attribute_mappings");
        b.putArray("allowed_groups");
        b.put("created_at", "2026-10-04T00:00:00Z");
        b.put("updated_at", "2026-10-04T00:00:00Z");
        return b;
    }

    private static ObjectNode credentialBody(String status) {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("issuer_ca_id", UUID.randomUUID().toString());
        b.put("certificate_pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
        b.put("serial", "0a1b");
        b.put("fingerprint", "ab".repeat(32));
        b.put("not_before", "2026-10-04T00:00:00Z");
        b.put("not_after", "2027-10-04T00:00:00Z");
        b.put("status", status);
        b.put("created_at", "2026-10-04T00:00:00Z");
        b.putNull("retired_at");
        return b;
    }

    private static SamlServiceProviderInput input() {
        return new SamlServiceProviderInput(
                List.of(new AcsEndpoint(SamlBinding.HTTP_POST, 0, true, "https://payroll.example/acs")),
                null, null, null, "Payroll", null, null, "https://payroll.example/sp",
                null, null, null, null, null, null, null);
    }

    // ── 1. Replacement ───────────────────────────────────────────────────

    @Test
    void updateServiceProviderPutsTheWholeRegistration() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", SAML + "/service-providers/" + id, 200, spBody().toString());
        SamlServiceProvider current = JSON.treeToValue(spBody(), SamlServiceProvider.class);
        SamlServiceProviderInput read = ReplacementBodies.from(current);
        SamlServiceProviderInput body = new SamlServiceProviderInput(read.acsUrls(), read.allowIdpInitiated(),
                read.allowedGroups(), read.attributeMappings(), "Payroll (EU)", read.enabled(),
                read.encryptAssertions(), read.entityId(), read.nameIdFormat(), read.signResponses(),
                read.sloBinding(), read.sloUrl(), read.spEncryptionCertPem(), read.spSigningCertPem(),
                read.wantAuthnRequestsSigned());

        SamlServiceProvider sp = client.saml().updateServiceProvider(id, body);
        assertEquals("https://payroll.example/sp", sp.entityId());
        JsonNode sent = put.last().json();
        for (String member : List.of("acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings",
                "display_name", "enabled", "encrypt_assertions", "entity_id", "name_id_format",
                "sign_responses", "want_authn_requests_signed")) {
            assertTrue(sent.has(member), "a member of the replacement was not sent");
        }
        assertEquals("Payroll (EU)", sent.path("display_name").asText());
        // display_name, entity_id and acs_urls cannot be null: the constructor refuses them.
        assertEquals(15, SamlServiceProviderInput.class.getRecordComponents().length);
        assertCannotBeBuiltWithout(input(), "display_name", "entity_id", "acs_urls");
    }

    // ── 2. No signing switch, open decoding ──────────────────────────────

    @Test
    void signAssertionsDoesNotExistAndUnknownValuesDecode() throws Exception {
        UUID id = UUID.randomUUID();
        ObjectNode body = spBody();
        body.put("sign_assertions", false);
        body.put("some_future_member", 1);
        ((ObjectNode) body.path("acs_urls").get(0)).put("binding", "http_artifact");
        mount("GET", SAML + "/service-providers/" + id, 200, body.toString());
        Route put = mount("PUT", SAML + "/service-providers/" + id, 200, spBody().toString());

        SamlServiceProvider sp = client.saml().getServiceProvider(id);
        assertEquals(SamlBinding.UNKNOWN, sp.acsUrls().get(0).binding());
        for (Class<?> type : List.of(SamlServiceProvider.class, SamlServiceProviderInput.class)) {
            assertFalse(Arrays.stream(type.getRecordComponents())
                    .anyMatch(c -> c.getName().equals("signAssertions")), "no signing switch");
        }
        // An unknown value decodes but is never sent: replace the ACS binding
        // before writing back.
        SamlServiceProviderInput read = ReplacementBodies.from(sp);
        AcsEndpoint acs = read.acsUrls().get(0);
        SamlServiceProviderInput fixed = new SamlServiceProviderInput(
                List.of(new AcsEndpoint(SamlBinding.HTTP_POST, acs.index(), acs.isDefault(), acs.url())),
                read.allowIdpInitiated(), read.allowedGroups(), read.attributeMappings(), read.displayName(),
                read.enabled(), read.encryptAssertions(), read.entityId(), read.nameIdFormat(),
                read.signResponses(), read.sloBinding(), read.sloUrl(), read.spEncryptionCertPem(),
                read.spSigningCertPem(), read.wantAuthnRequestsSigned());
        client.saml().updateServiceProvider(id, fixed);
        JsonNode sent = put.last().json();
        assertFalse(sent.has("sign_assertions"));
        assertFalse(sent.has("some_future_member"));
    }

    // ── 3. Draft round trip ──────────────────────────────────────────────

    @Test
    void parseSpMetadataSendsExactlyOneMemberAndTheDraftCreates() throws Exception {
        ObjectNode draft = JSON.createObjectNode();
        ObjectNode sp = draft.putObject("service_provider");
        sp.put("display_name", "Imported");
        sp.put("entity_id", "https://imported.example/sp");
        ObjectNode acs = sp.putArray("acs_urls").addObject();
        acs.put("binding", "http_post");
        acs.put("index", 1);
        acs.put("is_default", false);
        acs.put("url", "https://imported.example/acs");
        sp.put("sp_signing_cert_pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
        sp.put("want_authn_requests_signed", true);
        draft.put("signing_certificate_fingerprint", "cd".repeat(32));
        draft.putNull("encryption_certificate_fingerprint");
        draft.putArray("warnings").add("the metadata's signature was not evaluated");
        Route parse = mount("POST", SAML + "/parse-sp-metadata", 200, draft.toString());
        Route create = mount("POST", SAML + "/service-providers", 201, spBody().toString());

        var fromUrl = client.saml().parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://imported.example/metadata"));
        assertEquals("{\"metadata_url\":\"https://imported.example/metadata\"}", parse.last().body());
        client.saml().parseSpMetadata(ParseSamlSpMetadata.fromXml("<EntityDescriptor/>"));
        assertEquals("{\"metadata_xml\":\"<EntityDescriptor/>\"}", parse.last().body());

        for (ParseSamlSpMetadata bothOrNeither : List.of(
                new ParseSamlSpMetadata("https://a", "<x/>"), ParseSamlSpMetadata.builder().build())) {
            ValidationError e = assertThrows(ValidationError.class,
                    () -> client.saml().parseSpMetadata(bothOrNeither));
            assertEquals(400, e.status());
            assertEquals("saml.parse_sp_metadata", e.operation());
        }
        assertEquals(2, parse.calls(), "the refused calls sent nothing");
        assertEquals(List.of("the metadata's signature was not evaluated"), fromUrl.warnings());

        client.saml().createServiceProvider(fromUrl.serviceProvider());
        assertEquals(draft.path("service_provider"), create.last().json(), "the draft is sent unchanged");
    }

    // ── 4. Credentials carry no key ──────────────────────────────────────

    @Test
    void aCredentialHasNoKeyMemberAndPromotionMayRetireNothing() throws Exception {
        String leaked = "pk" + UUID.randomUUID().toString().replace("-", "");
        UUID id = UUID.randomUUID();
        ObjectNode retired = credentialBody("retired");
        retired.put("private_key_pem", leaked);
        mount("POST", SAML + "/idp-credentials/" + id + "/retire", 200, retired.toString());
        ObjectNode promotion = JSON.createObjectNode();
        promotion.set("active", credentialBody("active"));
        promotion.putNull("retired");
        mount("POST", SAML + "/idp-credentials/" + id + "/promote", 200, promotion.toString());

        SamlIdpCredential credential = client.saml().retireIdpCredential(id);
        for (String rendering : List.of(credential.toString(), JSON.writeValueAsString(credential))) {
            Redaction.assertNoFragment("credential rendering", rendering, leaked);
            assertFalse(rendering.contains("private_key"), "no key member is rendered");
        }
        assertFalse(Arrays.stream(SamlIdpCredential.class.getRecordComponents())
                .anyMatch(c -> c.getName().toLowerCase(java.util.Locale.ROOT).contains("key")), "no key accessor");
        SamlIdpCredentialPromotion promoted = client.saml().promoteIdpCredential(id);
        assertNull(promoted.retired());
        assertEquals(SamlIdpCredentialStatus.ACTIVE, promoted.active().status());
    }

    // ── 5. Pagination ────────────────────────────────────────────────────

    @Test
    void serviceProvidersPageWithSearchAndCredentialsAreAPlainList() throws Exception {
        Route list = mountTwoPages(SAML + "/service-providers", () -> spBody().toString());
        mount("GET", SAML + "/idp-credentials", 200,
                "[" + credentialBody("next") + "," + credentialBody("active") + "]");

        Page<SamlServiceProvider> page = client.saml().listServiceProviders(PageRequest.matching(1, "payroll"));
        assertEquals(2, page.total());
        List<SamlServiceProvider> all = client.saml().listServiceProvidersAll(PageRequest.matching(1, "payroll"));
        assertEquals(2, all.size());
        assertEquals(3, list.calls());
        for (Recorded r : list.requests()) {
            assertEquals("payroll", r.query().get("search"), "the pager carries search on every page");
        }
        List<SamlIdpCredential> credentials = client.saml().listIdpCredentials();
        assertEquals(2, credentials.size());
        assertEquals(SamlIdpCredentialStatus.NEXT, credentials.get(0).status());
    }

    // ── 6. No retry ──────────────────────────────────────────────────────

    @Test
    void noneOfTheSevenWritesIsRetriedOn503() {
        UUID id = UUID.randomUUID();
        List<Route> routes = List.of(
                mount("POST", SAML + "/service-providers", 503, ""),
                mount("PUT", SAML + "/service-providers/" + id, 503, ""),
                mount("DELETE", SAML + "/service-providers/" + id, 503, ""),
                mount("POST", SAML + "/parse-sp-metadata", 503, ""),
                mount("POST", SAML + "/idp-credentials", 503, ""),
                mount("POST", SAML + "/idp-credentials/" + id + "/promote", 503, ""),
                mount("POST", SAML + "/idp-credentials/" + id + "/retire", 503, ""));
        SamlApi s = client.saml();
        List<Executable> writes = new ArrayList<>(List.of(
                () -> s.createServiceProvider(input()),
                () -> s.updateServiceProvider(id, input()),
                () -> s.deleteServiceProvider(id),
                () -> s.parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://m")),
                () -> s.issueIdpCredential(new IssueSamlIdpCredential(UUID.randomUUID(), SamlIdpSlot.NEXT, null)),
                () -> s.promoteIdpCredential(id),
                () -> s.retireIdpCredential(id)));
        for (Executable write : writes) {
            NetworkError e = assertThrows(NetworkError.class, write);
            assertFalse(e instanceof ValidationError);
        }
        for (Route r : routes) {
            assertEquals(1, r.calls(), "exactly one request per write");
        }
    }

    @Test
    void noneOfTheSevenWritesIsResentAfterADroppedConnection() throws Exception {
        UUID id = UUID.randomUUID();
        SamlApi s = client.saml();
        assertSentOnceOverADroppedConnection("POST", SAML + "/service-providers", () -> s.createServiceProvider(input()));
        assertSentOnceOverADroppedConnection("PUT", SAML + "/service-providers/" + id,
                () -> s.updateServiceProvider(id, input()));
        assertSentOnceOverADroppedConnection("DELETE", SAML + "/service-providers/" + id,
                () -> s.deleteServiceProvider(id));
        assertSentOnceOverADroppedConnection("POST", SAML + "/parse-sp-metadata",
                () -> s.parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://m")));
        assertSentOnceOverADroppedConnection("POST", SAML + "/idp-credentials",
                () -> s.issueIdpCredential(new IssueSamlIdpCredential(UUID.randomUUID(), SamlIdpSlot.NEXT, null)));
        assertSentOnceOverADroppedConnection("POST", SAML + "/idp-credentials/" + id + "/promote",
                () -> s.promoteIdpCredential(id));
        assertSentOnceOverADroppedConnection("POST", SAML + "/idp-credentials/" + id + "/retire",
                () -> s.retireIdpCredential(id));
    }

    // ── 7. Errors ────────────────────────────────────────────────────────

    @Test
    void statusesMapPerSection2() {
        UUID id = UUID.randomUUID();
        mount("POST", SAML + "/service-providers", 409, "{\"error\":\"conflict\",\"message\":\"entity_id\"}");
        mount("PUT", SAML + "/service-providers/" + id, 400, "{\"error\":\"validation_error\","
                + "\"message\":\"entity_id is immutable: register a new service provider\"}");
        mount("GET", SAML + "/service-providers/" + id, 404, "{\"error\":\"not_found\",\"message\":\"no\"}");
        mount("POST", SAML + "/idp-credentials/" + id + "/promote", 409,
                "{\"error\":\"conflict\",\"message\":\"not next\"}");
        mount("POST", SAML + "/parse-sp-metadata", 503,
                "{\"error\":\"service_unavailable\",\"message\":\"saml\"}");
        mount("DELETE", SAML + "/service-providers/" + id, 401, "{\"error\":\"unauthorized\"}");
        mount("POST", "/api/v1/auth/refresh", 401, "{\"error\":\"unauthorized\"}");

        SamlApi s = client.saml();
        assertThrows(ConflictError.class, () -> s.createServiceProvider(input()));
        ValidationError v = assertThrows(ValidationError.class, () -> s.updateServiceProvider(id, input()));
        assertTrue(v.getMessage().contains("immutable"));
        assertThrows(NotFoundError.class, () -> s.getServiceProvider(id));
        assertThrows(ConflictError.class, () -> s.promoteIdpCredential(id));
        NetworkError n = assertThrows(NetworkError.class,
                () -> s.parseSpMetadata(ParseSamlSpMetadata.fromUrl("https://m")));
        assertFalse(n instanceof ValidationError);
        assertInstanceOf(AuthError.class, assertThrows(RuntimeException.class, () -> s.deleteServiceProvider(id)));
    }

    // ── 8. Readiness is read, not cached ─────────────────────────────────

    @Test
    void getIdpIsNeverCachedAndKeepsNullApartFromAbsent() throws Exception {
        UUID active = UUID.randomUUID();
        ObjectNode body = JSON.createObjectNode();
        body.put("tenant_id", TENANT_ID.toString());
        body.put("saml_available", true);
        body.put("saml_idp_enabled", false);
        body.put("metadata_served", true);
        body.put("entity_id", "https://iam.example/saml/v2/t");
        body.put("metadata_url", "https://iam.example/saml/v2/t/metadata");
        body.put("sso_url", "https://iam.example/saml/v2/t/sso");
        body.put("slo_url", "https://iam.example/saml/v2/t/slo");
        body.put("active_credential_id", active.toString());
        body.putNull("next_credential_id");
        // The configured tenant, in the path: getIdp takes no tenant argument.
        Route idp = mount("GET", SAML + "/idp", 200, body.toString());

        SamlIdpInfo info = client.saml().getIdp();
        client.saml().getIdp();
        assertEquals(2, idp.calls(), "two calls, two requests");
        assertEquals(SAML + "/idp", idp.last().path());
        assertEquals(JsonNullable.of(active), info.activeCredentialId());
        assertEquals(JsonNullable.ofNull(), info.nextCredentialId(), "null, not absent");
        assertTrue(info.samlAvailable() && info.metadataServed() && !info.samlIdpEnabled());

        body.remove("next_credential_id");
        SamlIdpInfo without = JSON.treeToValue(body, SamlIdpInfo.class);
        assertNull(without.nextCredentialId(), "absent stays absent");
    }
}
