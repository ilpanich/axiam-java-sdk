package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.CreateNetworkReplyProfileRequest;
import io.axiam.sdk.management.models.CreateNetworkSegmentRequest;
import io.axiam.sdk.management.models.NetworkPolicyResponse;
import io.axiam.sdk.management.models.NetworkReplyProfile;
import io.axiam.sdk.management.models.NetworkReplyProfileInput;
import io.axiam.sdk.management.models.NetworkSegmentKind;
import io.axiam.sdk.management.models.NetworkSegmentResponse;
import io.axiam.sdk.management.models.RadiusServiceType;
import io.axiam.sdk.management.models.RadiusTerminationAction;
import io.axiam.sdk.management.models.ReplaceNetworkPolicyRequest;
import io.axiam.sdk.management.models.ReplaceNetworkReplyProfileRequest;
import io.axiam.sdk.management.models.ReplaceNetworkSegmentRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;36.8, the five required tests of the {@code network} namespace
 * (contract 1.62), against the mocked server.
 */
class NetworkManagementTest extends ManagementTestBase {

    private static final String SEGMENTS = "/api/v1/network/segments";
    private static final String PROFILES = "/api/v1/network/profiles";
    private static final String POLICY = "/api/v1/network/policy";
    private static final UUID SEG = UUID.fromString("0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a");

    static String segmentBody(String kind, long version) {
        return ("{\"id\":\"%s\",\"tenant_id\":\"%s\",\"path\":\"/network/zones/default/lab\","
                + "\"name\":\"lab\",\"site_key\":\"default\",\"kind\":\"%s\",\"vlan_id\":120,"
                + "\"filter_ids\":[\"lab-in\",\"lab-out\"],\"rank\":1,\"enabled\":true,\"version\":%d,"
                + "\"created_by\":\"%s\",\"updated_by\":\"%s\","
                + "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}")
                .formatted(SEG, TENANT_ID, kind, version, EXAMPLE_ID, EXAMPLE_ID);
    }

    static String profileBody(String termination, String serviceType, boolean clamped, long version) {
        return ("{\"segment_id\":\"%s\",\"tenant_id\":\"%s\",\"dictionary\":\"axiam-radius-reply/1\","
                + "\"session_timeout_secs\":3600,\"session_timeout_clamped\":%s,"
                + "\"termination_action\":\"%s\",\"idle_timeout_secs\":600,\"filter_id\":\"lab-in\","
                + "\"service_type\":%s,\"version\":%d,\"created_by\":\"%s\",\"updated_by\":\"%s\","
                + "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}")
                .formatted(SEG, TENANT_ID, clamped, termination,
                        serviceType == null ? "null" : "\"" + serviceType + "\"", version, EXAMPLE_ID, EXAMPLE_ID);
    }

    private static NetworkReplyProfileInput input() {
        return new NetworkReplyProfileInput(null, null, null, null, 3600, null);
    }

    // -- 1. The surface ------------------------------------------------------------------------

    @Test
    void theTwelveOperationsExistAndNothingReachesTheDecisionRoute() throws Exception {
        Set<String> expected = new TreeSet<>(List.of(
                "listSegments", "createSegment", "getSegment", "replaceSegment", "deleteSegment",
                "listProfiles", "createProfile", "getProfile", "replaceProfile", "deleteProfile",
                "getPolicy", "replacePolicy"));
        Set<String> declared = new TreeSet<>();
        for (Method m : NetworkApi.class.getDeclaredMethods()) {
            if (java.lang.reflect.Modifier.isPublic(m.getModifiers()) && !m.getName().endsWith("All")) {
                declared.add(m.getName());
            }
        }
        assertEquals(expected, declared, "twelve operations, and none for POST /api/v1/network/decide");

        JsonNode registry = JSON.readTree(java.nio.file.Files.readString(
                java.nio.file.Path.of("management-registry.json")));
        assertEquals(202, registry.path("operation_count").asInt());
        assertEquals(29, registry.path("namespace_count").asInt());
        assertTrue(registry.path("excluded_operations").has("POST /api/v1/network/decide"),
                "the decision route is excluded by name (§27.0, §36.11)");
        assertEquals(12, registry.path("namespaces").path("network").path("operations").size());
        assertTrue(expectedSurface().stream().noneMatch(op -> op.contains("decide")));
    }

    @Test
    void everyOperationUsesTheMethodAndPathOfSection361() throws Exception {
        mount("GET", SEGMENTS, 200, pageOf(segmentBody("access", 1)));
        mount("POST", SEGMENTS, 201, segmentBody("access", 1));
        mount("GET", SEGMENTS + "/" + SEG, 200, segmentBody("access", 1));
        mount("PUT", SEGMENTS + "/" + SEG, 200, segmentBody("access", 2));
        mount("DELETE", SEGMENTS + "/" + SEG, 204, "");
        mount("GET", PROFILES, 200, pageOf(profileBody("radius_request", "framed_user", false, 1)));
        mount("POST", PROFILES, 201, profileBody("radius_request", "framed_user", false, 1));
        mount("GET", PROFILES + "/" + SEG, 200, profileBody("radius_request", "framed_user", false, 1));
        mount("PUT", PROFILES + "/" + SEG, 200, profileBody("radius_request", "framed_user", false, 2));
        mount("DELETE", PROFILES + "/" + SEG, 204, "");
        mount("GET", POLICY, 200, policyBody(3600, 0));
        mount("PUT", POLICY, 200, policyBody(7200, 1));

        NetworkApi n = client.management().network();
        n.listSegments(null, PageRequest.of(10));
        n.createSegment(new CreateNetworkSegmentRequest(null, null, NetworkSegmentKind.ACCESS, "lab", 1, "default", 120));
        n.getSegment(SEG);
        n.replaceSegment(SEG, new ReplaceNetworkSegmentRequest(true, List.of(), null, 1L, 120));
        n.deleteSegment(SEG, 2);
        n.listProfiles(PageRequest.of(10));
        n.createProfile(new CreateNetworkReplyProfileRequest(input(), SEG, 2L));
        n.getProfile(SEG);
        n.replaceProfile(SEG, new ReplaceNetworkReplyProfileRequest(input(), 2L, 1L));
        n.deleteProfile(SEG, 2);
        n.getPolicy();
        n.replacePolicy(new ReplaceNetworkPolicyRequest(7200, 0L));
        assertTrue(unmatched().isEmpty(), "every call reached a registry route: " + unmatched());
    }

    static String policyBody(int cap, long version) {
        return ("{\"tenant_id\":\"%s\",\"session_timeout_max_secs\":%d,\"version\":%d%s}")
                .formatted(TENANT_ID, cap, version,
                        version == 0 ? "" : ",\"updated_by\":\"" + EXAMPLE_ID + "\",\"updated_at\":\"2026-10-16T00:00:00Z\"");
    }

    // -- 2. Versions ---------------------------------------------------------------------------

    @Test
    void versionsAreSentExactlyAsGivenAndADeleteCannotBeCalledWithoutOne() throws Exception {
        Route replaceSegment = mount("PUT", SEGMENTS + "/" + SEG, 200, segmentBody("access", 8));
        Route deleteSegment = mount("DELETE", SEGMENTS + "/" + SEG, 204, "");
        Route createProfile = mount("POST", PROFILES, 201, profileBody("radius_request", null, false, 1));
        Route replaceProfile = mount("PUT", PROFILES + "/" + SEG, 200, profileBody("radius_request", null, false, 5));
        Route deleteProfile = mount("DELETE", PROFILES + "/" + SEG, 204, "");
        Route replacePolicy = mount("PUT", POLICY, 200, policyBody(7200, 1));
        NetworkApi n = client.management().network();

        n.replaceSegment(SEG, new ReplaceNetworkSegmentRequest(true, List.of("a"), 3, 7L, 120));
        assertEquals(7, replaceSegment.last().json().path("version").asLong());
        n.deleteSegment(SEG, 9);
        assertEquals("9", deleteSegment.last().query().get("version"));
        n.deleteProfile(SEG, 4);
        assertEquals("4", deleteProfile.last().query().get("version"));
        n.createProfile(new CreateNetworkReplyProfileRequest(input(), SEG, 11L));
        assertEquals(11, createProfile.last().json().path("segment_version").asLong());
        assertEquals(SEG.toString(), createProfile.last().json().path("segment_id").asText());
        n.replaceProfile(SEG, new ReplaceNetworkReplyProfileRequest(input(), 12L, 5L));
        assertEquals(5, replaceProfile.last().json().path("version").asLong());
        assertEquals(12, replaceProfile.last().json().path("segment_version").asLong());
        n.replacePolicy(new ReplaceNetworkPolicyRequest(7200, 0L));
        assertEquals(0, replacePolicy.last().json().path("version").asLong(), "0 is the first write, sent as given");

        // "cannot be called without one": the delete's version is a primitive long.
        for (String name : List.of("deleteSegment", "deleteProfile")) {
            Method m = Arrays.stream(NetworkApi.class.getDeclaredMethods())
                    .filter(x -> x.getName().equals(name)).findFirst().orElseThrow();
            assertEquals(long.class, m.getParameterTypes()[1], name + " takes a primitive version");
        }
    }

    @Test
    void aConflictToEachWriteIsOneRequestAndExposesTheReasonCode() throws Exception {
        String stale = "{\"error\":\"conflict\",\"message\":\"stale\",\"reason_code\":\"stale_version\"}";
        List<Route> routes = List.of(
                mount("POST", SEGMENTS, 409, stale),
                mount("PUT", SEGMENTS + "/" + SEG, 409, stale),
                mount("DELETE", SEGMENTS + "/" + SEG, 409, stale),
                mount("POST", PROFILES, 409, stale),
                mount("PUT", PROFILES + "/" + SEG, 409, stale),
                mount("DELETE", PROFILES + "/" + SEG, 409, stale),
                mount("PUT", POLICY, 409, stale));
        NetworkApi n = client.management().network();
        List<Executable> writes = List.of(
                () -> n.createSegment(new CreateNetworkSegmentRequest(null, null, NetworkSegmentKind.ACCESS, "lab", 1, "default", 120)),
                () -> n.replaceSegment(SEG, new ReplaceNetworkSegmentRequest(true, List.of(), null, 1L, 120)),
                () -> n.deleteSegment(SEG, 1),
                () -> n.createProfile(new CreateNetworkReplyProfileRequest(input(), SEG, 1L)),
                () -> n.replaceProfile(SEG, new ReplaceNetworkReplyProfileRequest(input(), 1L, 1L)),
                () -> n.deleteProfile(SEG, 1),
                () -> n.replacePolicy(new ReplaceNetworkPolicyRequest(7200, 0L)));
        for (Executable write : writes) {
            ConflictError e = assertThrows(ConflictError.class, write);
            assertEquals("stale_version", e.reasonCode());
        }
        for (Route r : routes) {
            assertEquals(1, r.calls(), "a 409 is never retried");
        }

        // already_exists + duplicate_vlan is a ConflictError that exposes it too.
        Route dup = mount("POST", SEGMENTS, 409,
                "{\"error\":\"already_exists\",\"message\":\"vlan\",\"reason_code\":\"duplicate_vlan\"}");
        ConflictError e = assertThrows(ConflictError.class, writes.get(0));
        assertEquals("duplicate_vlan", e.reasonCode());
        assertEquals(1, dup.calls());
    }

    @Test
    void aReasonCodeThisSdkDoesNotKnowIsSurfacedVerbatimAndAnAbsentOneIsNull() throws Exception {
        mount("DELETE", SEGMENTS + "/" + SEG, 409,
                "{\"error\":\"conflict\",\"message\":\"m\",\"reason_code\":\"a_future_reason\"}");
        ConflictError known = assertThrows(ConflictError.class,
                () -> client.management().network().deleteSegment(SEG, 1));
        assertEquals("a_future_reason", known.reasonCode());

        mount("DELETE", PROFILES + "/" + SEG, 409, "{\"error\":\"conflict\",\"message\":\"a server before 1.62\"}");
        ConflictError none = assertThrows(ConflictError.class,
                () -> client.management().network().deleteProfile(SEG, 1));
        assertNull(none.reasonCode(), "absent when a server predating it omits it");

        mount("DELETE", SEGMENTS + "/" + EXAMPLE_ID, 409, "not json at all");
        assertNull(assertThrows(ConflictError.class,
                () -> client.management().network().deleteSegment(EXAMPLE_ID, 1)).reasonCode());
    }

    // -- 3. Closed bodies ----------------------------------------------------------------------

    @Test
    void theRequestBodiesCarryExactlyTheKeysSectionTwoNames() throws Exception {
        Route createSegment = mount("POST", SEGMENTS, 201, segmentBody("access", 1));
        Route replaceSegment = mount("PUT", SEGMENTS + "/" + SEG, 200, segmentBody("access", 2));
        Route createProfile = mount("POST", PROFILES, 201, profileBody("radius_request", null, false, 1));
        Route replacePolicy = mount("PUT", POLICY, 200, policyBody(7200, 1));
        NetworkApi n = client.management().network();

        n.createSegment(new CreateNetworkSegmentRequest(null, null, NetworkSegmentKind.QUARANTINE, "q", null, "default", 999));
        assertEquals(List.of("kind", "name", "site_key", "vlan_id"), createSegment.last().keys(),
                "unset rank, filter_ids and enabled are absent, not null");
        assertEquals("quarantine", createSegment.last().json().path("kind").asText());

        n.replaceSegment(SEG, new ReplaceNetworkSegmentRequest(false, List.of(), null, 3L, 5));
        assertEquals(List.of("enabled", "filter_ids", "version", "vlan_id"), replaceSegment.last().keys(),
                "no kind, site_key or name on a replacement; an unset rank is absent");

        n.createProfile(new CreateNetworkReplyProfileRequest(input(), SEG, 1L));
        assertEquals(List.of("profile", "segment_id", "segment_version"), createProfile.last().keys());
        assertEquals(List.of("session_timeout_secs"),
                names(createProfile.last().json().path("profile")),
                "an unset idle_timeout_secs, filter_id, service_type and termination_action are absent");

        n.replacePolicy(new ReplaceNetworkPolicyRequest(7200, 0L));
        assertEquals(List.of("session_timeout_max_secs", "version"), replacePolicy.last().keys());

        // The profile as written has no VLAN member: the VLAN is the segment's.
        List<String> components = Arrays.stream(NetworkReplyProfileInput.class.getRecordComponents())
                .map(RecordComponent::getName).toList();
        assertFalse(components.stream().anyMatch(c -> c.toLowerCase().contains("vlan")), components.toString());
    }

    private static List<String> names(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.fieldNames().forEachRemaining(out::add);
        out.sort(String::compareTo);
        return out;
    }

    @Test
    void theReplaceTypesCannotBeBuiltWithoutTheirRequiredMembers() throws Exception {
        assertCannotBeBuiltWithout(new ReplaceNetworkSegmentRequest(true, List.of(), 1, 1L, 120),
                "enabled", "filter_ids", "version", "vlan_id");
        assertCannotBeBuiltWithout(new ReplaceNetworkReplyProfileRequest(input(), 1L, 1L),
                "profile", "segment_version", "version");
        assertCannotBeBuiltWithout(new ReplaceNetworkPolicyRequest(3600, 0L),
                "session_timeout_max_secs", "version");
    }

    // -- 4. Open decoding and pagination ------------------------------------------------------

    @Test
    void anUnknownEnumerationDecodesAndANeverResentUnknownIsDistinctFromAKnownOne() throws Exception {
        NetworkSegmentResponse segment = JSON.readValue(segmentBody("hybrid", 1), NetworkSegmentResponse.class);
        assertEquals(NetworkSegmentKind.UNKNOWN, segment.kind());
        assertEquals(List.of("lab-in", "lab-out"), segment.filterIds());

        NetworkReplyProfile profile = JSON.readValue(
                profileBody("future_action", "future_type", true, 3), NetworkReplyProfile.class);
        assertEquals(RadiusTerminationAction.UNKNOWN, profile.terminationAction());
        assertEquals(RadiusServiceType.UNKNOWN, profile.serviceType());
        assertTrue(profile.sessionTimeoutClamped(), "a clamped profile decodes with both members");
        assertEquals(3600, profile.sessionTimeoutSecs());
        assertEquals(3L, profile.version());

        NetworkPolicyResponse policy = JSON.readValue(policyBody(3600, 0), NetworkPolicyResponse.class);
        assertNull(policy.updatedAt(), "absent while it is the default");
        assertNull(policy.updatedBy());
        assertEquals(0L, policy.version());
    }

    @Test
    void bothListsReturnPagesWithATotalAndThePagerCarriesSearchAndSiteOnEveryRequest() throws Exception {
        Route segments = mountTwoPages(SEGMENTS, () -> segmentBody("access", 1));
        Route profiles = mountTwoPages(PROFILES, () -> profileBody("radius_request", null, false, 1));
        NetworkApi n = client.management().network();

        Page<NetworkSegmentResponse> page = n.listSegments("default", PageRequest.matching(1, "lab"));
        assertEquals(2, page.total());
        assertEquals(2, n.listSegmentsAll("default", PageRequest.matching(1, "lab")).size());
        for (Recorded r : segments.requests()) {
            assertEquals("lab", r.query().get("search"), "the pager carries search on every page");
            assertEquals("default", r.query().get("site"), "and site");
        }

        assertEquals(2, n.listProfiles(PageRequest.matching(1, "lab-in")).total());
        assertEquals(2, n.listProfilesAll(PageRequest.matching(1, "lab-in")).size());
        for (Recorded r : profiles.requests()) {
            assertEquals("lab-in", r.query().get("search"));
        }
    }

    // -- 5. Errors -----------------------------------------------------------------------------

    @Test
    void errorsMapToTheTaxonomy() throws Exception {
        NetworkApi n = client.management().network();

        mount("PUT", PROFILES + "/" + SEG, 403,
                "{\"error\":\"authorization_denied\",\"message\":\"no\",\"action\":\"network:grant\","
                        + "\"resource_id\":\"" + SEG + "\"}");
        AuthzError denied = assertThrows(AuthzError.class,
                () -> n.replaceProfile(SEG, new ReplaceNetworkReplyProfileRequest(input(), 1L, 1L)));
        assertEquals("network:grant", denied.action());
        assertEquals(SEG.toString(), denied.resourceId());

        mount("POST", SEGMENTS, 400, "{\"error\":\"validation_error\",\"message\":\"vlan_id out of range\"}");
        ValidationError invalid = assertThrows(ValidationError.class, () -> n.createSegment(
                new CreateNetworkSegmentRequest(null, null, NetworkSegmentKind.ACCESS, "lab", 1, "default", 99999)));
        assertTrue(invalid.getMessage().contains("vlan_id out of range"), invalid.getMessage());

        mount("GET", PROFILES + "/" + SEG, 404, "{\"error\":\"not_found\",\"message\":\"no profile\"}");
        assertThrows(NotFoundError.class, () -> n.getProfile(SEG));

        mount("GET", POLICY, 401, "{\"error\":\"unauthorized\",\"message\":\"a service-account token\"}");
        assertThrows(AuthError.class, n::getPolicy);
    }

    @Test
    void a429And503OnEachWriteIsANetworkErrorAfterExactlyOneRequest() throws Exception {
        for (int status : new int[] {429, 503}) {
            List<Route> routes = List.of(
                    mount("POST", SEGMENTS, status, ""),
                    mount("PUT", SEGMENTS + "/" + SEG, status, ""),
                    mount("DELETE", SEGMENTS + "/" + SEG, status, ""),
                    mount("POST", PROFILES, status, ""),
                    mount("PUT", PROFILES + "/" + SEG, status, ""),
                    mount("DELETE", PROFILES + "/" + SEG, status, ""),
                    mount("PUT", POLICY, status, ""));
            NetworkApi n = client.management().network();
            List<Executable> writes = List.of(
                    () -> n.createSegment(new CreateNetworkSegmentRequest(null, null, NetworkSegmentKind.ACCESS, "lab", 1, "default", 120)),
                    () -> n.replaceSegment(SEG, new ReplaceNetworkSegmentRequest(true, List.of(), null, 1L, 120)),
                    () -> n.deleteSegment(SEG, 1),
                    () -> n.createProfile(new CreateNetworkReplyProfileRequest(input(), SEG, 1L)),
                    () -> n.replaceProfile(SEG, new ReplaceNetworkReplyProfileRequest(input(), 1L, 1L)),
                    () -> n.deleteProfile(SEG, 1),
                    () -> n.replacePolicy(new ReplaceNetworkPolicyRequest(7200, 0L)));
            for (Executable write : writes) {
                NetworkError e = assertThrows(NetworkError.class, write);
                assertFalse(e instanceof ValidationError);
            }
            for (Route r : routes) {
                assertEquals(1, r.calls(), status + ": exactly one request per write");
            }
        }
    }
}
