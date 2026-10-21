package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.NetworkSegmentKind;
import io.axiam.sdk.management.models.RadiusServiceType;
import io.axiam.sdk.management.models.RadiusTerminationAction;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;27.6.2 and the "Manifest, {@code network}" tests of &sect;27.9 (contract
 * 1.62): the {@code network} namespace in the declarative layer.
 *
 * <p>Natural keys (a segment by site + kind + name, a profile by its segment, the policy a
 * singleton), the order (policy, segments, profiles), drift judged on the read, {@code
 * filter_ids} as a set, the version-conditional full-body {@code replace_*} bodies, and a
 * {@code 409} or {@code 403} as the action's failure with no retry.
 */
class NetworkManifestTest extends ManagementTestBase {

    private static final String SEGMENTS = "/api/v1/network/segments";
    private static final String PROFILES = "/api/v1/network/profiles";
    private static final String POLICY = "/api/v1/network/policy";

    private static final UUID LAB = UUID.fromString("0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a01");
    private static final UUID GUEST = UUID.fromString("0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a02");

    private final List<String> wire = Collections.synchronizedList(new ArrayList<>());

    // -- fixtures -------------------------------------------------------------------------------

    private static String segment(UUID id, String name, String kind, int vlan, String filterIds,
                                  Integer rank, boolean enabled, long version) {
        return ("{\"id\":\"%s\",\"tenant_id\":\"%s\",\"path\":\"/network/zones/default/%s\","
                + "\"name\":\"%s\",\"site_key\":\"default\",\"kind\":\"%s\",\"vlan_id\":%d,"
                + "\"filter_ids\":%s,%s\"enabled\":%s,\"version\":%d,\"created_by\":\"%s\","
                + "\"updated_by\":\"%s\",\"created_at\":\"2026-10-16T00:00:00Z\","
                + "\"updated_at\":\"2026-10-16T00:00:00Z\"}")
                .formatted(id, TENANT_ID, name, name, kind, vlan, filterIds,
                        rank == null ? "" : "\"rank\":" + rank + ",", enabled, version, EXAMPLE_ID, EXAMPLE_ID);
    }

    private static String labSegment(long version) {
        return segment(LAB, "lab", "access", 120, "[\"lab-in\",\"lab-out\"]", 1, true, version);
    }

    private static String profile(UUID segmentId, int timeout, boolean clamped, String termination,
                                  Integer idle, String filterId, String serviceType, long version) {
        return ("{\"segment_id\":\"%s\",\"tenant_id\":\"%s\",\"dictionary\":\"axiam-radius-reply/1\","
                + "\"session_timeout_secs\":%d,\"session_timeout_clamped\":%s,\"termination_action\":\"%s\","
                + "%s%s%s\"version\":%d,\"created_by\":\"%s\",\"updated_by\":\"%s\","
                + "\"created_at\":\"2026-10-16T00:00:00Z\",\"updated_at\":\"2026-10-16T00:00:00Z\"}")
                .formatted(segmentId, TENANT_ID, timeout, clamped, termination,
                        idle == null ? "" : "\"idle_timeout_secs\":" + idle + ",",
                        filterId == null ? "" : "\"filter_id\":\"" + filterId + "\",",
                        serviceType == null ? "" : "\"service_type\":\"" + serviceType + "\",",
                        version, EXAMPLE_ID, EXAMPLE_ID);
    }

    private static String labProfile() {
        return profile(LAB, 3600, false, "radius_request", 600, "lab-in", "framed_user", 5);
    }

    private static String page(String... items) {
        return "{\"items\":[" + String.join(",", items) + "],\"total\":" + items.length
                + ",\"offset\":0,\"limit\":200}";
    }

    private static String policy(int cap, long version) {
        return NetworkManagementTest.policyBody(cap, version);
    }

    private void mountEmptyTenant() {
        for (String path : List.of("resources", "permissions", "roles", "groups", "users")) {
            mount("GET", "/api/v1/" + path, 200, pageOf(null));
        }
    }

    private void mountReads(String policyBody, String segments, String profiles) {
        mountEmptyTenant();
        mount("GET", POLICY, 200, policyBody);
        mount("GET", SEGMENTS, 200, segments);
        mount("GET", PROFILES, 200, profiles);
    }

    /** A route that records its call, in wire order, and answers {@code body}. */
    private Route record(String method, String path, int status, String label, String body) {
        return mountDynamic(method, path, status, r -> {
            wire.add(label);
            return body;
        });
    }

    private static ManagementManifest.SegmentSpec lab() {
        return ManagementManifest.SegmentSpec.access("lab", "default", "lab", 120, 1)
                .withFilterIds(List.of("lab-in", "lab-out")).withEnabled(true);
    }

    private ManagementManifest manifest(ManagementManifest.SegmentSpec segment,
                                        ManagementManifest.ProfileSpec profile, Integer cap) {
        ManagementManifest.Builder b = ManagementManifest.builder();
        if (cap != null) {
            b.networkPolicy(cap);
        }
        if (segment != null) {
            b.networkSegment(segment);
        }
        if (profile != null) {
            b.networkProfile(profile);
        }
        return b.build();
    }

    private static List<ManagementPlan.Change> changes(ManagementPlan plan, ManagementPlan.Target target) {
        return plan.actions().stream().filter(a -> a.target() == target)
                .map(ManagementPlan.PlannedAction::change).toList();
    }

    private static List<String> keys(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.fieldNames().forEachRemaining(out::add);
        Collections.sort(out);
        return out;
    }

    // -- plan reads only, in the section's order -----------------------------------------------

    @Test
    void planOfAPolicyASegmentAndAProfileIssuesGetsOnly() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        ManagementManifest m = manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 3600), 3600);

        ManagementPlan plan = client.management().manifest().plan(m);

        assertTrue(unmatched().isEmpty(), "plan reached a route it should not have: " + unmatched());
        assertEquals(1, route("GET", POLICY).calls());
        assertEquals(1, route("GET", SEGMENTS).calls());
        assertEquals(1, route("GET", PROFILES).calls());
        // The policy always exists, so it is never a Create; the others are Creates here.
        assertEquals(List.of(ManagementPlan.Change.NO_CHANGE), changes(plan, ManagementPlan.Target.NETWORK_POLICY));
        assertEquals(List.of(ManagementPlan.Change.CREATE), changes(plan, ManagementPlan.Target.NETWORK_SEGMENT));
        assertEquals(List.of(ManagementPlan.Change.CREATE), changes(plan, ManagementPlan.Target.NETWORK_PROFILE));
    }

    @Test
    void theOrderIsPolicyThenSegmentsThenProfilesAfterEverythingElse() throws Exception {
        mountReads(policy(3600, 2), page(), page());
        ManagementManifest m = ManagementManifest.builder()
                .networkProfile(ManagementManifest.ProfileSpec.of("guest", 1800))
                .networkSegment(lab())
                .networkSegment(ManagementManifest.SegmentSpec.quarantine("guest", "default", "guest", 999))
                .networkProfile(ManagementManifest.ProfileSpec.of("lab", 3600))
                .networkPolicy(7200)
                .permission("read", "document:read", "Read")
                .build();

        List<ManagementPlan.Target> targets = client.management().manifest().plan(m).actions().stream()
                .map(ManagementPlan.PlannedAction::target).toList();

        assertEquals(List.of(ManagementPlan.Target.PERMISSION,
                ManagementPlan.Target.NETWORK_POLICY,
                ManagementPlan.Target.NETWORK_SEGMENT, ManagementPlan.Target.NETWORK_SEGMENT,
                ManagementPlan.Target.NETWORK_PROFILE, ManagementPlan.Target.NETWORK_PROFILE), targets);
        // A profile follows its segment: the profiles' order is the segments' (lab, then guest).
        List<String> profileKeys = client.management().manifest().plan(m).actions().stream()
                .filter(a -> a.target() == ManagementPlan.Target.NETWORK_PROFILE)
                .map(ManagementPlan.PlannedAction::key).toList();
        assertEquals(List.of("lab", "guest"), profileKeys);
    }

    @Test
    void aManifestWithoutANetworkSectionMakesNoNetworkRequest() throws Exception {
        mountEmptyTenant();
        client.management().manifest().plan(ManagementManifest.builder()
                .permission("read", "document:read", "Read").build());
        assertTrue(unmatched().isEmpty(), "no network route was asked for: " + unmatched());
    }

    // -- apply on an empty tenant: create_segment, then create_profile -------------------------

    @Test
    void applyCreatesTheSegmentThenTheProfileWithTheNewSegmentsIdAndVersion() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        record("POST", SEGMENTS, 201, "create_segment", labSegment(4));
        Route createProfile = record("POST", PROFILES, 201, "create_profile", labProfile());
        ManagementManifest m = manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 3600)
                .withIdleTimeoutSecs(600).withFilterId("lab-in"), 3600);

        ApplyReport report = client.management().manifest().apply(m);

        assertTrue(report.isComplete(), report.toString());
        assertEquals(List.of("create_segment", "create_profile"), wire);
        JsonNode body = createProfile.last().json();
        assertEquals(LAB.toString(), body.path("segment_id").asText(), "the new segment's id from the create response");
        assertEquals(4, body.path("segment_version").asLong(), "the version of the create response");
        assertEquals(3600, body.path("profile").path("session_timeout_secs").asInt());

        // §27.6 rule 6: plan afterwards is all NoChange.
        mountReads(policy(3600, 0), page(labSegment(4)), page(labProfile()));
        ManagementPlan after = client.management().manifest().plan(m);
        assertTrue(after.isConverged(), after.actions().toString());
    }

    @Test
    void aCreateBodyCarriesTheWireKindAndFilterIdsInTheStatedOrder() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        Route create = record("POST", SEGMENTS, 201, "create_segment", labSegment(1));
        ManagementManifest.SegmentSpec spec = ManagementManifest.SegmentSpec
                .access("lab", "default", "lab", 120, 1).withFilterIds(List.of("z-last", "a-first", "m-mid"));

        client.management().manifest().apply(manifest(spec, null, null));

        JsonNode body = create.last().json();
        assertEquals("access", body.path("kind").asText(), "the wire spelling, never zones");
        assertEquals("default", body.path("site_key").asText());
        assertEquals(List.of("z-last", "a-first", "m-mid"),
                new ObjectsList(body.path("filter_ids")).values, "the order the manifest states");
        assertEquals(List.of("filter_ids", "kind", "name", "rank", "site_key", "vlan_id"), keys(body),
                "enabled is unstated, so absent");
        // The SDK has no `zones` value: the kind enumeration is access, quarantine and "unknown".
        assertEquals(List.of("access", "quarantine", ""),
                Arrays.stream(NetworkSegmentKind.values()).map(NetworkSegmentKind::wire).toList());
    }

    /** A JSON string array as a list, for assertions. */
    private static final class ObjectsList {
        final List<String> values = new ArrayList<>();

        ObjectsList(JsonNode array) {
            array.forEach(n -> values.add(n.asText()));
        }
    }

    // -- update bodies -------------------------------------------------------------------------

    @Test
    void aSegmentUpdateSendsTheFullReplacementBodyAndNeverKindSiteOrName() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)), page());
        Route put = record("PUT", SEGMENTS + "/" + LAB, 200, "replace_segment", labSegment(6));
        // Only the VLAN is stated: rank, enabled and filter_ids are carried from the read.
        ManagementManifest.SegmentSpec spec = new ManagementManifest.SegmentSpec(
                "lab", "default", NetworkSegmentKind.ACCESS, "lab", 130, null, null, null);

        ApplyReport report = client.management().manifest().apply(manifest(spec, null, null));

        assertTrue(report.isComplete(), report.toString());
        JsonNode body = put.last().json();
        assertEquals(List.of("enabled", "filter_ids", "rank", "version", "vlan_id"), keys(body),
                "the exact key set: no kind, site_key or name");
        assertEquals(5, body.path("version").asLong(), "the version plan read");
        assertEquals(130, body.path("vlan_id").asInt());
        assertEquals(1, body.path("rank").asInt(), "carried from the read");
        assertTrue(body.path("enabled").asBoolean(), "carried from the read");
        assertEquals(List.of("lab-in", "lab-out"), new ObjectsList(body.path("filter_ids")).values);
    }

    @Test
    void aStatedNullOnAnOptionalProfileMemberLeavesTheKeyOutAndSilenceCarriesTheRead() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)), page(labProfile()));
        Route put = record("PUT", PROFILES + "/" + LAB, 200, "replace_profile", labProfile());
        // Stated: idle_timeout_secs is "none" (null). Unstated: filter_id, service_type, termination.
        ManagementManifest.ProfileSpec spec = ManagementManifest.ProfileSpec.of("lab", 3600)
                .withIdleTimeoutSecs(null);

        ManagementPlan plan = client.management().manifest().plan(manifest(lab(), spec, null));
        assertEquals(List.of(ManagementPlan.Change.NO_CHANGE), changes(plan, ManagementPlan.Target.NETWORK_SEGMENT));
        assertEquals(List.of(ManagementPlan.Change.UPDATE), changes(plan, ManagementPlan.Target.NETWORK_PROFILE),
                "the read holds an idle timeout and the manifest states none");

        client.management().manifest().apply(manifest(lab(), spec, null));

        JsonNode body = put.last().json();
        assertEquals(List.of("profile", "segment_version", "version"), keys(body));
        assertEquals(5, body.path("version").asLong(), "the profile's version as read");
        assertEquals(5, body.path("segment_version").asLong(), "the segment's version as read");
        JsonNode profile = body.path("profile");
        assertFalse(profile.has("idle_timeout_secs"), "stated null: left out, never sent as null");
        assertEquals("lab-in", profile.path("filter_id").asText(), "unstated: carried from the read");
        assertEquals("framed_user", profile.path("service_type").asText());
        assertEquals("radius_request", profile.path("termination_action").asText());
        assertEquals("axiam-radius-reply/1", profile.path("dictionary").asText());
        assertEquals(3600, profile.path("session_timeout_secs").asInt());
    }

    @Test
    void aSegmentAndItsProfileChangedInOneApplyUseTheSegmentWritesVersionForTheProfile() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)), page(labProfile()));
        record("PUT", SEGMENTS + "/" + LAB, 200, "replace_segment", labSegment(9));
        Route putProfile = record("PUT", PROFILES + "/" + LAB, 200, "replace_profile", labProfile());
        ManagementManifest.SegmentSpec segment = ManagementManifest.SegmentSpec
                .access("lab", "default", "lab", 130, 1);
        ManagementManifest.ProfileSpec profile = ManagementManifest.ProfileSpec.of("lab", 1800);

        ApplyReport report = client.management().manifest().apply(manifest(segment, profile, null));

        assertTrue(report.isComplete(), report.toString());
        assertEquals(List.of("replace_segment", "replace_profile"), wire);
        assertEquals(9, putProfile.last().json().path("segment_version").asLong(),
                "the replace_segment response's version, not the 5 that plan read");
        assertEquals(5, putProfile.last().json().path("version").asLong());
    }

    // -- 409 and 403 are the action's failure ---------------------------------------------------

    @Test
    void aStaleVersionConflictOnANetworkWriteStopsTheApplyAfterOneRequestAndExposesTheReasonCode() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)), page(labProfile()));
        Route put = mount("PUT", SEGMENTS + "/" + LAB, 409,
                "{\"error\":\"conflict\",\"message\":\"the segment changed\",\"reason_code\":\"stale_version\"}");
        Route putProfile = mount("PUT", PROFILES + "/" + LAB, 200, labProfile());
        ManagementManifest.SegmentSpec segment = ManagementManifest.SegmentSpec
                .access("lab", "default", "lab", 130, 1);

        ApplyReport report = client.management().manifest().apply(
                manifest(segment, ManagementManifest.ProfileSpec.of("lab", 1800), null));

        assertEquals(1, put.calls(), "never retried");
        assertEquals(0, putProfile.calls(), "later actions are not attempted");
        assertFalse(report.isComplete());
        ApplyReport.StepOutcome failed = report.failure().orElseThrow().outcome();
        assertEquals("stale_version", failed.reasonCode());
        assertEquals(ApplyReport.Status.FAILED, failed.status());
        List<ApplyReport.Status> statuses = report.steps().stream().map(s -> s.outcome().status()).toList();
        assertEquals(ApplyReport.Status.NOT_ATTEMPTED, statuses.get(statuses.size() - 1));
    }

    @Test
    void aDuplicateVlanConflictDoesTheSame() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        Route post = mount("POST", SEGMENTS, 409,
                "{\"error\":\"already_exists\",\"message\":\"vlan\",\"reason_code\":\"duplicate_vlan\"}");
        Route profile = mount("POST", PROFILES, 201, labProfile());

        ApplyReport report = client.management().manifest().apply(
                manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 3600), null));

        assertEquals(1, post.calls());
        assertEquals(0, profile.calls());
        assertEquals("duplicate_vlan", report.failure().orElseThrow().outcome().reasonCode());
    }

    @Test
    void aPolicyConflictStopsBeforeTheSegmentsAreTouched() throws Exception {
        mountReads(policy(3600, 2), page(), page());
        Route put = mount("PUT", POLICY, 409,
                "{\"error\":\"conflict\",\"message\":\"policy\",\"reason_code\":\"stale_version\"}");
        Route post = mount("POST", SEGMENTS, 201, labSegment(1));

        ApplyReport report = client.management().manifest().apply(manifest(lab(), null, 7200));

        assertEquals(1, put.calls());
        assertEquals(2, put.last().json().path("version").asLong(), "the policy's version as read");
        assertEquals(7200, put.last().json().path("session_timeout_max_secs").asInt());
        assertEquals(0, post.calls());
        assertEquals("stale_version", report.failure().orElseThrow().outcome().reasonCode());
    }

    @Test
    void aClampedProfileIsJudgedOnTheReadAndAValueAboveTheCapIsRefusedByTheServerNotAdjusted() throws Exception {
        String clamped = profile(LAB, 1800, true, "radius_request", null, null, null, 5);
        mountReads(policy(1800, 3), page(labSegment(5), segment(GUEST, "guest", "access", 140,
                "[]", 2, true, 7)), page(clamped));

        // Stating the cap itself is NoChange: the stored value is neither restored nor rewritten.
        ManagementPlan same = client.management().manifest().plan(
                manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 1800), null));
        assertEquals(List.of(ManagementPlan.Change.NO_CHANGE), changes(same, ManagementPlan.Target.NETWORK_PROFILE));

        // Stating more than the cap differs from the read: an Update, and apply sends it as is.
        Route put = mount("PUT", PROFILES + "/" + LAB, 403,
                "{\"error\":\"authorization_denied\","
                        + "\"message\":\"session_timeout_secs is above the tenant's cap of 1800\"}");
        Route later = mount("POST", PROFILES, 201, labProfile());
        ManagementManifest m = ManagementManifest.builder()
                .networkSegment(lab())
                .networkSegment(ManagementManifest.SegmentSpec.access("guest", "default", "guest", 140, 2)
                        .withFilterIds(List.of()).withEnabled(true))
                .networkProfile(ManagementManifest.ProfileSpec.of("lab", 7200))
                .networkProfile(ManagementManifest.ProfileSpec.of("guest", 600))
                .build();
        ManagementPlan plan = client.management().manifest().plan(m);
        assertEquals(List.of(ManagementPlan.Change.UPDATE, ManagementPlan.Change.CREATE),
                changes(plan, ManagementPlan.Target.NETWORK_PROFILE));

        ApplyReport report = client.management().manifest().apply(m);

        assertEquals(1, put.calls(), "exactly one replace_profile, no retry");
        assertEquals(7200, put.last().json().path("profile").path("session_timeout_secs").asInt(),
                "nothing is lowered to the cap by the SDK");
        assertEquals(0, later.calls(), "later actions are not attempted");
        ApplyReport.StepOutcome failed = report.failure().orElseThrow().outcome();
        assertTrue(failed.message().contains("above the tenant's cap of 1800"), failed.message());
        assertNull(failed.reasonCode(), "a 403 is not a 409");
    }

    @Test
    void anUnknownEnumerationOnTheReadIsRefusedAtPlanWithNoWriteUnlessTheManifestStatesIt() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)),
                page(profile(LAB, 3600, false, "future", 600, "lab-in", "framed_user", 5)));
        Route put = mount("PUT", PROFILES + "/" + LAB, 200, labProfile());
        ManagementManifest other = manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 1800), null);

        ValidationError e = assertThrows(ValidationError.class, () -> client.management().manifest().plan(other));
        assertTrue(e.getMessage().contains("termination_action"), e.getMessage());
        assertThrows(ValidationError.class, () -> client.management().manifest().apply(other));
        assertEquals(0, put.calls(), "§27.6.2 item 4: refused before any write");

        // The same for service_type.
        mountReads(policy(3600, 0), page(labSegment(5)),
                page(profile(LAB, 3600, false, "radius_request", 600, "lab-in", "a_future_service", 5)));
        ValidationError s = assertThrows(ValidationError.class, () -> client.management().manifest().plan(other));
        assertTrue(s.getMessage().contains("service_type"), s.getMessage());

        // Stating the member is the way out: a stated value is sent.
        mountReads(policy(3600, 0), page(labSegment(5)),
                page(profile(LAB, 3600, false, "future", 600, "lab-in", "framed_user", 5)));
        put = mount("PUT", PROFILES + "/" + LAB, 200, labProfile());
        client.management().manifest().apply(manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 1800)
                .withTerminationAction(RadiusTerminationAction.RADIUS_REQUEST), null));
        assertEquals("radius_request", put.last().json().path("profile").path("termination_action").asText());
        assertEquals(RadiusServiceType.FRAMED_USER, RadiusServiceType.fromWire("framed_user"));
    }

    // -- refusals with zero wire calls ----------------------------------------------------------

    @Test
    void duplicateNaturalKeysAndADanglingProfileAreRefusedBeforeAnyRequest() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        int before = totalCalls();

        // Two segments with one site, kind and name (different manifest keys).
        ManagementManifest.Builder twice = ManagementManifest.builder()
                .networkSegment(ManagementManifest.SegmentSpec.access("a", "default", "lab", 120, 1))
                .networkSegment(ManagementManifest.SegmentSpec.access("b", "default", "lab", 121, 2));
        NetworkError e = assertThrows(NetworkError.class, twice::build);
        assertTrue(e.getMessage().contains("default/access/lab"), e.getMessage());

        // The same name under another kind is another segment, not a duplicate.
        ManagementManifest ok = ManagementManifest.builder()
                .networkSegment(ManagementManifest.SegmentSpec.access("a", "default", "lab", 120, 1))
                .networkSegment(ManagementManifest.SegmentSpec.quarantine("b", "default", "lab", 999))
                .build();
        assertEquals(2, ok.network().segments().size());

        // A profile whose segment no spec declares is a dangling key.
        ManagementManifest.Builder dangling = ManagementManifest.builder()
                .networkSegment(lab()).networkProfile(ManagementManifest.ProfileSpec.of("nope", 3600));
        assertTrue(assertThrows(NetworkError.class, dangling::build).getMessage()
                .contains("which no segment declares"));

        // Two profiles for one segment, and two policies.
        assertThrows(NetworkError.class, () -> ManagementManifest.builder().networkSegment(lab())
                .networkProfile(ManagementManifest.ProfileSpec.of("lab", 3600))
                .networkProfile(ManagementManifest.ProfileSpec.of("lab", 1800)).build());
        assertThrows(NetworkError.class, () -> ManagementManifest.builder()
                .networkPolicy(3600).networkPolicy(7200).build());

        // And at plan and apply, for a manifest built through the record form.
        ManagementManifest raw = new ManagementManifest(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), new ManagementManifest.NetworkSpec(List.of(),
                        List.of(ManagementManifest.SegmentSpec.access("a", "default", "lab", 120, 1),
                                ManagementManifest.SegmentSpec.access("b", "default", "lab", 121, 2)),
                        List.of(ManagementManifest.ProfileSpec.of("nowhere", 3600))));
        assertThrows(NetworkError.class, () -> client.management().manifest().plan(raw));
        assertThrows(NetworkError.class, () -> client.management().manifest().apply(raw));

        assertEquals(before, totalCalls(), "zero wire calls for every refusal");
    }

    @Test
    void aSegmentListingOneFilterIdTwiceIsRefusedAtPlanAndApplyWithZeroWireCalls() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        int before = totalCalls();
        ManagementManifest.SegmentSpec dup = ManagementManifest.SegmentSpec
                .access("lab", "default", "lab", 120, 1).withFilterIds(List.of("lab-in", "lab-out", "lab-in"));

        assertThrows(NetworkError.class, () -> manifest(dup, null, null));
        ManagementManifest raw = new ManagementManifest(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), new ManagementManifest.NetworkSpec(List.of(), List.of(dup), List.of()));
        NetworkError atPlan = assertThrows(NetworkError.class, () -> client.management().manifest().plan(raw));
        assertTrue(atPlan.getMessage().contains("lab-in"), atPlan.getMessage());
        assertThrows(NetworkError.class, () -> client.management().manifest().apply(raw));
        assertEquals(before, totalCalls());
    }

    // -- filter_ids is a set ---------------------------------------------------------------------

    @Test
    void filterIdsInAnotherOrderAreNoChangeAndApplyWritesNothing() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)), page());
        Route put = mount("PUT", SEGMENTS + "/" + LAB, 200, labSegment(6));
        ManagementManifest.SegmentSpec reordered = ManagementManifest.SegmentSpec
                .access("lab", "default", "lab", 120, 1).withFilterIds(List.of("lab-out", "lab-in"));

        ManagementPlan plan = client.management().manifest().plan(manifest(reordered, null, null));
        assertEquals(List.of(ManagementPlan.Change.NO_CHANGE), changes(plan, ManagementPlan.Target.NETWORK_SEGMENT));
        ApplyReport report = client.management().manifest().apply(manifest(reordered, null, null));
        assertTrue(report.isComplete());
        assertEquals(0, put.calls(), "a reorder alone is never an Update");
    }

    @Test
    void anUpdateForAnotherMemberSendsFilterIdsInTheOrderTheManifestStates() throws Exception {
        mountReads(policy(3600, 0), page(labSegment(5)), page());
        Route put = mount("PUT", SEGMENTS + "/" + LAB, 200, labSegment(6));
        ManagementManifest.SegmentSpec spec = ManagementManifest.SegmentSpec
                .access("lab", "default", "lab", 130, 1).withFilterIds(List.of("lab-out", "lab-in"));

        client.management().manifest().apply(manifest(spec, null, null));

        assertEquals(List.of("lab-out", "lab-in"), new ObjectsList(put.last().json().path("filter_ids")).values,
                "the order the manifest states, not the read's and not sorted");
    }

    @Test
    void aSegmentOfAnotherKindOrSiteIsNotTheSameSegment() throws Exception {
        // The server holds a QUARANTINE segment named "lab"; the manifest states an ACCESS "lab".
        mountReads(policy(3600, 0), page(segment(LAB, "lab", "quarantine", 999, "[]", null, true, 5)), page());

        ManagementPlan plan = client.management().manifest().plan(manifest(lab(), null, null));

        assertEquals(List.of(ManagementPlan.Change.CREATE), changes(plan, ManagementPlan.Target.NETWORK_SEGMENT),
                "the natural key is site + kind + name");
    }

    // -- the policy -----------------------------------------------------------------------------

    @Test
    void thePolicyIsNeverACreateAndAStatedDifferentCapIsAnUpdateWithTheVersionRead() throws Exception {
        mountReads(policy(3600, 0), page(), page());
        Route put = record("PUT", POLICY, 200, "replace_policy", policy(7200, 1));

        ManagementManifest m = manifest(null, null, 7200);
        assertEquals(List.of(ManagementPlan.Change.UPDATE),
                changes(client.management().manifest().plan(m), ManagementPlan.Target.NETWORK_POLICY));
        client.management().manifest().apply(m);
        assertEquals(0, put.last().json().path("version").asLong(), "0 is the first write, as read");
        assertEquals(List.of("session_timeout_max_secs", "version"), put.last().keys());

        mountReads(policy(7200, 1), page(), page());
        assertEquals(List.of(ManagementPlan.Change.NO_CHANGE),
                changes(client.management().manifest().plan(m), ManagementPlan.Target.NETWORK_POLICY));
    }

    // -- pruning is not offered -----------------------------------------------------------------

    @Test
    void thisSdkOffersNoPruningSoASegmentTheManifestDoesNotStateIsNeverDeleted() throws Exception {
        // §27.6 rule 4 / §27.6.2 item 6: pruning is opt-in per namespace and off by default; this
        // SDK's declarative layer has no prune at all (no namespace has one), so an extra segment
        // and its profile on the server produce no action and no DELETE.
        mountReads(policy(3600, 0), page(labSegment(5), segment(GUEST, "guest", "access", 140, "[]", 2, true, 3)),
                page(labProfile()));
        // No DELETE route is mounted: a delete would be recorded as unmatched.
        ManagementManifest m = manifest(lab(), ManagementManifest.ProfileSpec.of("lab", 3600)
                .withIdleTimeoutSecs(600).withFilterId("lab-in").withServiceType(RadiusServiceType.FRAMED_USER), null);

        ManagementPlan plan = client.management().manifest().plan(m);
        client.management().manifest().apply(m);

        assertTrue(plan.isConverged(), plan.actions().toString());
        assertTrue(unmatched().isEmpty(), unmatched().toString());
    }
}
