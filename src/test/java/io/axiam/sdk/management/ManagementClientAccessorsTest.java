package io.axiam.sdk.management;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * CONTRACT §27.2/§27.3 — the namespace handles sit on the client.
 *
 * <p>§27.3's Java row is {@code client.serviceAccounts().rotateSecret(id)}, and §27.2
 * rule 4 makes the single {@code management()} accessor the <em>additional</em> one. Both
 * forms therefore exist, and rule 4 requires that "where an SDK offers both, the two MUST
 * return equivalent handles".
 *
 * <p>Equivalent means the same <em>request</em>, not merely the same type — a direct
 * accessor that built a handle with a default scope instead of the client's would return
 * the right type and address the wrong organization. So the assertions below compare what
 * each form actually put on the wire.
 */
class ManagementClientAccessorsTest extends ManagementTestBase {

    /**
     * Every namespace the aggregate exposes is also directly on the client, and both
     * forms hand back the same kind of handle.
     *
     * <p>Every one of the twenty-four is invoked, not a representative sample. A
     * forwarding accessor is one line, and one line is exactly where a copy-paste sends
     * {@code pgpKeys()} to {@code pgpKeys()}'s neighbour — a mistake that compiles, that
     * a sample would miss, and that this catches by comparing the returned type.
     */
    @Test
    void everyNamespaceIsReachableBothWays() throws Exception {
        Set<String> onAggregate = Arrays.stream(ManagementApi.class.getDeclaredMethods())
                .filter(m -> m.getParameterCount() == 0)
                .filter(m -> m.getReturnType().getSimpleName().endsWith("Api"))
                .filter(m -> !m.getName().equals("manifest"))
                .map(Method::getName)
                .collect(Collectors.toSet());

        Set<String> onClient = Arrays.stream(io.axiam.sdk.AxiamClient.class.getMethods())
                .filter(m -> m.getParameterCount() == 0)
                .map(Method::getName)
                .collect(Collectors.toSet());

        assertTrue(!onAggregate.isEmpty(), "the aggregate declares no namespaces");
        ManagementApi aggregate = client.management();
        for (String name : onAggregate) {
            assertTrue(onClient.contains(name),
                    "§27.3 puts `" + name + "` on the client, not only behind management()");

            Object direct = io.axiam.sdk.AxiamClient.class.getMethod(name).invoke(client);
            Object viaAggregate = ManagementApi.class.getMethod(name).invoke(aggregate);

            assertNotNull(direct, name + "() returned null");
            assertEquals(viaAggregate.getClass(), direct.getClass(),
                    "client." + name + "() and management()." + name
                            + "() must return the same kind of handle (§27.2 rule 4)");
        }
        // 24 namespaces. Pinned so a partial regeneration that dropped one fails here
        // rather than quietly shipping 23.
        assertEquals(24, onAggregate.size());
    }

    /** Both forms reach the same route with the client's own scope. */
    @Test
    void theTwoFormsIssueTheSameRequest() throws Exception {
        Route route = mount("GET", "/api/v1/roles", 200, pageOf(null));

        client.roles().list(null);
        assertEquals(1, route.calls());
        Recorded direct = route.last();

        client.management().roles().list(null);
        assertEquals(2, route.calls());
        Recorded viaAggregate = route.last();

        assertEquals(direct.method(), viaAggregate.method());
        assertEquals(direct.path(), viaAggregate.path());
        assertEquals(direct.query(), viaAggregate.query());
    }

    /**
     * A direct accessor carries the client's implicit {@code {org_id}}, not a bare default.
     *
     * <p>This is the failure the equivalence rule exists to prevent: a forwarding accessor
     * that constructed its own handle would compile, return the right type, and address the
     * wrong organization.
     */
    @Test
    void aDirectAccessorCarriesTheClientsOwnScope() throws Exception {
        Route route = mount("GET", "/api/v1/organizations/" + ORG_ID + "/ca-certificates",
                200, pageOf(null));

        client.caCertificates().list(null);

        assertEquals(1, route.calls());
        assertTrue(route.last().path().contains(ORG_ID.toString()), route.last().path());
    }

    /** Re-scoping a directly-reached handle still returns a new one (§27.4 rule 3). */
    @Test
    void aDirectAccessorStillRescopes() throws Exception {
        UUID other = UUID.fromString("44444444-4444-4444-8444-444444444444");
        Route mine = mount("GET", "/api/v1/organizations/" + ORG_ID + "/ca-certificates",
                200, pageOf(null));
        Route theirs = mount("GET", "/api/v1/organizations/" + other + "/ca-certificates",
                200, pageOf(null));

        CaCertificatesApi handle = client.caCertificates();
        handle.inOrg(other).list(null);
        handle.list(null);

        assertEquals(1, theirs.calls());
        assertEquals(1, mine.calls());
    }

    /** Acquiring a handle either way performs no I/O (§27.2 rule 1). */
    @Test
    void acquiringAHandlePerformsNoIO() {
        int before = server.getRequestCount();

        assertNotNull(client.roles());
        assertNotNull(client.serviceAccounts());
        assertNotNull(client.management().certificates());

        assertEquals(before, server.getRequestCount());
    }
}
