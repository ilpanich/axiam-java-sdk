package io.axiam.sdk.reactor;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;22.5 (the registry and its allow-lists), &sect;22.7 (the
 * hot-path exclusion) and &sect;22.8 (failure-policy composition).
 */
class ReactorRegistryTest {

    // ---- §22.5 the namespace-prefix rule -----------------------------------

    @Test
    void tokenPreIssueAdmitsTheExtNamespaceAndNothingElse() {
        ReactorEventSpec spec = ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE);
        assertNotNull(spec);

        assertTrue(spec.patchFieldAllowed("ext.department"));
        assertTrue(spec.patchFieldAllowed("ext.a.b.c"));

        // `ext.` names the namespace, not a claim: admitting it would let a
        // reactor set a claim literally called `ext.`.
        assertFalse(spec.patchFieldAllowed("ext."));
        assertFalse(spec.patchFieldAllowed("ext"));
        // A prefix match on the string is not a match on the namespace.
        assertFalse(spec.patchFieldAllowed("extra"));
        assertFalse(spec.patchFieldAllowed("external_id"));
        // Nor is a suffix match.
        assertFalse(spec.patchFieldAllowed("evil.ext.department"));
    }

    @Test
    void noStandardClaimIsReachableFromTokenPreIssue() {
        ReactorEventSpec spec = ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE);
        assertNotNull(spec);
        for (String claim : new String[]{"iss", "sub", "aud", "exp", "iat", "nbf", "jti",
                "scope", "scp", "azp", "act", "client_id"}) {
            assertFalse(spec.patchFieldAllowed(claim),
                    "a hook that can rewrite '" + claim + "' is a hook that can mint a token for anyone");
        }
    }

    @Test
    void userEventsAdmitProfileFieldsAndRefuseCredentialsAndBareMetadata() {
        for (String event : new String[]{ReactorEvents.USER_PRE_CREATE, ReactorEvents.USER_PRE_UPDATE}) {
            ReactorEventSpec spec = ReactorEvents.spec(event);
            assertNotNull(spec);
            assertTrue(spec.patchFieldAllowed("username"));
            assertTrue(spec.patchFieldAllowed("email"));
            assertTrue(spec.patchFieldAllowed("metadata.source"));

            assertFalse(spec.patchFieldAllowed("metadata"), "bare `metadata` is not in the namespace");
            assertFalse(spec.patchFieldAllowed("metadata."), "the namespace is not a field");
            for (String forbidden : new String[]{"password", "password_hash", "tenant_id", "id",
                    "roles", "is_admin"}) {
                assertFalse(spec.patchFieldAllowed(forbidden), event + " must refuse " + forbidden);
            }
        }
    }

    @Test
    void vetoOnlyEventsAcceptNoPatchFieldAtAll() {
        for (String event : new String[]{ReactorEvents.LOGIN_POST_AUTH, ReactorEvents.GRANT_PRE_ASSIGN}) {
            ReactorEventSpec spec = ReactorEvents.spec(event);
            assertNotNull(spec);
            assertFalse(spec.mutable(), event + " is veto-only");
            assertTrue(spec.mutableFields().isEmpty());
            for (String field : new String[]{"anything", "username", "ext.department", "role"}) {
                assertFalse(spec.patchFieldAllowed(field));
            }
        }
    }

    @Test
    void theRegistryMatchesTheServersFiveEntries() {
        assertEquals(List.of("token.pre_issue", "login.post_auth", "user.pre_create",
                        "user.pre_update", "grant.pre_assign"),
                ReactorEvents.REGISTRY.stream().map(ReactorEventSpec::name).toList());
        assertTrue(ReactorEvents.REGISTRY.stream().allMatch(ReactorEventSpec::interceptable),
                "all five v1 events are interceptable");
        assertNull(ReactorEvents.spec("not.an.event"));
        assertNull(ReactorEvents.spec(null));
    }

    // ---- §22.7 hot-path exclusion (MUST NOT) -------------------------------

    /**
     * Asserted against the enum/list, not against a comment: {@code authz.check},
     * {@code authz.check_batch} and {@code token.introspect} appear in no event
     * constant this SDK exposes, and in no registry row.
     */
    @Test
    void theHotPathOperationsAreAbsentFromEveryEventConstant() throws Exception {
        List<String> excluded = List.of("authz.check", "authz.check_batch", "token.introspect");

        for (ReactorEventSpec spec : ReactorEvents.REGISTRY) {
            assertFalse(excluded.contains(spec.name()),
                    spec.name() + " must not be hookable: a reactor round trip is milliseconds "
                            + "and the check path's budget is microseconds");
        }

        List<String> constants = new ArrayList<>();
        for (Field field : ReactorEvents.class.getDeclaredFields()) {
            if (Modifier.isPublic(field.getModifiers()) && Modifier.isStatic(field.getModifiers())
                    && field.getType() == String.class) {
                constants.add((String) field.get(null));
            }
        }
        assertEquals(5, constants.size(), "five event constants, no more");
        for (String name : excluded) {
            assertFalse(constants.contains(name), name + " must not be exposed as a reactor event");
            assertNull(ReactorEvents.spec(name), name + " must not resolve to a registry spec");
        }
    }

    // ---- §22.8 failure-policy composition ----------------------------------

    @Test
    void theStrictestDefaultWinsInEitherArrayOrder() {
        assertEquals(FailurePolicy.FAIL_OPEN,
                ReactorEvents.defaultFailurePolicyFor(List.of(ReactorEvents.TOKEN_PRE_ISSUE)));
        assertEquals(FailurePolicy.FAIL_CLOSED,
                ReactorEvents.defaultFailurePolicyFor(List.of(ReactorEvents.LOGIN_POST_AUTH)));

        // A reactor registered for both can veto a login, so it inherits
        // fail_closed — and the order of the array must not decide that.
        assertEquals(FailurePolicy.FAIL_CLOSED, ReactorEvents.defaultFailurePolicyFor(
                List.of(ReactorEvents.TOKEN_PRE_ISSUE, ReactorEvents.LOGIN_POST_AUTH)));
        assertEquals(FailurePolicy.FAIL_CLOSED, ReactorEvents.defaultFailurePolicyFor(
                List.of(ReactorEvents.LOGIN_POST_AUTH, ReactorEvents.TOKEN_PRE_ISSUE)));

        assertEquals(FailurePolicy.FAIL_OPEN, ReactorEvents.defaultFailurePolicyFor(List.of()));
        assertEquals(FailurePolicy.FAIL_OPEN,
                ReactorEvents.defaultFailurePolicyFor(List.of("not.an.event")));
    }

    @Test
    void theRegistrysPerEventDefaultsMatchTheServers() {
        assertEquals(FailurePolicy.FAIL_OPEN,
                ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE).defaultFailurePolicy());
        for (String closed : new String[]{ReactorEvents.LOGIN_POST_AUTH, ReactorEvents.USER_PRE_CREATE,
                ReactorEvents.USER_PRE_UPDATE, ReactorEvents.GRANT_PRE_ASSIGN}) {
            assertEquals(FailurePolicy.FAIL_CLOSED,
                    ReactorEvents.spec(closed).defaultFailurePolicy(), closed);
        }
    }

    @Test
    void failurePolicyWireFormsRoundTrip() {
        assertEquals("fail_open", FailurePolicy.FAIL_OPEN.wire());
        assertEquals("fail_closed", FailurePolicy.FAIL_CLOSED.wire());
        assertEquals(FailurePolicy.FAIL_CLOSED, FailurePolicy.fromWire(" FAIL_CLOSED "));
        assertEquals(FailurePolicy.FAIL_OPEN, FailurePolicy.fromWire("fail_open"));
        assertNull(FailurePolicy.fromWire("fail_sideways"));
        assertNull(FailurePolicy.fromWire(null));
    }

    // ---- §22.8 budget constants --------------------------------------------

    @Test
    void theBudgetConstantsAreTheContractsOwn() {
        assertEquals(500, ReactorProtocol.DEFAULT_TIMEOUT_MS);
        assertEquals(5_000, ReactorProtocol.MAX_TIMEOUT_MS);
        assertEquals(5_000, ReactorProtocol.CHAIN_CEILING_MS);
        assertEquals(64, ReactorProtocol.DEFAULT_MAX_IN_FLIGHT_PER_TENANT);
        assertEquals(2, ReactorProtocol.KEY_VERSION);
        assertEquals(2, ReactorProtocol.MIN_ACCEPTED_KEY_VERSION);
        assertEquals(300, ReactorProtocol.DEFAULT_FRESHNESS_SKEW.toSeconds());
    }
}
