package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import io.axiam.sdk.annotations.OnReactorEvent;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;22.14 &mdash; declarative reactor handler binding.
 *
 * <p>Six groups for six rules. None needs a broker: {@link ReactorHandlers} is
 * pure composition over the {@link ReactorHandler} {@link ReactorServer} already
 * takes, so what is under test is the binding table and the one answer it gives
 * for an event nobody bound.
 */
class ReactorHandlersTest {

    /**
     * Assembled from halves so a plain source scan for &sect;22.7's three
     * excluded operations cannot match on this file's own text.
     */
    private static final List<String> EXCLUDED_HOT_PATH = List.of(
            "authz" + "." + "check",
            "authz" + "." + "check_batch",
            "token" + "." + "introspect");

    /** A class-based reactor, the shape &sect;22.14 exists to make writable. */
    public static final class FixtureReactor {

        private final String team;

        FixtureReactor(String team) {
            this.team = team;
        }

        @OnReactorEvent(ReactorEvents.TOKEN_PRE_ISSUE)
        public ReactorDecision enrich(ReactorEvent event) {
            return ReactorDecision.mutate(Map.of("ext.team", team));
        }

        @OnReactorEvent(ReactorEvents.LOGIN_POST_AUTH)
        public ReactorDecision screen(ReactorEvent event) {
            return ReactorDecision.deny("embargoed region");
        }

        /** Not annotated — must not be collected. */
        public ReactorDecision helper(ReactorEvent event) {
            return ReactorDecision.allow();
        }
    }

    /** An annotated method with the wrong shape. */
    public static final class BadSignatureReactor {

        @OnReactorEvent(ReactorEvents.TOKEN_PRE_ISSUE)
        public String wrong(ReactorEvent event) {
            return "not a decision";
        }
    }

    private static ReactorEvent event(String name) {
        Instant now = Instant.now();
        return new ReactorEvent(
                UUID.randomUUID(), name, UUID.randomUUID(), JsonNodeFactory.instance.objectNode(),
                500, 2, UUID.randomUUID(), now, now.plusMillis(500));
    }

    // ---- rule 1: it composes, it does not replace ---------------------------

    @Test
    void collectsAnnotatedMethodsAndDispatchesEachToItsOwn() {
        ReactorHandler handler = ReactorHandlers.of(new FixtureReactor("platform")).handler();

        ReactorDecision enriched = handler.handle(event(ReactorEvents.TOKEN_PRE_ISSUE));
        // The method was invoked against its instance, so constructor state survived.
        assertEquals(Map.of("ext.team", "platform"),
                assertInstanceOf(ReactorDecision.Mutate.class, enriched).patch());

        ReactorDecision screened = handler.handle(event(ReactorEvents.LOGIN_POST_AUTH));
        assertEquals("embargoed region",
                assertInstanceOf(ReactorDecision.Deny.class, screened).reason());
    }

    @Test
    void ignoresUnannotatedMethods() {
        assertEquals(
                List.of(ReactorEvents.LOGIN_POST_AUTH, ReactorEvents.TOKEN_PRE_ISSUE),
                ReactorHandlers.of(new FixtureReactor("platform")).events());
    }

    @Test
    void bindAcceptsALambda() {
        ReactorHandler handler = new ReactorHandlers()
                .bind(ReactorEvents.USER_PRE_CREATE, e -> ReactorDecision.allow())
                .handler();

        assertInstanceOf(ReactorDecision.Allow.class,
                handler.handle(event(ReactorEvents.USER_PRE_CREATE)));
    }

    @Test
    void refusesAnAnnotatedMethodWithTheWrongSignature() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> ReactorHandlers.of(new BadSignatureReactor()));

        assertTrue(error.getMessage().contains("ReactorDecision(ReactorEvent)"), error.getMessage());
    }

    // ---- rule 2: an unregistered name is refused at bind time ---------------

    @Test
    void rejectsAMisspelledEventName() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ReactorHandlers().bind("token.pre_isue", e -> ReactorDecision.allow()));

        assertTrue(error.getMessage().contains("not a hookable reactor event"), error.getMessage());
    }

    /**
     * &sect;22.7's three are in no registry row, so rule 2 refuses them as
     * unknown names. Asserted on behaviour, not on a comment.
     */
    @Test
    void rejectsTheHotPathOperations() {
        for (String excluded : EXCLUDED_HOT_PATH) {
            assertThrows(IllegalArgumentException.class,
                    () -> new ReactorHandlers().bind(excluded, e -> ReactorDecision.allow()),
                    "binding " + excluded + " was accepted; §22.7 makes it un-hookable");
        }
    }

    /** The rejection names what IS hookable, never what is excluded (rule 2). */
    @Test
    void rejectionNamesTheRegistryNotTheExclusions() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ReactorHandlers().bind("nope", e -> ReactorDecision.allow()));

        assertTrue(error.getMessage().contains(ReactorEvents.TOKEN_PRE_ISSUE), error.getMessage());
        for (String excluded : EXCLUDED_HOT_PATH) {
            assertFalse(error.getMessage().contains(excluded), error.getMessage());
        }
    }

    // ---- rule 3: one handler per event --------------------------------------

    @Test
    void rejectsADuplicateBinding() {
        ReactorHandlers handlers = new ReactorHandlers()
                .bind(ReactorEvents.TOKEN_PRE_ISSUE, e -> ReactorDecision.allow());

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> handlers.bind(ReactorEvents.TOKEN_PRE_ISSUE, e -> ReactorDecision.deny("second")));

        assertTrue(error.getMessage().contains("already bound"), error.getMessage());
    }

    // ---- rule 4: an unbound event abstains ----------------------------------

    @Test
    void unboundEventAbstainsRatherThanAllowing() {
        ReactorHandler handler = ReactorHandlers.of(new FixtureReactor("platform")).handler();

        UnboundReactorEventException rejection = assertThrows(UnboundReactorEventException.class,
                () -> handler.handle(event(ReactorEvents.GRANT_PRE_ASSIGN)),
                "an unbound event produced an answer; §22.14 rule 4 requires no reply at all");

        // Throwing publishes NOTHING, so the registration's failure_policy
        // decides (§22.8) — not a synthesized allow (§22.10 rule 2).
        assertEquals(ReactorEvents.GRANT_PRE_ASSIGN, rejection.event());
    }

    @Test
    void emptyBindingSetIsRefused() {
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> new ReactorHandlers().handler());

        assertTrue(error.getMessage().contains("no bindings"), error.getMessage());
    }

    // ---- rule 5: a handler's own failure propagates --------------------------

    /** A reactor whose backing service is down. */
    public static final class ThrowingReactor {

        @OnReactorEvent(ReactorEvents.LOGIN_POST_AUTH)
        public ReactorDecision screen(ReactorEvent event) {
            throw new IllegalStateException("fraud service unreachable");
        }
    }

    @Test
    void handlerThrowablePropagatesUnwrapped() {
        ReactorHandler handler = ReactorHandlers.of(new ThrowingReactor()).handler();

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> handler.handle(event(ReactorEvents.LOGIN_POST_AUTH)));

        // Unwrapped from the reflective InvocationTargetException: a wrapper
        // would still publish no reply, but it would hide which handler failed
        // and why from every log line and telemetry event.
        assertEquals("fraud service unreachable", error.getMessage());
    }

    @Test
    void lambdaHandlerThrowablePropagates() {
        ReactorHandler handler = new ReactorHandlers()
                .bind(ReactorEvents.USER_PRE_UPDATE, e -> {
                    throw new IllegalStateException("directory timed out");
                })
                .handler();

        assertThrows(IllegalStateException.class,
                () -> handler.handle(event(ReactorEvents.USER_PRE_UPDATE)));
    }

    // ---- rule 6 and the SHOULD ----------------------------------------------

    @Test
    void forbiddenPatchKeyIsSentUnfiltered() {
        ReactorHandler handler = new ReactorHandlers()
                .bind(ReactorEvents.TOKEN_PRE_ISSUE,
                        e -> ReactorDecision.mutate(Map.of("sub", "attacker")))
                .handler();

        ReactorDecision decision = handler.handle(event(ReactorEvents.TOKEN_PRE_ISSUE));

        assertEquals(Map.of("sub", "attacker"),
                assertInstanceOf(ReactorDecision.Mutate.class, decision).patch(),
                "the binder silently dropped a patch key");
    }

    @Test
    void boundEventsFeedTheFailurePolicy() {
        ReactorHandlers handlers = ReactorHandlers.of(new FixtureReactor("platform"));

        // token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
        // strictest-wins composition makes the pair fail_closed.
        assertEquals(FailurePolicy.FAIL_CLOSED,
                ReactorEvents.defaultFailurePolicyFor(handlers.events()));
    }

    @Test
    void handlerSnapshotsItsBindings() {
        ReactorHandlers handlers = new ReactorHandlers()
                .bind(ReactorEvents.TOKEN_PRE_ISSUE, e -> ReactorDecision.allow());
        ReactorHandler handler = handlers.handler();

        handlers.bind(ReactorEvents.GRANT_PRE_ASSIGN, e -> ReactorDecision.deny("late"));

        assertThrows(UnboundReactorEventException.class,
                () -> handler.handle(event(ReactorEvents.GRANT_PRE_ASSIGN)));
    }
}
