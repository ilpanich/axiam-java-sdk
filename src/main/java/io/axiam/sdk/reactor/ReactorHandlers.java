package io.axiam.sdk.reactor;

import io.axiam.sdk.annotations.OnReactorEvent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Declarative reactor handler binding &mdash; CONTRACT.md &sect;22.14.
 *
 * <p>{@link ReactorServer} takes <strong>one</strong> {@link ReactorHandler}
 * from an event to one answer, which is the right shape for the wire and the
 * wrong shape for the code. A reactor registered for three events opens with a
 * {@code switch (event.event())}, and that switch carries two defects.
 *
 * <p>The first is cheap: a misspelled event name is a valid string, matches no
 * case, and is discovered as an event that never fires. The second is not. It is
 * the {@code default} arm, which is almost always written
 * {@code ReactorDecision.allow()}. That answers on behalf of code that never ran
 * &mdash; the defect &sect;22.10 rule 2 forbids the <em>runtime</em> from
 * committing, relocated into user code where the rule does not reach it. An
 * operator who set {@code fail_closed} on a registration has it defeated by a
 * {@code default} arm in a file they never read.
 *
 * <p>This class is the declarative form, in the spirit of &sect;11's
 * {@link io.axiam.sdk.annotations.AxiamRequireAccess}: annotate the methods,
 * collect them, hand the result to {@link ReactorServer}.
 *
 * <pre>{@code
 * public final class ClaimsReactor {
 *
 *     @OnReactorEvent(ReactorEvents.TOKEN_PRE_ISSUE)
 *     public ReactorDecision enrich(ReactorEvent event) { ... }
 *
 *     @OnReactorEvent(ReactorEvents.LOGIN_POST_AUTH)
 *     public ReactorDecision screen(ReactorEvent event) { ... }
 * }
 *
 * ReactorHandlers handlers = ReactorHandlers.of(new ClaimsReactor());
 * ReactorServeOptions options = ReactorServeOptions.builder(channel, tenantId, subkey)
 *         .reactorId(reactorId)
 *         .handler(handlers.handler())
 *         .build();
 * }</pre>
 *
 * <p>It is <strong>pure sugar</strong> (&sect;22.14 rule 1): what
 * {@link #handler()} returns is exactly the {@link ReactorHandler}
 * {@link ReactorServer} already accepts. It opens nothing, verifies nothing,
 * signs nothing, and does not filter a patch (&sect;22.10 rule 3).
 *
 * <p>Instances are built once at startup and are not thread-safe to mutate;
 * the handler {@link #handler()} returns snapshots its bindings and is safe for
 * concurrent dispatch.
 */
public final class ReactorHandlers {

    private final Map<String, ReactorHandler> handlers = new LinkedHashMap<>();

    /** Creates an empty binding table. Use {@link #bind} or {@link #of}. */
    public ReactorHandlers() {
    }

    /**
     * Collects every {@link OnReactorEvent}-annotated public method on
     * {@code sources}.
     *
     * <p>Methods are invoked against the instance they were found on, so a
     * class-based reactor keeps its state and its constructor-injected
     * collaborators. Declaration order is not guaranteed by reflection, so
     * methods are bound in event-name order for reproducibility.
     *
     * @param sources objects whose public methods carry the annotation
     * @return the collected bindings
     * @throws IllegalArgumentException on an unregistered event name (which is
     *         also how &sect;22.7's hot-path operations are refused), a second
     *         binding for an already-bound event, or an annotated method whose
     *         signature is not {@code ReactorDecision(ReactorEvent)}
     */
    public static ReactorHandlers of(Object... sources) {
        ReactorHandlers collected = new ReactorHandlers();
        for (Object source : sources) {
            Objects.requireNonNull(source, "reactor handler source must not be null");
            List<Method> annotated = new ArrayList<>();
            for (Method method : source.getClass().getMethods()) {
                if (method.isAnnotationPresent(OnReactorEvent.class)) {
                    annotated.add(method);
                }
            }
            // getMethods() has no defined order; sort so two runs of the same
            // program bind in the same order and events() is reproducible.
            annotated.sort(Comparator.comparing(m -> m.getAnnotation(OnReactorEvent.class).value()));
            for (Method method : annotated) {
                collected.bind(method.getAnnotation(OnReactorEvent.class).value(), adapt(source, method));
            }
        }
        return collected;
    }

    /**
     * Binds {@code handler} to {@code event} without an annotation.
     *
     * <p>The imperative half of the same thing, for handlers that are lambdas
     * rather than methods. Governed by every &sect;22.14 rule identically.
     *
     * @param event   a &sect;22.5 registry event name
     * @param handler the decision function for that event
     * @return {@code this}, for chaining
     * @throws IllegalArgumentException when {@code event} is outside the
     *         &sect;22.5 registry &mdash; which is how &sect;22.7's hot-path
     *         operations are refused, since they are in no registry row &mdash;
     *         or is already bound. A second binding is a mistake, never a silent
     *         overwrite: which of the two runs is not visible from either one.
     */
    public ReactorHandlers bind(String event, ReactorHandler handler) {
        Objects.requireNonNull(handler, "reactor handler must not be null");
        if (ReactorEvents.spec(event) == null) {
            // The message names what IS hookable. It deliberately does not name
            // what is excluded: §22.13 requires the three hot-path operations to
            // be absent from every event constant this SDK exposes, and a list of
            // them here — even only to say they are refused — is exactly the
            // constant that would break it (§22.14 rule 2).
            List<String> hookable = new ArrayList<>();
            for (ReactorEventSpec spec : ReactorEvents.REGISTRY) {
                hookable.add(spec.name());
            }
            throw new IllegalArgumentException(
                    event + " is not a hookable reactor event; the registry is "
                            + hookable);
        }
        if (handlers.containsKey(event)) {
            throw new IllegalArgumentException("reactor event " + event + " is already bound");
        }
        handlers.put(event, handler);
        return this;
    }

    /**
     * The bound event names, in binding order.
     *
     * <p>Pass them to {@link ReactorEvents#defaultFailurePolicyFor} to see what
     * an unreachable reactor costs &mdash; the strictest default among them
     * (&sect;22.8) &mdash; derived from the code that handles the events rather
     * than from a restatement of the registration.
     *
     * @return an unmodifiable list of wire event names
     */
    public List<String> events() {
        return List.copyOf(handlers.keySet());
    }

    /**
     * Composes the bindings into the {@link ReactorHandler}
     * {@link ReactorServer} accepts.
     *
     * @return the composed handler
     * @throws IllegalStateException when nothing is bound. A reactor that
     *         handles nothing would consume its queue and abstain from every
     *         event, which looks exactly like an outage.
     */
    public ReactorHandler handler() {
        if (handlers.isEmpty()) {
            throw new IllegalStateException(
                    "ReactorHandlers has no bindings; bind at least one event");
        }
        Map<String, ReactorHandler> bound = Map.copyOf(handlers);
        return event -> {
            ReactorHandler handler = bound.get(event.event());
            if (handler == null) {
                // §22.14 rule 4. NOT allow(): throwing publishes NO REPLY, so the
                // registration's failure_policy resolves this exactly as it
                // resolves a timeout (§22.8). This binder does not know what the
                // registration was for; the operator's policy does.
                throw new UnboundReactorEventException(event.event());
            }
            // Invoked without a try/catch on purpose (§22.14 rule 5): a handler's
            // own throwable must reach ReactorServer unchanged so it publishes
            // nothing. Catching it here would satisfy the letter of §22.10 rule 2
            // while defeating it.
            return handler.handle(event);
        };
    }

    /** Wraps one annotated method as a {@link ReactorHandler}. */
    private static ReactorHandler adapt(Object source, Method method) {
        if (!Modifier.isPublic(method.getModifiers())
                || method.getParameterCount() != 1
                || !method.getParameterTypes()[0].equals(ReactorEvent.class)
                || !method.getReturnType().equals(ReactorDecision.class)) {
            throw new IllegalArgumentException(
                    "@OnReactorEvent method " + method.getDeclaringClass().getName() + "#"
                            + method.getName()
                            + " must be public and have the signature "
                            + "ReactorDecision(ReactorEvent)");
        }
        return event -> {
            try {
                return (ReactorDecision) method.invoke(source, event);
            } catch (IllegalAccessException e) {
                throw new IllegalStateException(
                        "@OnReactorEvent method " + method.getName() + " is not accessible", e);
            } catch (InvocationTargetException e) {
                // Unwrap so the handler's OWN failure is what ReactorServer sees
                // (§22.14 rule 5) — a reflection wrapper around it would still
                // produce no reply, but it would hide which handler failed and
                // why from every log line and telemetry event.
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException runtime) {
                    throw runtime;
                }
                if (cause instanceof Error error) {
                    throw error;
                }
                throw new IllegalStateException(cause);
            }
        };
    }
}
