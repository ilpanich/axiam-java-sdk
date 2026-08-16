package io.axiam.sdk.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that a method handles one reactor hook event (CONTRACT.md
 * &sect;22.14, canonical {@code reactor_handlers}).
 *
 * <p>Placing this annotation on a method does not itself dispatch anything
 * &mdash; it is metadata read by
 * {@link io.axiam.sdk.reactor.ReactorHandlers#of(Object...)}, which builds the
 * single {@link io.axiam.sdk.reactor.ReactorHandler} that
 * {@link io.axiam.sdk.reactor.ReactorServer} already takes. That is the same
 * shape {@link AxiamRequireAccess} uses for &sect;11: the annotation carries the
 * declaration, a collector turns it into enforcement.
 *
 * <pre>{@code
 * public final class ClaimsReactor {
 *
 *     @OnReactorEvent(ReactorEvents.TOKEN_PRE_ISSUE)
 *     public ReactorDecision enrich(ReactorEvent event) {
 *         return ReactorDecision.mutate(Map.of("ext.department", "engineering"));
 *     }
 * }
 *
 * ReactorHandler handler = ReactorHandlers.of(new ClaimsReactor()).handler();
 * }</pre>
 *
 * <p>The event name is validated when {@code ReactorHandlers} reads the
 * annotation, so a typo fails at wiring time rather than becoming an event that
 * silently never fires (&sect;22.14 rule 2). A name outside the &sect;22.5
 * registry is refused &mdash; which is also how &sect;22.7's hot-path
 * operations are refused, since they are in no registry row.
 *
 * <p>Annotated methods must be public, take one {@link
 * io.axiam.sdk.reactor.ReactorEvent} and return a
 * {@link io.axiam.sdk.reactor.ReactorDecision}.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface OnReactorEvent {

    /**
     * The &sect;22.5 registry event this method handles, e.g.
     * {@code ReactorEvents.TOKEN_PRE_ISSUE}.
     *
     * @return the wire event name
     */
    String value();
}
