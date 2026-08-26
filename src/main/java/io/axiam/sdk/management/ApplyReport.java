package io.axiam.sdk.management;

import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Optional;

/**
 * The result of applying a manifest (CONTRACT.md &sect;27.6).
 *
 * <p><strong>There is no transaction here and this type does not pretend there
 * is</strong> (&sect;27.6 rule 7). These are independent HTTP endpoints; nothing
 * spans them. If step 12 of 30 fails, steps 1–11 have happened and will not be
 * undone — so every step's outcome is reported, execution stops at the first
 * failure rather than continuing blindly, and there is no rollback because this
 * SDK could not honour one. Fix the cause and re-apply: rule 6's idempotence is
 * what makes that safe.
 *
 * @param steps each planned step paired with what became of it, in plan order
 */
public record ApplyReport(List<AppliedStep> steps) {

    /**
     * Canonical constructor, defensively copying the step list.
     *
     * @param steps each planned step paired with what became of it
     */
    public ApplyReport {
        steps = List.copyOf(steps);
    }

    /**
     * The failing step, if the apply stopped early.
     *
     * @return the first failed step, or empty when every step that was meant to
     *         run did
     */
    public Optional<AppliedStep> failure() {
        return steps.stream().filter(s -> s.outcome().status() == Status.FAILED).findFirst();
    }

    /**
     * Whether every step that was meant to run did.
     *
     * @return {@code true} when no step failed
     */
    public boolean isComplete() {
        return failure().isEmpty();
    }

    /**
     * How many steps actually changed something.
     *
     * @return the number of created or updated steps
     */
    public int changedCount() {
        return (int) steps.stream()
                .filter(s -> s.outcome().status() == Status.CREATED
                        || s.outcome().status() == Status.UPDATED)
                .count();
    }

    /** What actually became of one planned step. */
    public enum Status {
        /** The step ran and the thing now exists. */
        CREATED,
        /** The step ran and the thing was updated. */
        UPDATED,
        /** A no-op step; nothing was sent. */
        UNCHANGED,
        /** The step failed. Everything before it has already happened. */
        FAILED,
        /** Never attempted, because an earlier step failed. */
        NOT_ATTEMPTED
    }

    /**
     * What happened to one planned step.
     *
     * @param status created, updated, unchanged, failed or not-attempted
     * @param message the error the server or transport gave, on a failed step
     *                only; {@code null} otherwise
     */
    public record StepOutcome(Status status, @Nullable String message) {
    }

    /**
     * One planned step paired with what became of it.
     *
     * @param action the step, exactly as plan reported it
     * @param outcome what actually happened when it ran — or did not
     */
    public record AppliedStep(ManagementPlan.PlannedAction action, StepOutcome outcome) {
    }
}
