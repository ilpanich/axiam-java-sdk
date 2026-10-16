package io.axiam.sdk.management;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.management.models.SsfDeliveryMethod;
import io.axiam.sdk.management.models.SsfStreamStatus;
import io.axiam.sdk.management.models.SsfSubjectFormat;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * The changes a caller wants to make to a stream it has read &mdash; the second argument of
 * {@link ReplacementBodies#ssfStream(io.axiam.sdk.management.models.SsfStream, SsfStreamChanges)}
 * (CONTRACT.md &sect;32.2, contract 1.62).
 *
 * <p>Every member is tri-state: <em>never set</em> keeps what the stream was read with, and a
 * call to its setter replaces it &mdash; including with {@code null}, which for the optional
 * members means "none" (the key is left out of the body and {@code null} is never sent,
 * &sect;27.11 rule 5). Build one with {@link #builder()}; an {@link #empty() empty} set of
 * changes yields the body the plain converter yields.
 *
 * <p>The members are those of {@code SsfStreamInput}; the stream's {@code id}, its read-only
 * fields and the write-only {@code authorization_header} (a read never carries it) are not
 * "read" values, so {@link Builder#authorizationHeader} and
 * {@link Builder#clearAuthorizationHeader} set them from scratch.
 */
public final class SsfStreamChanges {

    private static final SsfStreamChanges EMPTY = new SsfStreamChanges(new Builder());

    private final Builder set;

    private SsfStreamChanges(Builder set) {
        this.set = set;
    }

    /**
     * No changes: the result is what the plain converter returns.
     *
     * @return an empty set of changes
     */
    public static SsfStreamChanges empty() {
        return EMPTY;
    }

    /**
     * Starts a set of changes with nothing set.
     *
     * @return a fresh builder
     */
    public static Builder builder() {
        return new Builder();
    }

    // The package reads the members through these, so that "never set" and "set to null" stay apart.

    boolean hasEventsAllowed() {
        return set.eventsAllowedSet;
    }

    boolean hasEventsRequested() {
        return set.eventsRequestedSet;
    }

    /**
     * Applies each member the caller set over {@code base}, leaving the rest as it was read.
     *
     * @param base the body built from the read
     * @return the body with the changes applied
     */
    io.axiam.sdk.management.models.SsfStreamInput applyTo(
            io.axiam.sdk.management.models.SsfStreamInput base) {
        return new io.axiam.sdk.management.models.SsfStreamInput(
                set.audienceSet ? set.audience : base.audience(),
                set.authorizationHeaderSet ? set.authorizationHeader : base.authorizationHeader(),
                set.clearAuthorizationHeaderSet
                        ? set.clearAuthorizationHeader : base.clearAuthorizationHeader(),
                set.deliveryMethodSet ? set.deliveryMethod : base.deliveryMethod(),
                set.descriptionSet ? set.description : base.description(),
                set.endpointUrlSet ? set.endpointUrl : base.endpointUrl(),
                set.eventsAllowedSet ? set.eventsAllowed : base.eventsAllowed(),
                set.eventsRequestedSet ? set.eventsRequested : base.eventsRequested(),
                set.expectedUpdatedAtSet ? set.expectedUpdatedAt : base.expectedUpdatedAt(),
                set.receiverClientIdSet ? set.receiverClientId : base.receiverClientId(),
                set.statusSet ? set.status : base.status(),
                set.statusReasonSet ? set.statusReason : base.statusReason(),
                set.subjectFormatSet ? set.subjectFormat : base.subjectFormat());
    }

    /** Builds a {@link SsfStreamChanges}; a member never set is kept as read. */
    public static final class Builder {

        private boolean audienceSet;
        private @Nullable String audience;
        private boolean authorizationHeaderSet;
        private @Nullable Sensitive authorizationHeader;
        private boolean clearAuthorizationHeaderSet;
        private @Nullable Boolean clearAuthorizationHeader;
        private boolean deliveryMethodSet;
        private @Nullable SsfDeliveryMethod deliveryMethod;
        private boolean descriptionSet;
        private @Nullable String description;
        private boolean endpointUrlSet;
        private @Nullable String endpointUrl;
        private boolean eventsAllowedSet;
        private @Nullable List<String> eventsAllowed;
        private boolean eventsRequestedSet;
        private @Nullable List<String> eventsRequested;
        private boolean expectedUpdatedAtSet;
        private @Nullable String expectedUpdatedAt;
        private boolean receiverClientIdSet;
        private @Nullable String receiverClientId;
        private boolean statusSet;
        private @Nullable SsfStreamStatus status;
        private boolean statusReasonSet;
        private @Nullable String statusReason;
        private boolean subjectFormatSet;
        private @Nullable SsfSubjectFormat subjectFormat;

        private Builder() {
        }

        /**
         * Changes the SET {@code aud}.
         *
         * @param value the new audience
         * @return this builder
         */
        public Builder audience(String value) {
            audienceSet = true;
            audience = java.util.Objects.requireNonNull(value, "audience is required");
            return this;
        }

        /**
         * Sends a new push {@code Authorization} header. A read never carries the stored one,
         * so without this the body leaves it absent, which keeps the stored header (&sect;32.2).
         *
         * @param value the header value to send
         * @return this builder
         */
        public Builder authorizationHeader(Sensitive value) {
            authorizationHeaderSet = true;
            authorizationHeader = java.util.Objects.requireNonNull(value, "authorizationHeader");
            return this;
        }

        /**
         * Removes the stored push {@code Authorization} header; refused by the server together
         * with {@link #authorizationHeader}.
         *
         * @param value {@code true} to remove the stored header
         * @return this builder
         */
        public Builder clearAuthorizationHeader(boolean value) {
            clearAuthorizationHeaderSet = true;
            clearAuthorizationHeader = value;
            return this;
        }

        /**
         * Changes {@code push} or {@code poll}.
         *
         * @param value the new delivery method
         * @return this builder
         */
        public Builder deliveryMethod(SsfDeliveryMethod value) {
            deliveryMethodSet = true;
            deliveryMethod = java.util.Objects.requireNonNull(value, "deliveryMethod is required");
            return this;
        }

        /**
         * Changes the description.
         *
         * @param value the new description, or {@code null} for none (the key is left out)
         * @return this builder
         */
        public Builder description(@Nullable String value) {
            descriptionSet = true;
            description = value;
            return this;
        }

        /**
         * Changes the push endpoint.
         *
         * @param value the new endpoint, or {@code null} for none (the key is left out)
         * @return this builder
         */
        public Builder endpointUrl(@Nullable String value) {
            endpointUrlSet = true;
            endpointUrl = value;
            return this;
        }

        /**
         * Changes the administrator's ceiling. When this is set and
         * {@link #eventsRequested} is not, the {@code events_requested} that was read is
         * <strong>cut to the new ceiling</strong> &mdash; the entries still in it, in their
         * order &mdash; so that lowering the ceiling does not send an {@code events_requested}
         * the server refuses with {@code 400} (&sect;32.2).
         *
         * @param value the new {@code events_allowed}
         * @return this builder
         */
        public Builder eventsAllowed(List<String> value) {
            eventsAllowedSet = true;
            eventsAllowed = List.copyOf(java.util.Objects.requireNonNull(value, "eventsAllowed is required"));
            return this;
        }

        /**
         * Names the {@code events_requested} to send, exactly as given: the server judges it.
         * {@code []} is stored as the receiver's "none"; {@code null} here means the key is
         * <strong>left out, which resets</strong> the stream to every event of
         * {@code events_allowed} (&sect;32.2) &mdash; widening whatever the receiver narrowed.
         *
         * @param value the list to send, or {@code null} to omit the key and reset
         * @return this builder
         */
        public Builder eventsRequested(@Nullable List<String> value) {
            eventsRequestedSet = true;
            eventsRequested = value == null ? null : List.copyOf(value);
            return this;
        }

        /**
         * Replaces the {@code expected_updated_at} that was read (the server's own string).
         *
         * @param value the string to send, or {@code null} for none: the key is left out and
         *     the replacement is conditional only on the version the server reads itself
         * @return this builder
         */
        public Builder expectedUpdatedAt(@Nullable String value) {
            expectedUpdatedAtSet = true;
            expectedUpdatedAt = value;
            return this;
        }

        /**
         * Changes the receiver's OAuth2 {@code client_id}.
         *
         * @param value the new receiver client id
         * @return this builder
         */
        public Builder receiverClientId(String value) {
            receiverClientIdSet = true;
            receiverClientId = java.util.Objects.requireNonNull(value, "receiverClientId is required");
            return this;
        }

        /**
         * Changes the stream's status.
         *
         * @param value the new status
         * @return this builder
         */
        public Builder status(@Nullable SsfStreamStatus value) {
            statusSet = true;
            status = value;
            return this;
        }

        /**
         * Changes the status reason.
         *
         * @param value the new reason, or {@code null} for none (the key is left out)
         * @return this builder
         */
        public Builder statusReason(@Nullable String value) {
            statusReasonSet = true;
            statusReason = value;
            return this;
        }

        /**
         * Changes how users are named in the stream's SETs.
         *
         * @param value the new subject format
         * @return this builder
         */
        public Builder subjectFormat(@Nullable SsfSubjectFormat value) {
            subjectFormatSet = true;
            subjectFormat = value;
            return this;
        }

        /**
         * Builds the changes.
         *
         * @return the changes set so far
         */
        public SsfStreamChanges build() {
            return new SsfStreamChanges(copy());
        }

        private Builder copy() {
            Builder c = new Builder();
            c.audienceSet = audienceSet;
            c.audience = audience;
            c.authorizationHeaderSet = authorizationHeaderSet;
            c.authorizationHeader = authorizationHeader;
            c.clearAuthorizationHeaderSet = clearAuthorizationHeaderSet;
            c.clearAuthorizationHeader = clearAuthorizationHeader;
            c.deliveryMethodSet = deliveryMethodSet;
            c.deliveryMethod = deliveryMethod;
            c.descriptionSet = descriptionSet;
            c.description = description;
            c.endpointUrlSet = endpointUrlSet;
            c.endpointUrl = endpointUrl;
            c.eventsAllowedSet = eventsAllowedSet;
            c.eventsAllowed = eventsAllowed;
            c.eventsRequestedSet = eventsRequestedSet;
            c.eventsRequested = eventsRequested;
            c.expectedUpdatedAtSet = expectedUpdatedAtSet;
            c.expectedUpdatedAt = expectedUpdatedAt;
            c.receiverClientIdSet = receiverClientIdSet;
            c.receiverClientId = receiverClientId;
            c.statusSet = statusSet;
            c.status = status;
            c.statusReasonSet = statusReasonSet;
            c.statusReason = statusReason;
            c.subjectFormatSet = subjectFormatSet;
            c.subjectFormat = subjectFormat;
            return c;
        }
    }
}
