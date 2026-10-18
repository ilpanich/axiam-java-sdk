package io.axiam.sdk.management;

import io.axiam.sdk.management.models.DirectoryConfig;
import io.axiam.sdk.management.models.SamlServiceProvider;
import io.axiam.sdk.management.models.SamlServiceProviderInput;
import io.axiam.sdk.management.models.ScimTargetInput;
import io.axiam.sdk.management.models.ScimTargetResponse;
import io.axiam.sdk.management.models.SetDirectoryConfig;
import io.axiam.sdk.management.models.SsfStream;
import io.axiam.sdk.management.models.SsfStreamInput;

import java.time.format.DateTimeFormatter;

/**
 * The read-modify-write form &sect;27.4 rule 5 recommends for a
 * {@code replace} update: a read result turned back into the replacement body,
 * every member carried over, so changing one field and sending it back
 * preserves the rest instead of resetting it to its default.
 *
 * <p>The one member a read never carries &mdash; the write-only secret &mdash; is
 * left absent, which on these updates means <em>keep the stored one</em>,
 * subject to the rule that moving the connection requires it again
 * (&sect;30.3 rule 2, &sect;31.3 rule 2, &sect;32.3 rule 5). Records are
 * immutable, so change a member by rebuilding: every component is positional.
 */
public final class ReplacementBodies {

    private ReplacementBodies() {
    }

    /**
     * {@code saml.update_service_provider}'s body from a
     * {@code get_service_provider} result (&sect;29.2).
     *
     * @param sp the registration as read
     * @return the replacement body carrying every member of {@code sp}
     */
    public static SamlServiceProviderInput from(SamlServiceProvider sp) {
        return new SamlServiceProviderInput(
                sp.acsUrls(),
                sp.allowIdpInitiated(),
                sp.allowedGroups(),
                sp.attributeMappings(),
                sp.displayName(),
                sp.enabled(),
                sp.encryptAssertions(),
                sp.entityId(),
                sp.nameIdFormat(),
                sp.signResponses(),
                sp.sloBinding(),
                sp.sloUrl(),
                sp.spEncryptionCertPem(),
                sp.spSigningCertPem(),
                sp.wantAuthnRequestsSigned());
    }

    /**
     * {@code ssf.update_stream}'s body from a {@code get_stream} result
     * (&sect;32.2) &mdash; <strong>the plain converter</strong>.
     * {@code authorization_header} and {@code clear_authorization_header} are left absent:
     * absent keeps the stored header.
     *
     * <p>The body carries the {@code events_requested} and the {@code expected_updated_at}
     * that were read (contract 1.61). An {@code events_requested} of {@code []} stays
     * {@code []} (the receiver's "none"; omitting it would <em>widen</em> the stream to
     * every allowed event), and {@code expected_updated_at} is the response's <em>own
     * string</em> ({@link SsfStream#updatedAtRaw()}, contract 1.62): the server compares the
     * instant it stored, and a re-rendered offset or fraction can miss. The update is
     * therefore refused {@code 409} if the stream was written (by the receiver as well as by
     * an administrator) in between; read it again, never retry the same body.
     *
     * <p><strong>The caller's duty.</strong> This converter cannot know that you will lower
     * {@code events_allowed}. If you do, <em>cut {@code events_requested} to the new
     * ceiling yourself</em> (the body is a record: rebuild it), because an entry outside
     * {@code events_allowed} is refused {@code 400}; and an {@code events_requested} you
     * <em>omit</em> resets the stream to every allowed event, widening what the receiver
     * narrowed. The three meanings of {@code events_requested} on an update are stated at
     * {@code SsfApi.updateStream}. To have the cut done for you, use
     * {@link #ssfStream(SsfStream, SsfStreamChanges)}. Pass {@code null} for
     * {@code expectedUpdatedAt} to replace whatever is stored.
     *
     * @param stream the stream as read
     * @return the replacement body
     */
    public static SsfStreamInput from(SsfStream stream) {
        return new SsfStreamInput(
                stream.audience(),
                null,
                null,
                stream.deliveryMethod(),
                stream.description(),
                stream.endpointUrl(),
                stream.eventsAllowed(),
                stream.eventsRequested(),
                stream.updatedAtRaw(),
                stream.receiverClientId(),
                stream.status(),
                stream.statusReason(),
                stream.subjectFormat());
    }

    /**
     * {@code ssf.update_stream}'s body from a {@code get_stream} result and the changes to
     * make &mdash; <strong>the change-taking form</strong> (&sect;32.2, contract 1.62; the
     * composed read-modify-write form of &sect;27.4 rule 5).
     *
     * <p>It applies {@code changes} over what was read and sends the
     * {@code events_requested} and the {@code expected_updated_at} <em>as read</em>: the
     * response's own string, an {@code []} as {@code []}. When the changes lower
     * {@code events_allowed} and do not name {@code events_requested}, the
     * {@code events_requested} that was read is <strong>cut to the new
     * {@code events_allowed}</strong> (the entries still in it, in their order). An
     * {@code events_requested} the changes name is sent as given; the server judges it
     * ({@code 400} outside the ceiling). A {@code null} {@code expectedUpdatedAt} in the
     * changes means "none": the key is left out, and {@code null} is never sent.
     *
     * <p>A {@code 409} from the update means the stream changed since it was read; the
     * administrator reads again and decides, and this form does not retry (&sect;32.3 rule 4).
     *
     * @param stream the stream as read
     * @param changes what to change; members never set keep what was read
     * @return the replacement body
     */
    public static SsfStreamInput ssfStream(SsfStream stream, SsfStreamChanges changes) {
        SsfStreamInput merged = changes.applyTo(from(stream));
        if (!changes.hasEventsAllowed() || changes.hasEventsRequested()
                || merged.eventsRequested() == null) {
            return merged;
        }
        java.util.Set<String> ceiling = new java.util.HashSet<>(merged.eventsAllowed());
        java.util.List<String> cut = merged.eventsRequested().stream()
                .filter(ceiling::contains).toList();
        return new SsfStreamInput(merged.audience(), merged.authorizationHeader(),
                merged.clearAuthorizationHeader(), merged.deliveryMethod(), merged.description(),
                merged.endpointUrl(), merged.eventsAllowed(), cut, merged.expectedUpdatedAt(),
                merged.receiverClientId(), merged.status(), merged.statusReason(),
                merged.subjectFormat());
    }

    /**
     * {@code ssf.update_stream}'s body from a {@code get_stream} result, with nothing
     * changed: the same body as {@link #from(SsfStream)}.
     *
     * @param stream the stream as read
     * @return the replacement body
     */
    public static SsfStreamInput ssfStream(SsfStream stream) {
        return ssfStream(stream, SsfStreamChanges.empty());
    }

    /**
     * {@code scim_targets.update}'s body from a {@code get} result (&sect;31.2).
     * {@code credential} is left absent: absent keeps the stored one, unless the
     * write moves its URL (&sect;31.3 rule 2). {@code expected_updated_at} carries
     * the {@code updated_at} that was read (&sect;31.3 rule 4, contract 1.60), so the
     * update is refused {@code 409} if another administrator wrote the target in
     * between; pass {@code null} there to replace whatever is stored.
     *
     * @param target the target as read
     * @return the replacement body
     */
    public static ScimTargetInput from(ScimTargetResponse target) {
        return new ScimTargetInput(
                target.auth(),
                target.baseUrl(),
                null,
                target.deprovision(),
                target.enabled(),
                target.updatedAt() == null ? null
                        : DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(target.updatedAt()),
                target.name(),
                target.pushGroups(),
                target.scope(),
                target.userNameFrom());
    }

    /**
     * {@code directory.set}'s body from a {@code get} result (&sect;30.2).
     * {@code bind_secret} is left absent: absent keeps the stored secret, unless
     * the write moves the connection (&sect;30.3 rule 2).
     *
     * @param config the configuration as read
     * @return the replacement body
     */
    public static SetDirectoryConfig from(DirectoryConfig config) {
        return new SetDirectoryConfig(
                config.baseDn(),
                config.bindDn(),
                null,
                config.enabled(),
                config.groupBaseDn(),
                config.groupFilter(),
                config.groupMappings(),
                config.groupMemberAttribute(),
                config.groupNestingDepth(),
                config.jitProvisioning(),
                config.kind(),
                config.startTls(),
                config.syncIntervalSecs(),
                config.trustAnchorsPem(),
                config.url(),
                config.userAttributeMap(),
                config.userFilter());
    }
}
