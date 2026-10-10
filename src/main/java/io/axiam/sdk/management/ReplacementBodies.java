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
     * (&sect;32.2). {@code authorization_header} and
     * {@code clear_authorization_header} are left absent: absent keeps the stored
     * header.
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
                stream.receiverClientId(),
                stream.status(),
                stream.statusReason(),
                stream.subjectFormat());
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
