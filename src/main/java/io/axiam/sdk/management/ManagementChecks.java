package io.axiam.sdk.management;

import io.axiam.sdk.internal.LocalRefusal;
import io.axiam.sdk.management.models.ParseSamlSpMetadata;
import io.axiam.sdk.management.models.SamlServiceProviderDraft;
import io.axiam.sdk.management.models.SamlServiceProviderInput;

/**
 * Local checks the generated &sect;27 surface runs before any I/O.
 *
 * <p>The generator ({@code scripts/gen_management.py}, {@code PRECHECKS}) emits
 * a call to a method here at the top of an operation. Nothing here performs
 * I/O, and each refusal is the SDK's local {@code ValidationError}
 * ({@link LocalRefusal}).
 */
final class ManagementChecks {

    private ManagementChecks() {
    }

    /**
     * &sect;29.2: {@code ParseSamlSpMetadata} is <strong>exactly one</strong> of
     * {@code metadata_xml} and {@code metadata_url}. Both, or neither, is refused
     * here &mdash; never a request the server refuses.
     *
     * @param operation the operation name
     * @param body      the request body
     */
    static void parseSpMetadataExactlyOne(String operation, ParseSamlSpMetadata body) {
        boolean xml = body.metadataXml() != null;
        boolean url = body.metadataUrl() != null;
        if (xml && url) {
            throw LocalRefusal.of(operation, "metadata_xml",
                    "set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)");
        }
        if (!xml && !url) {
            throw LocalRefusal.of(operation, "metadata_url",
                    "set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)");
        }
    }

    /**
     * Contract 1.60 B6 / &sect;34.2 P12.9: completes a draft's service provider into the
     * strict input, or refuses it. A draft decodes without the required-member check, so
     * this is where a missing {@code acs_urls}, {@code display_name} or {@code entity_id}
     * is refused &mdash; locally, with the SDK's {@code ValidationError}, before any
     * request.
     *
     * @param operation the operation name
     * @param draft     the draft's service provider
     * @return the input to submit, with every required member present
     */
    static SamlServiceProviderInput completeServiceProvider(String operation, SamlServiceProviderDraft draft) {
        if (draft.acsUrls() == null) {
            throw LocalRefusal.of(operation, "acs_urls",
                    "is required and the draft lacks it (CONTRACT.md §34.2 P12.9)");
        }
        if (draft.displayName() == null) {
            throw LocalRefusal.of(operation, "display_name",
                    "is required and the draft lacks it (CONTRACT.md §34.2 P12.9)");
        }
        if (draft.entityId() == null) {
            throw LocalRefusal.of(operation, "entity_id",
                    "is required and the draft lacks it (CONTRACT.md §34.2 P12.9)");
        }
        return new SamlServiceProviderInput(draft.acsUrls(), draft.allowIdpInitiated(),
                draft.allowedGroups(), draft.attributeMappings(), draft.displayName(), draft.enabled(),
                draft.encryptAssertions(), draft.entityId(), draft.nameIdFormat(), draft.signResponses(),
                draft.sloBinding(), draft.sloUrl(), draft.spEncryptionCertPem(), draft.spSigningCertPem(),
                draft.wantAuthnRequestsSigned());
    }
}
