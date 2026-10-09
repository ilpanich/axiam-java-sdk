package io.axiam.sdk.management;

import io.axiam.sdk.internal.LocalRefusal;
import io.axiam.sdk.management.models.ParseSamlSpMetadata;

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
}
