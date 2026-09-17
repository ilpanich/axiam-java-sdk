package io.axiam.sdk.mcp;

/**
 * What {@link Mcp#protectedResourceMetadata} returns: the document, the path
 * it is served at, and the URL that path resolves to.
 *
 * <p>{@link #metadataUrl()} exists so the guard's {@code resourceMetadataUrl}
 * option (&sect;28.5) is fed from the value that derived it rather than
 * retyped &mdash; retyping is how the two come to disagree, and a challenge
 * pointing at a document that is not this resource server's is worse than no
 * challenge at all.
 *
 * @param document the RFC 9728 &sect;2 document, ready to serialize
 * @param metadataPath the absolute path the document is served at, derived
 *                     from the resource per &sect;28.3 &mdash; never chosen
 * @param metadataUrl {@link #metadataPath()} resolved against the resource's
 *                    scheme and authority; feed this to the guard's
 *                    {@code resourceMetadataUrl}
 */
public record ProtectedResourceMetadata(
        ProtectedResourceMetadataDocument document, String metadataPath, String metadataUrl) {
}
