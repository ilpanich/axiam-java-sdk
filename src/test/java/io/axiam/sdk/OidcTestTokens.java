package io.axiam.sdk;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * A structurally valid, unsigned access token for tests that only need the
 * SDK's own unverified claim decode to succeed.
 *
 * <p>Never a real credential: the signature segment is literal text. It exists
 * because {@code AxiamClient} decodes {@code sub}/{@code tenant_id} out of the
 * access cookie to build its {@link AxiamUser}, and a session fixture has to
 * satisfy that without standing up a JWKS endpoint.
 */
final class OidcTestTokens {

    private OidcTestTokens() {
    }

    static String unsignedAccessToken() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(
                "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(("{"
                + "\"sub\":\"" + UUID.randomUUID() + "\","
                + "\"tenant_id\":\"" + UUID.randomUUID() + "\","
                + "\"org_id\":\"" + UUID.randomUUID() + "\","
                + "\"exp\":" + (Instant.now().getEpochSecond() + 900)
                + "}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".not-a-real-signature";
    }
}
