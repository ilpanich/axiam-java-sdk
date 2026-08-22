package io.axiam.sdk.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import io.axiam.sdk.Sensitive;

/**
 * A started ceremony: the server's options plus the token binding a response to
 * them (CONTRACT.md &sect;24.1).
 *
 * @param challenge  the server's options, exactly as they arrived — a
 *                   {@code {"publicKey": {…}}} object carrying base64url
 *                   buffers. Hand it to the authenticator <strong>unchanged</strong>
 *                   (&sect;24.0), or call {@link #requestJson()} for the string a
 *                   platform API takes.
 * @param stateToken binds the authenticator's answer to this challenge. A
 *                   bearer credential for the length of the ceremony — one that
 *                   leaks inside that window is a ceremony an attacker can try
 *                   to complete — so it is {@link Sensitive} (&sect;24.5). It is
 *                   <strong>opaque</strong>: this SDK never decodes it, and
 *                   neither should a caller.
 */
public record WebauthnChallenge(JsonNode challenge, Sensitive stateToken) {

    /**
     * The challenge in the JSON form every platform authenticator API takes
     * (&sect;24.6a rule 1).
     *
     * <p>This is the string an Android app passes to
     * {@code CreatePublicKeyCredentialRequest} or
     * {@code GetPublicKeyCredentialOption}, and the value a browser passes to
     * {@code PublicKeyCredential.parseCreationOptionsFromJSON()}. It is the
     * inner options object: the {@code publicKey} wrapper belongs to the DOM's
     * {@code CredentialCreationOptions}, and the platform JSON APIs do not want
     * it.
     *
     * <p>Pure local computation, no I/O. Nothing is defaulted, dropped or
     * reordered on the way through (&sect;24.0).
     *
     * @return the options object, serialized
     */
    public String requestJson() {
        JsonNode options = challenge.get("publicKey");
        return (options == null ? challenge : options).toString();
    }
}
