package io.axiam.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcStateEntry;
import io.axiam.sdk.oidc.OidcTokenSet;

import org.junit.jupiter.api.Test;

import java.io.Serializable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CR-04-class regression test for {@link Sensitive} (D-17, CONTRACT.md
 * &sect;7): proves the raw token value never survives {@code toString()} or
 * Jackson serialization, and that {@code Sensitive} fails closed on Java
 * serialization rather than leaking {@code value} via reflection.
 *
 * <p>Follow-up F-12 (cross-SDK CONTRACT.md &sect;12 conformance review,
 * T9): the redaction assertions above only ever exercised a bare
 * {@link Sensitive}. The three &sect;12 DTOs that carry one or more
 * {@code Sensitive} components ({@link OidcTokenSet},
 * {@link AuthorizationRequest}, {@link OidcStateEntry}) are correct by
 * construction &mdash; {@code @JsonSerialize} is a class-level annotation on
 * {@code Sensitive} itself, so any container serializes it the same way
 * &mdash; but that was never actually asserted against a real
 * {@code ObjectMapper.writeValueAsString} call. These tests close that gap.
 */
class SensitiveTest {

    private static final String RAW_TOKEN = "super-secret-token";
    private static final String REDACTED = "[SENSITIVE]";

    @Test
    void toStringReturnsRedactedPlaceholder() {
        Sensitive sensitive = Sensitive.of(RAW_TOKEN);

        assertTrue(sensitive.toString().equals(REDACTED), "toString() must return the redacted placeholder");
        assertFalse(sensitive.toString().contains(RAW_TOKEN), "toString() must never contain the raw token");
    }

    @Test
    void jacksonSerializationEmitsRedactedPlaceholder() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        String json = mapper.writeValueAsString(Sensitive.of(RAW_TOKEN));

        assertTrue(json.contains(REDACTED), "Jackson output must contain the redacted placeholder");
        assertFalse(json.contains(RAW_TOKEN), "Jackson output must never contain the raw token");
    }

    @Test
    void sensitiveIsNotSerializable() {
        assertFalse(Serializable.class.isAssignableFrom(Sensitive.class),
                "Sensitive must NOT implement java.io.Serializable (fail-closed on reflective serialization)");
    }

    @Test
    void jacksonSerializationOfOidcTokenSetRedactsAllThreeSensitiveComponents() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        OidcTokenSet tokenSet = new OidcTokenSet(
                Sensitive.of("access-" + RAW_TOKEN),
                "Bearer",
                900,
                "openid profile",
                Sensitive.of("refresh-" + RAW_TOKEN),
                Sensitive.of("idtok-" + RAW_TOKEN),
                null);

        String json = mapper.writeValueAsString(tokenSet);

        assertFalse(json.contains(RAW_TOKEN), "OidcTokenSet JSON must never contain a raw token: " + json);
        assertTrue(json.contains(REDACTED), "OidcTokenSet JSON must contain the redacted placeholder: " + json);
        // Three Sensitive components (access/refresh/id token) must each redact.
        assertEquals(3, countOccurrences(json, REDACTED),
                "expected exactly three redacted Sensitive components in: " + json);
    }

    @Test
    void jacksonSerializationOfAuthorizationRequestRedactsTheCodeVerifier() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        AuthorizationRequest request = new AuthorizationRequest(
                "https://axiam.example.com/oauth2/authorize?state=s1",
                "state-value",
                "nonce-value",
                Sensitive.of(RAW_TOKEN));

        String json = mapper.writeValueAsString(request);

        assertFalse(json.contains(RAW_TOKEN), "AuthorizationRequest JSON must never contain the raw code_verifier: " + json);
        assertTrue(json.contains(REDACTED), "AuthorizationRequest JSON must contain the redacted placeholder: " + json);
        // state/nonce are not Sensitive (CONTRACT.md §12.3 rule 2) and must still round-trip in the clear.
        assertTrue(json.contains("state-value"), "state is not a secret and must be emitted verbatim: " + json);
        assertTrue(json.contains("nonce-value"), "nonce is not a secret and must be emitted verbatim: " + json);
    }

    @Test
    void jacksonSerializationOfOidcStateEntryRedactsTheCodeVerifier() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        OidcStateEntry entry = new OidcStateEntry(
                "state-value", "nonce-value", Sensitive.of(RAW_TOKEN), "https://app.example.com/cb");

        String json = mapper.writeValueAsString(entry);

        assertFalse(json.contains(RAW_TOKEN), "OidcStateEntry JSON must never contain the raw code_verifier: " + json);
        assertTrue(json.contains(REDACTED), "OidcStateEntry JSON must contain the redacted placeholder: " + json);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int index = 0;
        while ((index = haystack.indexOf(needle, index)) != -1) {
            count++;
            index += needle.length();
        }
        return count;
    }
}
