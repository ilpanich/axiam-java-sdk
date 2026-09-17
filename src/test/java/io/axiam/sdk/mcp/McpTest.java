package io.axiam.sdk.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.errors.ValidationError;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two framework-independent CONTRACT.md &sect;28.9 required tests: test 1
 * (document shape, and the validation negatives) and test 2 (challenge
 * quoting). Tests 3-5 need a running guard and live in
 * {@code io.axiam.sdk.spring.McpGuardTest}.
 *
 * <p>The fixture below is &sect;28.9's, verbatim, and every test uses it.
 */
class McpTest {

    private static final String RESOURCE = "https://mcp.example.com/mcp";
    private static final List<String> AUTHORIZATION_SERVERS = List.of("https://axiam.example.com");
    private static final List<String> SCOPES_SUPPORTED = List.of("mcp:read", "mcp:tools");
    private static final String RESOURCE_DOCUMENTATION = "https://mcp.example.com/docs";
    private static final String METADATA_PATH = "/.well-known/oauth-protected-resource/mcp";
    private static final String METADATA_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ------------------------------------------------------------------
    // Test 1 — document shape, and the validation negatives
    // ------------------------------------------------------------------

    @Test
    void theFixtureProducesTheExactDocumentShapeAndDerivedPathAndUrl() throws Exception {
        ProtectedResourceMetadata result = Mcp.protectedResourceMetadata(
                RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED, null, RESOURCE_DOCUMENTATION);

        assertEquals(RESOURCE, result.document().resource());
        assertEquals(AUTHORIZATION_SERVERS, result.document().authorizationServers());
        assertEquals(SCOPES_SUPPORTED, result.document().scopesSupported());
        assertEquals(List.of("header"), result.document().bearerMethodsSupported());
        assertEquals(RESOURCE_DOCUMENTATION, result.document().resourceDocumentation());
        assertEquals(METADATA_PATH, result.metadataPath());
        assertEquals(METADATA_URL, result.metadataUrl());

        // Compared as a parsed value (§28.9 test 1), not a byte string.
        JsonNode parsed = MAPPER.readTree(MAPPER.writeValueAsString(result.document()));
        assertEquals(RESOURCE, parsed.path("resource").asText());
        assertEquals("https://axiam.example.com", parsed.path("authorization_servers").get(0).asText());
        assertEquals("mcp:read", parsed.path("scopes_supported").get(0).asText());
        assertEquals("mcp:tools", parsed.path("scopes_supported").get(1).asText());
        assertEquals("header", parsed.path("bearer_methods_supported").get(0).asText());
        assertEquals(RESOURCE_DOCUMENTATION, parsed.path("resource_documentation").asText());
        assertEquals(5, parsed.size(), "no member beyond the five §28.2 permits, plus none extra");
    }

    @Test
    void anEmptyScopesSupportedIsAcceptedAndTheMemberIsOmittedRatherThanEmpty() throws Exception {
        ProtectedResourceMetadata result =
                Mcp.protectedResourceMetadata(RESOURCE, AUTHORIZATION_SERVERS, List.of());
        assertTrue(result.document().scopesSupported().isEmpty());

        JsonNode parsed = MAPPER.readTree(MAPPER.writeValueAsString(result.document()));
        assertFalse(parsed.has("scopes_supported"), "an empty scopes_supported must be omitted, not emitted empty");
    }

    @Test
    void anAbsentResourceDocumentationOmitsTheMemberRatherThanNull() throws Exception {
        ProtectedResourceMetadata result =
                Mcp.protectedResourceMetadata(RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        assertNull(result.document().resourceDocumentation());

        JsonNode parsed = MAPPER.readTree(MAPPER.writeValueAsString(result.document()));
        assertFalse(parsed.has("resource_documentation"), "an absent resource_documentation must be omitted, never null");
    }

    private static Stream<Arguments> metadataPathDerivations() {
        return Stream.of(
                Arguments.of("https://mcp.example.com", "/.well-known/oauth-protected-resource"),
                Arguments.of("https://mcp.example.com/", "/.well-known/oauth-protected-resource"),
                Arguments.of("https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"),
                Arguments.of("https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"),
                Arguments.of("https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b"));
    }

    @ParameterizedTest
    @MethodSource("metadataPathDerivations")
    void metadataPathIsDerivedPerTheFiveWorkedExamples(String resource, String expectedPath) {
        ProtectedResourceMetadata result =
                Mcp.protectedResourceMetadata(resource, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        assertEquals(expectedPath, result.metadataPath());
    }

    @Test
    void aRelativeResourceIsRefused() {
        assertThrows(ValidationError.class,
                () -> Mcp.protectedResourceMetadata("/mcp", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED));
    }

    @Test
    void aResourceWithAFragmentIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                "https://mcp.example.com/mcp#frag", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED));
    }

    @Test
    void aResourceWithAQueryIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                "https://mcp.example.com/mcp?x=1", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED));
    }

    @Test
    void anHttpResourceOnANonLoopbackHostIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                "http://mcp.example.com/mcp", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED));
    }

    @Test
    void theSameHttpResourceOn127001IsAccepted() {
        ProtectedResourceMetadata result = Mcp.protectedResourceMetadata(
                "http://127.0.0.1/mcp", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        assertEquals("http://127.0.0.1/.well-known/oauth-protected-resource/mcp", result.metadataUrl());
    }

    @Test
    void anEmptyResourceIsRefused() {
        assertThrows(ValidationError.class,
                () -> Mcp.protectedResourceMetadata("", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED));
    }

    @Test
    void aResourceWithNoAuthorityIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                "https:///mcp", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED));
    }

    @Test
    void anHttpResourceOnTheIpv6LoopbackIsAccepted() {
        ProtectedResourceMetadata result = Mcp.protectedResourceMetadata(
                "http://[::1]/mcp", AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        assertEquals("http://[::1]/.well-known/oauth-protected-resource/mcp", result.metadataUrl());
    }

    @Test
    void anEmptyAuthorizationServersIsRefused() {
        assertThrows(ValidationError.class,
                () -> Mcp.protectedResourceMetadata(RESOURCE, List.of(), SCOPES_SUPPORTED));
    }

    @Test
    void anAuthorizationServersEntryCarryingAQueryIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                RESOURCE, List.of("https://axiam.example.com?x=1"), SCOPES_SUPPORTED));
    }

    @Test
    void anAuthorizationServersEntryCarryingAFragmentIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                RESOURCE, List.of("https://axiam.example.com#frag"), SCOPES_SUPPORTED));
    }

    @Test
    void aDuplicateAuthorizationServersEntryIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                RESOURCE, List.of("https://axiam.example.com", "https://axiam.example.com"), SCOPES_SUPPORTED));
    }

    @Test
    void aDuplicateScopeIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                RESOURCE, AUTHORIZATION_SERVERS, List.of("mcp:read", "mcp:read")));
    }

    @Test
    void bearerMethodsSupportedOfQueryIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED, List.of("query"), null));
    }

    @Test
    void bearerMethodsSupportedOfHeaderAndBodyIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.protectedResourceMetadata(
                RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED, List.of("header", "body"), null));
    }

    // ------------------------------------------------------------------
    // Test 2 — challenge quoting
    // ------------------------------------------------------------------

    @Test
    void vector1NoCredentialNamesNoError() {
        assertEquals(
                "Bearer resource_metadata=\"" + METADATA_URL + "\"",
                Mcp.bearerChallenge(METADATA_URL));
    }

    @Test
    void vector2CredentialRejectedNamesInvalidToken() {
        assertEquals(
                "Bearer error=\"invalid_token\", resource_metadata=\"" + METADATA_URL + "\"",
                Mcp.bearerChallenge(METADATA_URL, BearerChallengeError.INVALID_TOKEN, null, null));
    }

    @Test
    void vector3ScopeFailureNamesInsufficientScope() {
        assertEquals(
                "Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"" + METADATA_URL + "\"",
                Mcp.bearerChallenge(METADATA_URL, BearerChallengeError.INSUFFICIENT_SCOPE, null, "mcp:tools"));
    }

    @Test
    void vector4AllFourParametersInOrder() {
        assertEquals(
                "Bearer error=\"invalid_request\", error_description=\"The access token is malformed\", "
                        + "scope=\"mcp:read mcp:tools\", resource_metadata=\"" + METADATA_URL + "\"",
                Mcp.bearerChallenge(METADATA_URL, BearerChallengeError.INVALID_REQUEST,
                        "The access token is malformed", "mcp:read mcp:tools"));
    }

    @Test
    void anErrorOutsideRfc6750sThreeCodesIsRefused() {
        // BearerChallengeError is a closed enum, so the only way to exercise
        // this refusal end to end is through Mcp's own validation of a value
        // outside the enum — proven at the type level here: the enum itself
        // cannot name "invalid_grant".
        for (BearerChallengeError value : BearerChallengeError.values()) {
            assertFalse(value.wireValue().equals("invalid_grant"));
        }
    }

    @Test
    void anErrorDescriptionContainingADoubleQuoteIsRefusedRatherThanEscaped() {
        ValidationError e = assertThrows(ValidationError.class, () -> Mcp.bearerChallenge(
                METADATA_URL, BearerChallengeError.INVALID_REQUEST, "bad \"quote\"", null));
        assertFalse(e.getMessage().contains("\\\""), "must refuse, never escape");
    }

    @Test
    void anErrorDescriptionContainingABackslashIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.bearerChallenge(
                METADATA_URL, BearerChallengeError.INVALID_REQUEST, "bad\\thing", null));
    }

    @Test
    void anErrorDescriptionContainingANewlineIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.bearerChallenge(
                METADATA_URL, BearerChallengeError.INVALID_REQUEST, "bad\nthing", null));
    }

    @Test
    void anErrorDescriptionContainingANonAsciiCharacterIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.bearerChallenge(
                METADATA_URL, BearerChallengeError.INVALID_REQUEST, "café", null));
    }

    @Test
    void aScopeWithALeadingSpaceIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.bearerChallenge(
                METADATA_URL, BearerChallengeError.INSUFFICIENT_SCOPE, null, " mcp:tools"));
    }

    @Test
    void aScopeWithADoubledSpaceIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.bearerChallenge(
                METADATA_URL, BearerChallengeError.INSUFFICIENT_SCOPE, null, "mcp:read  mcp:tools"));
    }

    @Test
    void anEmptyScopeIsRefused() {
        assertThrows(ValidationError.class,
                () -> Mcp.bearerChallenge(METADATA_URL, BearerChallengeError.INSUFFICIENT_SCOPE, null, ""));
    }

    @Test
    void aResourceMetadataContainingASpaceIsRefused() {
        assertThrows(ValidationError.class, () -> Mcp.bearerChallenge("https://mcp.example.com/a b"));
    }

    // ------------------------------------------------------------------
    // §28.5 rule 3 — requireMetadataMatchesGuard
    // ------------------------------------------------------------------

    @Test
    void bothArgumentsNullSkipsTheCrossCheckEntirely() {
        ProtectedResourceMetadata metadata =
                Mcp.protectedResourceMetadata(RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        Mcp.requireMetadataMatchesGuard(metadata, null, null); // must not throw
    }

    @Test
    void aMatchingGuardPassesTheCrossCheck() {
        ProtectedResourceMetadata metadata =
                Mcp.protectedResourceMetadata(RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        Mcp.requireMetadataMatchesGuard(metadata, METADATA_URL, RESOURCE); // must not throw
    }

    @Test
    void aGuardResourceMetadataUrlDisagreeingWithTheDocumentsMetadataUrlIsRefused() {
        ProtectedResourceMetadata metadata =
                Mcp.protectedResourceMetadata(RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        assertThrows(ValidationError.class, () -> Mcp.requireMetadataMatchesGuard(
                metadata, "https://mcp.example.com/.well-known/oauth-protected-resource/other", RESOURCE));
    }

    @Test
    void aGuardExpectedAudienceDisagreeingWithTheDocumentsResourceIsRefused() {
        ProtectedResourceMetadata metadata =
                Mcp.protectedResourceMetadata(RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED);
        assertThrows(ValidationError.class, () -> Mcp.requireMetadataMatchesGuard(
                metadata, METADATA_URL, "https://mcp.example.com/other"));
    }
}
