package io.axiam.sdk.errors;

import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;2 sub-type table / &sect;12.3 rule 3: {@link OAuthProtocolError}
 * is a sub-type of {@link AuthError} (so existing {@code catch (AuthError e)}
 * code keeps working), its message is exactly {@code "<error>: <error_description>"},
 * and {@link ErrorMapper#fromOAuth2Response} builds it only for a
 * {@code 400}/{@code 401} carrying an {@code OAuth2ErrorResponse} body.
 */
class OAuthProtocolErrorTest {

    @Test
    void isASubtypeOfAuthErrorSoExistingCatchBlocksStillWork() {
        OAuthProtocolError error = new OAuthProtocolError("invalid_grant", "the authorization code has expired");

        assertInstanceOf(AuthError.class, error, "OAuthProtocolError must remain catchable as AuthError");
    }

    @Test
    void messageIsExactlyErrorColonErrorDescription() {
        OAuthProtocolError error = new OAuthProtocolError("invalid_grant", "the authorization code has expired");

        assertEquals("invalid_grant: the authorization code has expired", error.getMessage());
        assertEquals("invalid_grant", error.error());
        assertEquals("the authorization code has expired", error.errorDescription());
    }

    @Test
    void authErrorReasonDefaultsToNullWhenUnset() {
        AuthError plain = new AuthError("plain failure");
        assertEquals(null, plain.reason());
    }

    @Test
    void authErrorCarriesAnOptionalReasonCode() {
        AuthError withReason = new AuthError("id_token validation failed (invalid_issuer): ...", "invalid_issuer");
        assertEquals("invalid_issuer", withReason.reason());
    }

    @Test
    void fromOAuth2ResponseMapsA400WithOAuth2ErrorBodyToOAuthProtocolError() throws Exception {
        Response response = jsonResponse(400, "{\"error\":\"invalid_grant\",\"error_description\":\"code expired\"}");

        RuntimeException mapped = ErrorMapper.fromOAuth2Response(400, response, "token request failed");

        OAuthProtocolError protocolError = assertInstanceOf(OAuthProtocolError.class, mapped);
        assertEquals("invalid_grant", protocolError.error());
        assertEquals("code expired", protocolError.errorDescription());
    }

    @Test
    void fromOAuth2ResponseMapsA401WithOAuth2ErrorBodyToOAuthProtocolError() throws Exception {
        Response response = jsonResponse(401, "{\"error\":\"invalid_client\",\"error_description\":\"bad client_secret\"}");

        RuntimeException mapped = ErrorMapper.fromOAuth2Response(401, response, "introspect request failed");

        OAuthProtocolError protocolError = assertInstanceOf(OAuthProtocolError.class, mapped);
        assertEquals("invalid_client", protocolError.error());
    }

    @Test
    void fromOAuth2ResponseFallsBackToGenericMappingWhenBodyIsNotOAuth2Shaped() throws Exception {
        Response response = jsonResponse(400, "{\"message\":\"something else\"}");

        RuntimeException mapped = ErrorMapper.fromOAuth2Response(400, response, "token request failed");

        assertInstanceOf(NetworkError.class, mapped, "a 400 without an OAuth2ErrorResponse body stays NetworkError (§2)");
    }

    @Test
    void fromOAuth2ResponseNeverMapsA5xxToOAuthProtocolError() throws Exception {
        Response response = jsonResponse(500, "{\"error\":\"server_error\",\"error_description\":\"boom\"}");

        RuntimeException mapped = ErrorMapper.fromOAuth2Response(500, response, "token request failed");

        assertInstanceOf(NetworkError.class, mapped,
                "a 5xx stays a NetworkError even with an OAuth2-shaped body (port-brief-addendum item 20)");
    }

    @Test
    void fromOAuth2ResponseFallsBackToGenericMappingOnMalformedJsonBody() throws Exception {
        Response response = jsonResponse(400, "{not-valid-json");

        RuntimeException mapped = ErrorMapper.fromOAuth2Response(400, response, "token request failed");

        assertInstanceOf(NetworkError.class, mapped, "a malformed body must fall through, never mask the real status");
    }

    @Test
    void fromOAuth2ResponseWithNullResponseFallsBackToGenericMapping() {
        RuntimeException mapped = ErrorMapper.fromOAuth2Response(401, null, "introspect request failed");
        assertInstanceOf(AuthError.class, mapped);
        assertTrue(!(mapped instanceof OAuthProtocolError));
    }

    private static Response jsonResponse(int status, String body) {
        return new Response.Builder()
                .request(new Request.Builder().url("https://axiam.example.com/oauth2/token").build())
                .protocol(Protocol.HTTP_1_1)
                .code(status)
                .message("status")
                .body(ResponseBody.create(body, MediaType.get("application/json")))
                .build();
    }
}
