package io.axiam.sdk;

import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.1 rule 3: no redirect is followed from a POST to an {@code /oauth2/*} endpoint; a
 * {@code 3xx} is a {@link NetworkError} (C165-23), whatever its body carries (C165-25).
 */
class Oauth2NoRedirectTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String REFRESH = "the-refresh-token";
    private static final String SECRET = "s3cret";

    private void assertRedirectRefused(int status, Consumer<AxiamClient> call) throws Exception {
        try (MockWebServer server = new MockWebServer(); MockWebServer other = new MockWebServer()) {
            other.start();
            server.start();
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(status)
                    .setHeader("Location", other.url("/oauth2/token").toString()));
            // If the redirect were followed, this is what the second host would answer.
            other.enqueue(new MockResponse().setResponseCode(200).setBody("{}"));
            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("app").oidcClientSecret(SECRET).build()) {
                client.oidcDiscover();
                NetworkError e = assertThrows(NetworkError.class, () -> call.accept(client));
                assertEquals(0, other.getRequestCount(), "the second host must receive no request");
                String text = String.valueOf(e.getMessage()) + e.getCause();
                assertFalse(text.contains(SECRET) || text.contains(REFRESH), "no secret in the error: " + text);
                assertTrue(server.getRequestCount() == 2, "exactly one token POST was sent");
            }
        }
    }

    @Test
    void oidcRefresh307IsNetworkErrorAndSecondHostSeesNothing() throws Exception {
        assertRedirectRefused(307, c -> c.oidcRefresh(REFRESH));
    }

    @Test
    void oidcRefresh308IsNetworkErrorAndSecondHostSeesNothing() throws Exception {
        assertRedirectRefused(308, c -> c.oidcRefresh(REFRESH));
    }

    @Test
    void clientCredentials307IsNetworkErrorAndSecondHostSeesNothing() throws Exception {
        assertRedirectRefused(307, AxiamClient::loginClientCredentials);
    }

    @Test
    void clientCredentials302IsNetworkErrorAndSecondHostSeesNothing() throws Exception {
        assertRedirectRefused(302, AxiamClient::loginClientCredentials);
    }

    @Test
    void redirectWhoseBodyCarriesAnErrorIsNetworkErrorNotOAuthProtocolError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.oauthError(302, "invalid_grant")
                    .setHeader("Location", "http://127.0.0.1:1/oauth2/token"));
            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("app").oidcClientSecret(SECRET).build()) {
                client.oidcDiscover();
                assertThrows(NetworkError.class, client::loginClientCredentials);
            }
        }
    }

    @Test
    void anyStatusMapperAlsoChecksTheStatusFirst() {
        okhttp3.Response response = new okhttp3.Response.Builder()
                .request(new okhttp3.Request.Builder().url("http://localhost/oauth2/token").build())
                .protocol(okhttp3.Protocol.HTTP_1_1).code(307).message("Temporary Redirect")
                .header("Location", "http://other.invalid/oauth2/token")
                .body(okhttp3.ResponseBody.create("{\"error\":\"invalid_grant\"}",
                        okhttp3.MediaType.get("application/json")))
                .build();
        assertTrue(io.axiam.sdk.errors.ErrorMapper.fromOAuth2ErrorAtAnyStatus(307, response, "x") instanceof NetworkError);
        assertTrue(io.axiam.sdk.errors.ErrorMapper.fromOAuth2Response(307, response, "x") instanceof NetworkError);
    }
}
