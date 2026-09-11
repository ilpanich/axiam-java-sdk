package io.axiam.sdk;

import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Contract 1.42 &mdash; the discovery document may publish the tenant
 * <em>inside</em> the endpoint URLs it advertises, and the SDK must not append
 * a second one.
 *
 * <p>Since contract 1.42 the server's {@code tenant_scoped()} helper appends
 * {@code ?tenant_id=<uuid>} to the token, revocation, introspection,
 * device-authorization, PAR and end-session endpoints whenever the discovery
 * request named a tenant or the deployment sets
 * {@code oauth2_default_tenant_id}. ({@code userinfo_endpoint} and
 * {@code jwks_uri} are deliberately never scoped.)
 *
 * <p>This SDK builds every {@code /oauth2/*} URL through one helper,
 * {@code AxiamClient.oauth2Url}, which used OkHttp's
 * {@link HttpUrl.Builder#addQueryParameter} &mdash; and that <em>appends</em>.
 * Against a scoped document it therefore produced
 * {@code ?tenant_id=A&tenant_id=B}: two values for the parameter that decides
 * which tenant's users a token is minted for, resolved by whichever one the
 * server's query parser happens to reach first. The fix is replace-don't-append,
 * and these tests are what stops it regressing.
 *
 * <p>Two invariants, and the second is why this is not simply
 * {@code query(null)}: <strong>exactly one</strong> {@code tenant_id} reaches
 * the wire, carrying the <em>resolved</em> value, and <strong>every other</strong>
 * query parameter the endpoint carried survives &mdash; RFC 6749 &sect;3.1/&sect;3.2
 * require a client to retain the endpoint's own query component.
 */
class AxiamClientTenantScopedDiscoveryTest {

    /** The tenant this client authenticated against — the one that must win. */
    private static final UUID CLIENT_TENANT =
            UUID.fromString("33333333-3333-3333-3333-333333333333");

    /**
     * A <em>different</em> tenant, pre-baked into the advertised endpoints.
     * Deliberately not equal to {@link #CLIENT_TENANT}: if the two matched, a
     * doubled parameter and a correct one would be indistinguishable in the
     * assertion.
     */
    private static final UUID DOCUMENT_TENANT =
            UUID.fromString("99999999-9999-9999-9999-999999999999");

    private static AxiamClient client(String base) {
        return AxiamClient.builder(base, CLIENT_TENANT.toString())
                .oidcClientId("app")
                .oidcClientSecret("s3cret")
                .build();
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * The document a tenant-scoped discovery request gets back: every
     * {@code /oauth2/*} endpoint already carries {@code tenant_id}, and the
     * token endpoint additionally carries an unrelated parameter that must
     * survive untouched.
     */
    private static OidcConfiguration scopedConfiguration(String base) {
        String root = stripSlash(base);
        String scope = "?tenant_id=" + DOCUMENT_TENANT;
        return new OidcConfiguration(
                root,
                root + "/oauth2/authorize",
                root + "/oauth2/token" + scope + "&audience=legacy",
                root + "/oauth2/userinfo",
                root + "/oauth2/jwks",
                root + "/oauth2/revoke" + scope,
                root + "/oauth2/introspect" + scope,
                List.of("code"),
                List.of("public"),
                List.of("EdDSA"),
                List.of("openid"),
                List.of("client_secret_post"),
                List.of("sub"),
                List.of("authorization_code", "client_credentials"),
                root + "/oauth2/device_authorization" + scope,
                root + "/oauth2/par" + scope,
                root + "/oauth2/end_session" + scope,
                false,
                false);
    }

    private static MockResponse tokenResponse() {
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":900}");
    }

    /**
     * Asserts the recorded request carried exactly one {@code tenant_id}, and
     * that it was the resolved one.
     */
    private static void assertSingleResolvedTenant(HttpUrl url) {
        assertEquals(List.of(CLIENT_TENANT.toString()), url.queryParameterValues("tenant_id"),
                "exactly one tenant_id, carrying the resolved value");
    }

    @Test
    void theTokenEndpointGetsOneTenantIdAndKeepsItsOtherQueryParameters() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = scopedConfiguration(server.url("/").toString());
                server.enqueue(tokenResponse());

                client.loginClientCredentials("openid", null, config);

                HttpUrl url = Objects.requireNonNull(server.takeRequest().getRequestUrl());
                assertEquals("/oauth2/token", url.encodedPath());
                assertSingleResolvedTenant(url);
                // RFC 6749 §3.2: the endpoint's own query component is the
                // deployment's, not the SDK's to discard.
                assertEquals("legacy", url.queryParameter("audience"));
            }
        }
    }

    @Test
    void theRevocationEndpointGetsOneTenantId() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = scopedConfiguration(server.url("/").toString());
                server.enqueue(new MockResponse().setResponseCode(200));

                client.revoke(io.axiam.sdk.Sensitive.of("some-token"), null, null, config);

                HttpUrl url = Objects.requireNonNull(server.takeRequest().getRequestUrl());
                assertEquals("/oauth2/revoke", url.encodedPath());
                assertSingleResolvedTenant(url);
            }
        }
    }

    @Test
    void theIntrospectionEndpointGetsOneTenantId() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = scopedConfiguration(server.url("/").toString());
                server.enqueue(new MockResponse()
                        .setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"active\":true}"));

                client.introspect(io.axiam.sdk.Sensitive.of("some-token"), null, null, config);

                HttpUrl url = Objects.requireNonNull(server.takeRequest().getRequestUrl());
                assertEquals("/oauth2/introspect", url.encodedPath());
                assertSingleResolvedTenant(url);
            }
        }
    }

    @Test
    void theParEndpointGetsOneTenantId() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = scopedConfiguration(server.url("/").toString());
                AuthorizationRequest begun = client.oidcBegin(config, "https://app.example.com/callback");
                server.enqueue(new MockResponse()
                        .setResponseCode(201)
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"request_uri\":\"urn:ietf:params:oauth:request_uri:x\",\"expires_in\":90}"));

                client.oidcPar(config, begun, "https://app.example.com/callback", "openid", null);

                HttpUrl url = Objects.requireNonNull(server.takeRequest().getRequestUrl());
                assertEquals("/oauth2/par", url.encodedPath());
                assertSingleResolvedTenant(url);
            }
        }
    }

    @Test
    void anExplicitTenantArgumentStillWinsOverTheDocumentsOwn() throws Exception {
        UUID explicit = UUID.fromString("44444444-4444-4444-4444-444444444444");
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = scopedConfiguration(server.url("/").toString());
                server.enqueue(tokenResponse());

                client.loginClientCredentials("openid", explicit, config);

                HttpUrl url = Objects.requireNonNull(server.takeRequest().getRequestUrl());
                assertEquals(List.of(explicit.toString()), url.queryParameterValues("tenant_id"));
            }
        }
    }

    /**
     * {@code end_session_endpoint} is scoped by the same server-side helper,
     * but {@code logoutUrl} never adds a {@code tenant_id} of its own — it
     * carries the document's through verbatim. Asserted here so that a future
     * "make logout consistent with the token endpoint" change has to notice
     * that consistency would mean <em>overwriting</em> a value the SDK has no
     * opinion about on a front-channel URL.
     */
    @Test
    void logoutUrlCarriesTheDocumentsOwnTenantThrough() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = scopedConfiguration(server.url("/").toString());

                HttpUrl url = Objects.requireNonNull(HttpUrl.parse(
                        client.logoutUrl(io.axiam.sdk.Sensitive.of("id-token"), null, null, config)));

                assertEquals(List.of(DOCUMENT_TENANT.toString()), url.queryParameterValues("tenant_id"));
            }
        }
    }

    /**
     * The bare (unscoped) document a discovery request that named no tenant
     * gets back: the SDK supplies the parameter, exactly once, as it always
     * has.
     */
    @Test
    void anUnscopedDocumentStillGetsExactlyOneTenantId() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();
            try (AxiamClient client = client(server.url("/").toString())) {
                OidcConfiguration config = client.oidcDiscover();
                server.takeRequest();
                assertNull(HttpUrl.get(config.token_endpoint()).queryParameter("tenant_id"));

                server.enqueue(tokenResponse());
                client.loginClientCredentials("openid", null, config);

                assertSingleResolvedTenant(
                        Objects.requireNonNull(server.takeRequest().getRequestUrl()));
            }
        }
    }
}
