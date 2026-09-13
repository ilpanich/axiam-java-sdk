package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.MtlsEndpointAliases;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.testutil.TestCerts;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RFC 8705 &sect;5 {@code mtls_endpoint_aliases} — CONTRACT.md &sect;21.3
 * rule 2 (contract 1.40).
 *
 * <p>The rule has one sentence and three named ways to get it wrong, and this
 * class is organised around them rather than around the SDK's method list:
 *
 * <ul>
 *   <li>a call going over mTLS prefers the alias;</li>
 *   <li>a call NOT going over mTLS keeps the top-level entry;</li>
 *   <li>an ABSENT member means "no separate mTLS host", never
 *       "unsupported";</li>
 *   <li>only the six listed endpoints are ever aliased — not
 *       {@code authorization_endpoint}, {@code end_session_endpoint} or
 *       {@code jwks_uri};</li>
 *   <li>{@code issuer} is not an endpoint, does not move, and still governs
 *       {@code iss} validation by exact string.</li>
 * </ul>
 *
 * <p>Two {@link MockWebServer}s stand in for the two listeners a deployment
 * runs. The &sect;6.1 identity is a throwaway keypair; both servers speak
 * plain HTTP, so no handshake occurs — what is under test is <em>which URL the
 * SDK chooses</em>, which the configured identity and the document decide, not
 * the socket.
 */
class AxiamClientMtlsEndpointAliasesTest {

    private static final String TENANT = "33333333-3333-3333-3333-333333333333";
    private static final UUID TENANT_UUID = UUID.fromString(TENANT);

    @TempDir
    Path tempDir;

    /** The paths each origin was asked for, in order. */
    private final List<String> conventionalHits = Collections.synchronizedList(new ArrayList<>());
    private final List<String> mtlsHits = Collections.synchronizedList(new ArrayList<>());

    private static String strip(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** The reply each OAuth2 endpoint's caller will accept. */
    private static MockResponse oauth2Response(String path) {
        String body;
        int code = 200;
        switch (path) {
            case "/oauth2/device_authorization" -> body = "{\"device_code\":\"d\",\"user_code\":\"WDJB-MJHT\","
                    + "\"verification_uri\":\"https://example.test/device\",\"expires_in\":30,\"interval\":1}";
            case "/oauth2/par" -> {
                // RFC 9126 §2.2 specifies Created, and the SDK asserts exactly that.
                code = 201;
                body = "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:x\",\"expires_in\":60}";
            }
            case "/oauth2/introspect" -> body = "{\"active\":true}";
            case "/oauth2/revoke" -> body = "{}";
            default -> body = "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":900}";
        }
        return new MockResponse().setResponseCode(code)
                .setHeader("Content-Type", "application/json").setBody(body);
    }

    /**
     * The discovery document, with the six aliases pointing at {@code mtlsBase}
     * when {@code aliases} is non-null. {@code aliasesJson} is inserted
     * verbatim so a test can publish a partial object.
     */
    private static String discoveryJson(String base, String aliasesJson) {
        String t = strip(base);
        return "{"
                + "\"issuer\":\"" + t + "\","
                + "\"authorization_endpoint\":\"" + t + "/oauth2/authorize\","
                + "\"token_endpoint\":\"" + t + "/oauth2/token\","
                + "\"userinfo_endpoint\":\"" + t + "/oauth2/userinfo\","
                + "\"jwks_uri\":\"" + t + "/oauth2/jwks\","
                + "\"revocation_endpoint\":\"" + t + "/oauth2/revoke\","
                + "\"introspection_endpoint\":\"" + t + "/oauth2/introspect\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"EdDSA\"],"
                + "\"scopes_supported\":[\"openid\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"client_secret_post\"],"
                + "\"claims_supported\":[\"sub\",\"iss\"],"
                + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\",\"client_credentials\","
                + "\"urn:ietf:params:oauth:grant-type:device_code\"],"
                + "\"device_authorization_endpoint\":\"" + t + "/oauth2/device_authorization\","
                + "\"pushed_authorization_request_endpoint\":\"" + t + "/oauth2/par\","
                + "\"end_session_endpoint\":\"" + t + "/oauth2/end_session\","
                + "\"backchannel_logout_supported\":true,"
                + "\"backchannel_logout_session_supported\":true"
                + (aliasesJson == null ? "" : ",\"mtls_endpoint_aliases\":" + aliasesJson)
                + "}";
    }

    /** All six aliases on {@code mtlsBase}. */
    private static String allAliases(String mtlsBase) {
        String m = strip(mtlsBase);
        return "{"
                + "\"token_endpoint\":\"" + m + "/oauth2/token\","
                + "\"userinfo_endpoint\":\"" + m + "/oauth2/userinfo\","
                + "\"revocation_endpoint\":\"" + m + "/oauth2/revoke\","
                + "\"introspection_endpoint\":\"" + m + "/oauth2/introspect\","
                + "\"device_authorization_endpoint\":\"" + m + "/oauth2/device_authorization\","
                + "\"pushed_authorization_request_endpoint\":\"" + m + "/oauth2/par\""
                + "}";
    }

    private Dispatcher recordingDispatcher(List<String> hits, java.util.function.Supplier<String> discovery) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String path = URI.create(request.getPath()).getPath();
                if (path.equals("/.well-known/openid-configuration")) {
                    return new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json").setBody(discovery.get());
                }
                hits.add(path);
                return oauth2Response(path);
            }
        };
    }

    /**
     * Builds a client against {@code conventional}, optionally carrying a
     * &sect;6.1 identity so &sect;21.3 rule 2 applies to every call it makes.
     */
    private AxiamClient client(MockWebServer conventional, boolean mtls) throws Exception {
        AxiamClient.Builder b = AxiamClient.builder(conventional.url("/").toString(), TENANT)
                .oidcClientId("axiam-rp")
                .oidcClientSecret("rp-secret-value");
        if (mtls) {
            TestCerts.Identity id = TestCerts.selfSignedIdentity(tempDir, "alias-client-" + UUID.randomUUID());
            b = b.clientCertificate(id.certPem(), id.keyPem());
        }
        return b.build();
    }

    // ── The document round-trips the member ────────────────────────────────

    @Test
    void discoveryExposesTheMemberWhenPublished() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString());
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();

            try (AxiamClient client = client(conv, false)) {
                OidcConfiguration config = client.oidcDiscover();

                MtlsEndpointAliases got = config.mtls_endpoint_aliases();
                assertNotNull(got, "the member the server published must survive parsing");
                assertEquals(strip(mtls.url("/").toString()) + "/oauth2/token", got.token_endpoint());
                // Alongside, never instead of: the conventional entry is untouched.
                assertEquals(strip(conv.url("/").toString()) + "/oauth2/token", config.token_endpoint());
            }
        }
    }

    @Test
    void anAbsentMemberParsesToNullRatherThanFailing() throws Exception {
        try (MockWebServer conv = new MockWebServer()) {
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), null)));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                OidcConfiguration config = client.oidcDiscover();
                assertNull(config.mtls_endpoint_aliases(),
                        "a document with no aliases is valid, not an error");
            }
        }
    }

    // ── A call over mTLS prefers the alias ─────────────────────────────────

    @Test
    void everyAliasableEndpointGoesToTheAliasHost() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.setDispatcher(recordingDispatcher(mtlsHits, () -> "{}"));
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString());
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                client.loginClientCredentials(null, TENANT_UUID, null);
                client.introspect(Sensitive.of("t"), null, TENANT_UUID, null);
                client.revoke(Sensitive.of("t"), null, TENANT_UUID, null);
                client.deviceAuthorize(null, TENANT_UUID, null);
                OidcConfiguration config = client.oidcDiscover();
                AuthorizationRequest request = client.oidcBegin(config, "https://app.example.com/cb");
                client.oidcPar(config, request, "https://app.example.com/cb", "openid", TENANT_UUID);
            }

            assertEquals(List.of("/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
                    "/oauth2/device_authorization", "/oauth2/par"), mtlsHits);
            assertTrue(conventionalHits.isEmpty(),
                    "no aliasable endpoint may reach the conventional host: " + conventionalHits);
        }
    }

    // ── Consequence 1: absence means "no separate host" ────────────────────

    @Test
    void anMtlsClientWithNoAliasesKeepsTheTopLevelEndpoints() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.setDispatcher(recordingDispatcher(mtlsHits, () -> "{}"));
            mtls.start();
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), null)));
            conv.start();

            // Not an error, and not the alias origin: a deployment running
            // client_auth = optional on one listener serves both populations at
            // the conventional endpoints and correctly publishes nothing.
            try (AxiamClient client = client(conv, true)) {
                client.introspect(Sensitive.of("t"), null, TENANT_UUID, null);
            }

            assertEquals(List.of("/oauth2/introspect"), conventionalHits);
            assertTrue(mtlsHits.isEmpty());
        }
    }

    @Test
    void aClientNotDoingMtlsKeepsTheTopLevelEndpoints() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.setDispatcher(recordingDispatcher(mtlsHits, () -> "{}"));
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString());
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();

            try (AxiamClient client = client(conv, false)) {
                client.revoke(Sensitive.of("t"), null, TENANT_UUID, null);
            }

            assertEquals(List.of("/oauth2/revoke"), conventionalHits);
            assertTrue(mtlsHits.isEmpty());
        }
    }

    @Test
    void aPartialAliasObjectFallsBackPerEndpoint() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.setDispatcher(recordingDispatcher(mtlsHits, () -> "{}"));
            mtls.start();
            // RFC 8705 §5 does not require an OP to alias all six, and the
            // shape of this member must never be why a client stops working.
            String partial = "{\"token_endpoint\":\"" + strip(mtls.url("/").toString()) + "/oauth2/token\"}";
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), partial)));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                client.loginClientCredentials(null, TENANT_UUID, null);
                client.introspect(Sensitive.of("t"), null, TENANT_UUID, null);
            }

            assertEquals(List.of("/oauth2/token"), mtlsHits, "the one aliased endpoint uses its alias");
            assertEquals(List.of("/oauth2/introspect"), conventionalHits,
                    "an endpoint the object does not name falls back to the top level");
        }
    }

    @Test
    void anUnsupportedGrantIsStillReportedWhenNeitherLevelNamesIt() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString())
                    .replace(",\"device_authorization_endpoint\":\""
                            + strip(mtls.url("/").toString()) + "/oauth2/device_authorization\"", "");
            String document = discoveryJson(conv.url("/").toString(), aliases)
                    .replace("\"device_authorization_endpoint\":\""
                            + strip(conv.url("/").toString()) + "/oauth2/device_authorization\",", "");
            conv.setDispatcher(recordingDispatcher(conventionalHits, () -> document));
            conv.start();

            // Neither level names the endpoint, so the answer is still "this
            // server does not support the device grant" — never a URL built by
            // concatenation.
            try (AxiamClient client = client(conv, true)) {
                assertThrows(AuthError.class, () -> client.deviceAuthorize(null, TENANT_UUID, null));
            }
        }
    }

    // ── Consequence 2: no alias is ever synthesised ────────────────────────

    @Test
    void theFrontChannelAndJwksEndpointsAreNeverAliased() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString());
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();
            String conventionalOrigin = strip(conv.url("/").toString());

            try (AxiamClient client = client(conv, true)) {
                OidcConfiguration config = client.oidcDiscover();

                // A browser sent to an mTLS host raises a native
                // certificate-chooser dialog most users cannot answer, and
                // jwks_uri is public key material that gains nothing from a
                // handshake.
                AuthorizationRequest request = client.oidcBegin(config, "https://app.example.com/cb");
                assertTrue(request.url().startsWith(conventionalOrigin + "/oauth2/authorize"),
                        "authorization_endpoint must stay on the conventional host: " + request.url());

                String logout = client.logoutUrl(Sensitive.of("not-a-real-token"), null, null, config);
                assertTrue(logout.startsWith(conventionalOrigin + "/oauth2/end_session"),
                        "end_session_endpoint must stay on the conventional host: " + logout);

                assertEquals(conventionalOrigin + "/oauth2/jwks", config.jwks_uri(),
                        "jwks_uri must stay on the conventional host");
            }
        }
    }

    @Test
    void theAliasRecordCarriesOnlyTheSixAliasableEndpoints() {
        // Naming them as a closed set is what makes authorization_endpoint,
        // end_session_endpoint and jwks_uri unrepresentable rather than merely
        // unused. A seventh component here would be an alias the SDK could
        // synthesise.
        List<String> components = java.util.Arrays.stream(MtlsEndpointAliases.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName)
                .sorted()
                .toList();
        assertEquals(List.of(
                "device_authorization_endpoint",
                "introspection_endpoint",
                "pushed_authorization_request_endpoint",
                "revocation_endpoint",
                "token_endpoint",
                "userinfo_endpoint"), components);
    }

    // ── Consequence 3: issuer is never aliased ─────────────────────────────

    @Test
    void theIssuerDoesNotMoveWithTheEndpoints() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString());
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                OidcConfiguration config = client.oidcDiscover();

                // §12.4 rule 3 compares `iss` against THIS value by exact
                // string, for every token — including one minted at an alias
                // endpoint. An SDK that derived an expected issuer from the
                // host it called would reject every token it obtains over mTLS.
                assertEquals(strip(conv.url("/").toString()), config.issuer());
                assertFalse(config.issuer().equals(strip(mtls.url("/").toString())),
                        "issuer must not follow the aliased endpoints to the mTLS host");
            }
        }
    }

    // ── Vector C: a malformed alias is refused, never fallen back from ─────
    //
    // CONTRACT.md §21.3.1 vector C, contract 1.43. Rule 2 had been normative
    // since 1.40 and, until the 2026-09-12 pass, said nothing about an alias
    // that is PRESENT and unusable — every SDK that read the member fell back
    // to the top-level endpoint. Falling back looks like the safe answer and is
    // the dangerous one: the caller asked to authenticate with a certificate,
    // the operator published something unusable, and sending the certificate to
    // the front-channel host authenticates nothing while appearing to work.

    @Test
    void aRelativeAliasIsRefusedRatherThanResolved() throws Exception {
        // A relative alias resolves against nothing the client holds, and the
        // base that might seem obvious — the issuer's host — is precisely the
        // host the alias exists to name a different one from.
        try (MockWebServer conv = new MockWebServer()) {
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(),
                            "{\"token_endpoint\":\"/oauth2/token\"}")));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                AuthError refused = assertThrows(AuthError.class,
                        () -> client.loginClientCredentials(null, TENANT_UUID, null));
                assertTrue(refused.getMessage().contains("not an absolute URL"), refused.getMessage());
            }

            // And the certificate never reached the conventional host, which is
            // the whole point of refusing rather than falling back.
            assertTrue(conventionalHits.isEmpty(),
                    "a refused alias still produced a call to " + conventionalHits);
        }
    }

    @Test
    void aSchemeDowngradeIsRefused() throws Exception {
        // The comparison is like with like: the alias substitutes for exactly
        // one top-level endpoint, and that endpoint's scheme is what a
        // downgrade is measured against.
        try (MockWebServer conv = new MockWebServer()) {
            conv.setDispatcher(recordingDispatcher(conventionalHits, () -> {
                String document = discoveryJson(conv.url("/").toString(),
                        "{\"token_endpoint\":\"http://mtls.example.test/oauth2/token\"}");
                return document.replace("\"token_endpoint\":\"" + strip(conv.url("/").toString())
                        + "/oauth2/token\"", "\"token_endpoint\":\"https://iam.example.test/oauth2/token\"");
            }));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                AuthError refused = assertThrows(AuthError.class,
                        () -> client.loginClientCredentials(null, TENANT_UUID, null));
                assertTrue(refused.getMessage().contains("downgrade"), refused.getMessage());
            }
        }
    }

    /**
     * The I4 twin of the downgrade refusal, and the reason the rule compares
     * like with like rather than demanding {@code https} outright: an
     * {@code http} alias for an {@code http} endpoint is a development
     * deployment, which AXIAM's own {@code build_mtls_aliases} supports and
     * this class's own servers are. A rule written as "the scheme must be
     * https" would have failed every test above.
     */
    @Test
    void anHttpAliasForAnHttpEndpointIsAccepted() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.setDispatcher(recordingDispatcher(mtlsHits, () -> "{}"));
            mtls.start();
            String aliases = allAliases(mtls.url("/").toString());
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                client.loginClientCredentials(null, TENANT_UUID, null);
            }

            assertEquals(List.of("/oauth2/token"), mtlsHits);
        }
    }

    /**
     * The second I4 twin, and the more important one: a client with no
     * certificate never reads the member at all, not even to validate it. A
     * deployment whose aliases are malformed cannot break the clients that
     * never use them.
     */
    @Test
    void aMalformedAliasCannotBreakAClientNotDoingMtls() throws Exception {
        try (MockWebServer conv = new MockWebServer()) {
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(),
                            "{\"token_endpoint\":\"not-a-url-at-all\"}")));
            conv.start();

            try (AxiamClient client = client(conv, false)) {
                client.loginClientCredentials(null, TENANT_UUID, null);
            }

            assertEquals(List.of("/oauth2/token"), conventionalHits);
        }
    }

    /**
     * Per endpoint, like the fallback itself: one malformed alias stops the
     * calls that would have used it and leaves every other endpoint working.
     */
    @Test
    void oneMalformedAliasDoesNotPoisonTheOthers() throws Exception {
        try (MockWebServer mtls = new MockWebServer(); MockWebServer conv = new MockWebServer()) {
            mtls.setDispatcher(recordingDispatcher(mtlsHits, () -> "{}"));
            mtls.start();
            String m = strip(mtls.url("/").toString());
            String aliases = "{\"token_endpoint\":\"" + m + "/oauth2/token\","
                    + "\"introspection_endpoint\":\"::not a url::\"}";
            conv.setDispatcher(recordingDispatcher(conventionalHits,
                    () -> discoveryJson(conv.url("/").toString(), aliases)));
            conv.start();

            try (AxiamClient client = client(conv, true)) {
                client.loginClientCredentials(null, TENANT_UUID, null);
                AuthError refused = assertThrows(AuthError.class,
                        () -> client.introspect(Sensitive.of("t"), null, TENANT_UUID, null));
                assertTrue(refused.getMessage().contains("not an absolute URL"), refused.getMessage());
            }

            assertEquals(List.of("/oauth2/token"), mtlsHits);
        }
    }
}
