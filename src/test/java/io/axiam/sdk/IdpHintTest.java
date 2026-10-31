package io.axiam.sdk;

import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.PushedAuthorizationRequest;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CONTRACT.md &sect;12.1 (the {@code idp_hint} paragraph) and &sect;26.2 rule 8 (contract 1.65):
 * the optional provider hint on {@code oidcBegin} and {@code oidcPar}.
 */
class IdpHintTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String REDIRECT_URI = "https://app.example.com/cb";
    private static final Set<String> EIGHT = Set.of("response_type", "client_id", "redirect_uri", "scope", "state",
            "nonce", "code_challenge", "code_challenge_method");

    private static List<String> values(HttpUrl url, String name) {
        List<String> all = new ArrayList<>();
        for (int i = 0; i < url.querySize(); i++) {
            if (url.queryParameterName(i).equals(name)) {
                all.add(url.queryParameterValue(i));
            }
        }
        return all;
    }

    private static OidcConfiguration discover(MockWebServer server, AxiamClient client) throws Exception {
        server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
        OidcConfiguration config = client.oidcDiscover();
        server.takeRequest();
        return config;
    }

    @Test
    void idpHintEmittedOnce() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("app").build()) {
                OidcConfiguration config = discover(server, client);
                // A slug, a UUID, a kind name that must not be folded, and a value needing percent-encoding.
                for (String hint : List.of("corp-okta", "0b2f8f0e-6d1f-4c3a-9a53-1f1c9a7d1c11", "Google",
                        "corp okta&x=1/é+")) {
                    AuthorizationRequest request = client.oidcBegin(config, REDIRECT_URI, null, null, hint);
                    HttpUrl url = HttpUrl.parse(request.url());
                    assertEquals(List.of(hint), values(url, "axiam_idp_hint"), "exactly once, intact: " + hint);
                    Set<String> names = new TreeSet<>();
                    for (int i = 0; i < url.querySize(); i++) {
                        names.add(url.queryParameterName(i));
                    }
                    Set<String> expected = new TreeSet<>(EIGHT);
                    expected.add("axiam_idp_hint");
                    assertEquals(expected, names, "beside the other eight, unchanged");
                    assertEquals("openid", url.queryParameter("scope"));
                    assertEquals(request.state(), url.queryParameter("state"));
                }
            }
        }
    }

    @Test
    void idpHintOmittedWhenUnset() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("app").build()) {
                OidcConfiguration config = discover(server, client);
                HttpUrl url = HttpUrl.parse(client.oidcBegin(config, REDIRECT_URI).url());
                HttpUrl viaFive = HttpUrl.parse(client.oidcBegin(config, REDIRECT_URI, null, null, null).url());
                for (HttpUrl u : List.of(url, viaFive)) {
                    Set<String> names = new TreeSet<>();
                    for (int i = 0; i < u.querySize(); i++) {
                        names.add(u.queryParameterName(i));
                    }
                    assertEquals(new TreeSet<>(EIGHT), names, "exactly the eight parameters of rule 5");
                    assertFalse(names.contains("axiam_idp_hint"));
                    assertFalse(names.contains("kc_idp_hint"));
                }
            }
        }
    }

    @Test
    void idpHintNotDuplicated() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("app").build()) {
                OidcConfiguration config = discover(server, client);
                HttpUrl url = HttpUrl.parse(client.oidcBegin(config, REDIRECT_URI, null,
                        Map.of("axiam_idp_hint", "other"), "corp-okta").url());
                assertEquals(List.of("corp-okta"), values(url, "axiam_idp_hint"), "the option's, once");

                // Unset: an additional parameter of the same name passes through, still once.
                HttpUrl passthrough = HttpUrl.parse(client.oidcBegin(config, REDIRECT_URI, null,
                        Map.of("axiam_idp_hint", "other")).url());
                assertEquals(List.of("other"), values(passthrough, "axiam_idp_hint"));
            }
        }
    }

    @Test
    void idpHintBounds() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("app").build()) {
                OidcConfiguration config = discover(server, client);
                assertThrows(ValidationError.class, () -> client.oidcBegin(config, REDIRECT_URI, null, null, ""));
                assertThrows(ValidationError.class,
                        () -> client.oidcBegin(config, REDIRECT_URI, null, null, "a".repeat(257)));
                // Bytes, not characters: 129 two-byte characters is 258 bytes.
                assertThrows(ValidationError.class,
                        () -> client.oidcBegin(config, REDIRECT_URI, null, null, "é".repeat(129)));
                String edge = "a".repeat(256);
                AuthorizationRequest ok = client.oidcBegin(config, REDIRECT_URI, null, null, edge);
                assertEquals(List.of(edge), values(HttpUrl.parse(ok.url()), "axiam_idp_hint"));
                // The same bounds guard the PAR push, with nothing sent.
                int before = server.getRequestCount();
                assertThrows(ValidationError.class, () -> client.oidcPar(config, ok, REDIRECT_URI, null, null, null, ""));
                assertEquals(0, server.getRequestCount() - before);
            }
        }
    }

    @Test
    void parIdpHintInPushedBody() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("app").build()) {
                OidcConfiguration config = discover(server, client);
                AuthorizationRequest begun = client.oidcBegin(config, REDIRECT_URI, null, null, "corp-okta");

                String requestUri = "urn:ietf:params:oauth:request_uri:abc";
                server.enqueue(new MockResponse().setResponseCode(201).setHeader("Content-Type", "application/json")
                        .setBody("{\"request_uri\":\"" + requestUri + "\",\"expires_in\":90}"));
                PushedAuthorizationRequest pushed =
                        client.oidcPar(config, begun, REDIRECT_URI, null, null, null, "corp-okta");

                RecordedRequest request = server.takeRequest();
                List<String> hints = new ArrayList<>();
                for (String pair : request.getBody().readUtf8().split("&")) {
                    int eq = pair.indexOf('=');
                    if (URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8).equals("axiam_idp_hint")) {
                        hints.add(URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                    }
                }
                assertEquals(List.of("corp-okta"), hints, "exactly once in the pushed body");
                // The redirect stays exactly client_id and request_uri.
                HttpUrl redirect = HttpUrl.parse(pushed.url());
                assertEquals(Set.of("client_id", "request_uri"), new TreeSet<>(redirect.queryParameterNames()));
                assertFalse(pushed.url().contains("idp_hint"));

                // Without one the field is absent.
                server.enqueue(new MockResponse().setResponseCode(201).setHeader("Content-Type", "application/json")
                        .setBody("{\"request_uri\":\"" + requestUri + "\",\"expires_in\":90}"));
                client.oidcPar(config, begun, REDIRECT_URI, null, null);
                String bare = server.takeRequest().getBody().readUtf8();
                assertFalse(bare.contains("idp_hint"));
            }
        }
    }
}
