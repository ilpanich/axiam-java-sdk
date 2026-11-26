package io.axiam.sdk.spring;

import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.oidc.MemoryOidcStateStore;
import io.axiam.sdk.oidc.OidcStateEntry;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;

import jakarta.servlet.http.Cookie;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.8 (contract 1.68; C7, C6): the Spring "Login with AXIAM" glue binds the
 * callback to the browser that started the login, and honours only a same-origin relative
 * {@code return_to}. The required tests of &sect;12.8 rule 4, over a real login-then-callback
 * round trip against a mock AXIAM.
 */
class AxiamOidcLoginBindingTest {

    private static final List<HttpMessageConverter<?>> CONVERTERS =
            List.of(new StringHttpMessageConverter(), new MappingJackson2HttpMessageConverter());
    private static final String HTTPS_CALLBACK = "https://app.example.com/oidc/callback";
    private static final String TENANT = "33333333-3333-3333-3333-333333333333";
    private static final String UNIFORM_401 = "unknown, expired, or already-used login state";

    // --- login response ------------------------------------------------------

    @Test
    void loginSetsTheHostPrefixedBindingCookieWithTheContractAttributes() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            MockHttpServletResponse response = h.dispatch("GET", "/oidc/login", null);

            assertEquals(302, response.getStatus());
            String setCookie = h.bindingSetCookie(response);
            assertTrue(setCookie.startsWith("__Host-axiam_oidc_bind="), setCookie);
            assertTrue(setCookie.contains("HttpOnly"), setCookie);
            assertTrue(setCookie.contains("Secure"), setCookie);
            assertTrue(setCookie.contains("SameSite=Lax"), setCookie);
            assertTrue(setCookie.contains("Path=/"), setCookie);
            assertFalse(setCookie.toLowerCase().contains("domain"), setCookie);
            assertTrue(setCookie.contains("Max-Age=600"), setCookie);
            // 32 random bytes, base64url without padding.
            assertEquals(43, cookieValue(setCookie).length(), setCookie);
        }
    }

    @Test
    void everyLoginDrawsAFreshBindingValue() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            String first = cookieValue(h.bindingSetCookie(h.dispatch("GET", "/oidc/login", null)));
            // A cookie the login request already presents is never reused.
            String second = cookieValue(h.bindingSetCookie(h.dispatch("GET", "/oidc/login",
                    new Cookie("__Host-axiam_oidc_bind", first))));
            assertTrue(!first.equals(second));
        }
    }

    @Test
    void loopbackHttpRedirectUriUsesTheFallbackNameWithoutSecure() throws Exception {
        for (String redirect : new String[] {
            "http://localhost:8080/oidc/callback", "http://127.0.0.1:3000/cb", "http://[::1]:3000/cb"}) {
            try (Harness h = new Harness(redirect)) {
                String setCookie = h.bindingSetCookie(h.dispatch("GET", "/oidc/login", null));
                assertTrue(setCookie.startsWith("axiam_oidc_bind="), redirect + " -> " + setCookie);
                assertFalse(setCookie.contains("Secure"), setCookie);
                assertTrue(setCookie.contains("HttpOnly") && setCookie.contains("SameSite=Lax"), setCookie);
            }
        }
    }

    @Test
    void plainHttpToANonLoopbackHostStillUsesTheHostPrefixedName() throws Exception {
        for (String redirect : new String[] {"http://app.example.com/cb", "http://localhost.evil.example/cb"}) {
            try (Harness h = new Harness(redirect)) {
                String setCookie = h.bindingSetCookie(h.dispatch("GET", "/oidc/login", null));
                assertTrue(setCookie.startsWith("__Host-axiam_oidc_bind="), redirect + " -> " + setCookie);
                assertTrue(setCookie.contains("Secure"), setCookie);
            }
        }
    }

    // --- callback: the binding -----------------------------------------------

    @Test
    void validStateWithNoBindingCookieIsTheUniform401AndNothingIsExchanged() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();

            MockHttpServletResponse response = h.callback(login.state, "code-1", null);

            assertEquals(401, response.getStatus());
            assertTrue(response.getContentAsString().contains(UNIFORM_401), response.getContentAsString());
            assertEquals(0, h.tokenRequests.get(), "the code must not be exchanged");
            assertEquals(0, h.successCalls.size(), "onSuccess must not run");
            assertCleared(h, response);

            // The state was consumed first: a retry with the right cookie is refused too.
            MockHttpServletResponse retry = h.callback(login.state, "code-1", login.cookie());
            assertEquals(401, retry.getStatus());
            assertEquals(0, h.tokenRequests.get());
        }
    }

    @Test
    void validStateWithAnotherLoginsCookieIsTheUniform401AndNothingIsExchanged() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login victim = h.login();
            Login attacker = h.login();

            MockHttpServletResponse response = h.callback(attacker.state, "code-1", victim.cookie());

            assertEquals(401, response.getStatus());
            assertTrue(response.getContentAsString().contains(UNIFORM_401));
            assertEquals(0, h.tokenRequests.get());
            assertEquals(0, h.successCalls.size());
            assertCleared(h, response);
        }
    }

    @Test
    void theCookieValueIsNotAcceptedUnderTheWrongName() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();
            MockHttpServletResponse response = h.callback(login.state, "code-1",
                    new Cookie("axiam_oidc_bind", login.value));
            assertEquals(401, response.getStatus());
            assertEquals(0, h.tokenRequests.get());
        }
    }

    @Test
    void entryWithNoBindingDigestIsRefusedWithoutAnExchange() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            // As an older glue or a pre-1.68 store would have written it.
            h.store.save(new OidcStateEntry("legacy-state", "nonce-x", Sensitive.of("verifier"), HTTPS_CALLBACK));

            MockHttpServletResponse response = h.callback("legacy-state", "code-1",
                    new Cookie("__Host-axiam_oidc_bind", "anything"));

            assertEquals(401, response.getStatus());
            assertEquals(0, h.tokenRequests.get());
            assertEquals(0, h.successCalls.size());
        }
    }

    @Test
    void matchingCookieCompletesTheLoginAndTheSuccessHookRuns() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();

            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

            assertEquals(200, response.getStatus(), response.getContentAsString());
            assertEquals(1, h.tokenRequests.get());
            assertEquals(1, h.successCalls.size());
            assertCleared(h, response);

            // Single-use: replaying the same callback is refused.
            MockHttpServletResponse replay = h.callback(login.state, "code-1", login.cookie());
            assertEquals(401, replay.getStatus());
            assertEquals(1, h.tokenRequests.get());
        }
    }

    @Test
    void everyOtherCallbackErrorClearsTheCookieToo() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            assertCleared(h, h.dispatch("GET", "/oidc/callback?error=access_denied", null));
            assertCleared(h, h.dispatch("GET", "/oidc/callback", null));
            assertCleared(h, h.dispatch("GET", "/oidc/callback?state=never&code=c", null));
        }
    }

    // --- C6: return_to ----------------------------------------------------------

    @Test
    void anUnsafeStoredReturnToIsNeverFollowed() throws Exception {
        for (String evil : new String[] {
            "https://evil.example/x", "//evil.example/x", "/\\evil.example", "/a\\b",
            "/a\r\nSet-Cookie: x=y", "/a\u0000b", "/a\u007fb", "javascript:alert(1)"}) {
            try (Harness h = new Harness(HTTPS_CALLBACK)) {
                Login login = h.login();
                h.replaceReturnTo(login, evil);

                MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

                assertEquals(200, response.getStatus(), "falls back to the JSON summary for " + evil);
                assertNull(response.getHeader("Location"), evil);
            }
        }
    }

    @Test
    void aSafeStoredReturnToIsFollowed() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();
            h.replaceReturnTo(login, "/dashboard?tab=1");

            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

            assertEquals(302, response.getStatus());
            assertEquals("/dashboard?tab=1", response.getHeader("Location"));
        }
    }

    @Test
    void theEntryHoldsTheSha256OfTheCookieValueAndNotTheValue() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();
            OidcStateEntry entry = h.store.consume(login.state);
            assertNotNull(entry);
            String expected = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(login.value.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
            assertEquals(expected, entry.bindingDigest());
            assertFalse(entry.toString().contains(login.value), "the cookie value must never be stored");
        }
    }

    @Test
    void theSuccessHookReceivesTheRequestAndTheConsumedEntry() throws Exception {
        List<String> seen = new ArrayList<>();
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> o.withSuccessHandler(
                (tokens, entry, request) -> seen.add(request.path() + "|" + entry.state() + "|"
                        + tokens.idClaims().sub())))) {
            Login login = h.login();

            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

            assertEquals(200, response.getStatus(), response.getContentAsString());
            assertEquals(List.of("/oidc/callback|" + login.state + "|user-1"), seen);
        }
    }

    @Test
    void theSuccessHookDoesNotRunWhenTheBindingFails() throws Exception {
        List<String> seen = new ArrayList<>();
        try (Harness h = new Harness(HTTPS_CALLBACK,
                o -> o.withSuccessHandler((tokens, entry, request) -> seen.add("ran")))) {
            Login login = h.login();
            assertEquals(401, h.callback(login.state, "code-1", null).getStatus());
            assertEquals(List.of(), seen);
        }
    }

    // --- C6 at login, and the integrator predicate ---------------------------------

    @Test
    void loginStoresASafeReturnToAndDropsAnUnsafeOne() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            for (String[] c : new String[][] {
                {"/dashboard?tab=1", "/dashboard?tab=1"},
                {"https://evil.example/x", null},
                {"//evil.example/x", null},
                {"/\\evil.example", null},
                {"/a\\b", null}}) {
                MockHttpServletResponse response = h.dispatch("GET", "/oidc/login?returnTo="
                        + java.net.URLEncoder.encode(c[0], "UTF-8"), null);
                String state = null;
                for (String pair : URI.create(response.getHeader("Location")).getRawQuery().split("&")) {
                    if (pair.startsWith("state=")) {
                        state = pair.substring(6);
                    }
                }
                OidcStateEntry entry = h.store.consume(state);
                assertNotNull(entry);
                assertEquals(c[1], entry.returnTo(), c[0]);
            }
        }
    }

    @Test
    void anIntegratorPredicateWidensTheRuleOnlyForWhatItAccepts() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK,
                o -> o.withAllowReturnTo(v -> v.startsWith("https://app.example/")))) {
            Login ok = h.login();
            h.replaceReturnTo(ok, "https://app.example/x");
            assertEquals("https://app.example/x", h.callback(ok.state, "code-1", ok.cookie()).getHeader("Location"));

            Login evil = h.login();
            h.replaceReturnTo(evil, "https://evil.example/x");
            MockHttpServletResponse refused = h.callback(evil.state, "code-1", evil.cookie());
            assertEquals(200, refused.getStatus());
            assertNull(refused.getHeader("Location"));
        }
    }

    @Test
    void aPredicateThatThrowsAcceptsNothing() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> o.withAllowReturnTo(v -> {
            throw new IllegalStateException("boom");
        }))) {
            Login login = h.login();
            h.replaceReturnTo(login, "https://evil.example/x");
            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());
            assertEquals(200, response.getStatus());
            assertNull(response.getHeader("Location"));
        }
    }

    @Test
    void theConfiguredSuccessRedirectStillWinsOverAValidReturnTo() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> new AxiamOidcLoginRoutes.Options(o.loginPath(),
                o.callbackPath(), o.redirectUri(), null, "/home", o.onSuccess()))) {
            Login login = h.login();
            h.replaceReturnTo(login, "/dashboard");
            assertEquals("/home", h.callback(login.state, "code-1", login.cookie()).getHeader("Location"));
        }
    }

    // --- JAV-R1-2 / GLUE-R1-1 and Decision 7: the Location header is the encoded form ---------

    @Test
    void aStoredReturnToJavaNetUriRefusesIsFollowedAsItsPercentEncodedForm() throws Exception {
        // java.net.URI rejects each of these; isSafeReturnTo accepts them (no backslash, no control
        // character). Decision 7: the adapter writes the percent-encoded form, pure ASCII; existing %XX
        // kept, any other % becomes %25. The user is signed in and is never given a 500.
        String[][] cases = {
            {"/a b", "/a%20b"},
            {"/%", "/%25"},
            {"/a%20b", "/a%20b"},
            {"/caf\u00e9", "/caf%C3%A9"},
            {"/\u20ac", "/%E2%82%AC"},
            {"/a|b\"c", "/a|b%22c"},
            {"/a\ud800b", "/a%EF%BF%BDb"},
            {"/dashboard?tab=1&x=a b#frag", "/dashboard?tab=1&x=a%20b#frag"}};
        for (String[] c : cases) {
            try (Harness h = new Harness(HTTPS_CALLBACK)) {
                Login login = h.login();
                h.replaceReturnTo(login, c[0]);

                MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

                assertEquals(302, response.getStatus(), c[0]);
                assertEquals(c[1], response.getHeader("Location"), c[0]);
                assertCleared(h, response);
                assertEquals(1, h.successCalls.size(), "onSuccess runs once for " + c[0]);
                for (char ch : response.getHeader("Location").toCharArray()) {
                    assertTrue(ch > 0x20 && ch < 0x7F, "Location must be visible ASCII: " + c[1]);
                }
            }
        }
    }

    @Test
    void aCrLfDestinationAdmittedByThePredicateNeverReachesTheHeader() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> o.withAllowReturnTo(v -> v.startsWith("/a\r\n")))) {
            Login login = h.login();
            h.replaceReturnTo(login, "/a\r\nSet-Cookie: x=y");

            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

            assertEquals(302, response.getStatus());
            assertEquals("/a%0D%0ASet-Cookie:%20x=y", response.getHeader("Location"));
            assertEquals(null, response.getHeader("X"), "no injected header");
            for (String header : response.getHeaders("Set-Cookie")) {
                assertFalse(header.startsWith("x=y"), header);
            }
            assertCleared(h, response);
        }
    }

    @Test
    void aConfiguredSuccessRedirectIsEncodedToo() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> new AxiamOidcLoginRoutes.Options(o.loginPath(),
                o.callbackPath(), o.redirectUri(), null, "/h\u00f4me page", o.onSuccess()))) {
            Login login = h.login();
            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());
            assertEquals(302, response.getStatus());
            assertEquals("/h%C3%B4me%20page", response.getHeader("Location"));
            assertCleared(h, response);
        }
    }

    @Test
    void aLoginWithAReturnToThatHasASpaceSignsInAndLandsOnTheEncodedPath() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            MockHttpServletResponse loginResponse = h.dispatch("GET", "/oidc/login?returnTo=%2Fa%20b", null);
            String state = null;
            for (String pair : URI.create(loginResponse.getHeader("Location")).getRawQuery().split("&")) {
                if (pair.startsWith("state=")) {
                    state = pair.substring(6);
                } else if (pair.startsWith("nonce=")) {
                    h.nonce.set(pair.substring(6));
                }
            }
            String setCookie = h.bindingSetCookie(loginResponse);
            Cookie cookie = new Cookie(setCookie.substring(0, setCookie.indexOf('=')), cookieValue(setCookie));

            MockHttpServletResponse response = h.callback(state, "code-1", cookie);

            assertEquals(302, response.getStatus());
            assertEquals("/a%20b", response.getHeader("Location"));
            assertCleared(h, response);
        }
    }

    // --- GLUE-R1-4, GLUE-R1-5, N4 -----------------------------------------------------

    @Test
    void aRefusalWithAnotherBrowsersCookieConsumesTheState() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login victim = h.login();
            Login attacker = h.login();

            assertEquals(401, h.callback(attacker.state, "code-1", victim.cookie()).getStatus());

            // GLUE-R1-4: the entry was consumed by the refused callback, so the rightful cookie
            // cannot retry it either, and nothing was exchanged.
            MockHttpServletResponse retry = h.callback(attacker.state, "code-1", attacker.cookie());
            assertEquals(401, retry.getStatus());
            assertTrue(retry.getContentAsString().contains(UNIFORM_401));
            assertEquals(0, h.tokenRequests.get());
            assertNull(h.store.consume(attacker.state));
        }
    }

    @Test
    void aSuccessHookThatThrowsStillClearsTheCookie() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> new AxiamOidcLoginRoutes.Options(o.loginPath(),
                o.callbackPath(), o.redirectUri(), null, null, t -> {
                    throw new IllegalStateException("application hook failed");
                }))) {
            Login login = h.login();

            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());

            assertEquals(500, response.getStatus());
            assertCleared(h, response);
            assertFalse(response.getContentAsString().contains("application hook failed"),
                    "the failure text of an application hook is not echoed to the browser");
        }
    }

    @Test
    void aRequestAwareSuccessHookThatThrowsStillClearsTheCookie() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> o.withSuccessHandler((tokens, entry, request) -> {
            throw new IllegalStateException("application hook failed");
        }))) {
            Login login = h.login();
            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());
            assertEquals(500, response.getStatus());
            assertCleared(h, response);
        }
    }

    @Test
    void aStoreThatThrowsOnConsumeStillClearsTheCookie() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();
            io.axiam.sdk.oidc.OidcStateStore broken = new io.axiam.sdk.oidc.OidcStateStore() {
                @Override
                public void save(OidcStateEntry entry) {
                    h.store.save(entry);
                }

                @Override
                public OidcStateEntry consume(String state) {
                    throw new IllegalStateException("store down");
                }
            };
            RouterFunction<ServerResponse> brokenRoutes = AxiamOidcLoginRoutes.routes(h.client, broken,
                    new AxiamOidcLoginRoutes.Options("/oidc/login", "/oidc/callback", HTTPS_CALLBACK));
            MockHttpServletResponse response = h.dispatchOn(brokenRoutes, "GET",
                    "/oidc/callback?state=" + login.state + "&code=c", login.cookie());
            assertEquals(500, response.getStatus());
            assertCleared(h, response);
        }
    }

    @Test
    void aPredicateThatThrowsAnErrorAcceptsNothing() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK, o -> o.withAllowReturnTo(v -> {
            throw new AssertionError("boom");
        }))) {
            Login login = h.login();
            h.replaceReturnTo(login, "https://evil.example/x");
            MockHttpServletResponse response = h.callback(login.state, "code-1", login.cookie());
            assertEquals(200, response.getStatus());
            assertNull(response.getHeader("Location"));
        }
    }

    @Test
    void theStateEntryToStringKeepsTheBindingDigestOut() throws Exception {
        try (Harness h = new Harness(HTTPS_CALLBACK)) {
            Login login = h.login();
            OidcStateEntry entry = h.store.consume(login.state);
            assertNotNull(entry);
            assertFalse(entry.toString().contains(entry.bindingDigest()), entry.toString());
        }
    }

    // --- helpers -----------------------------------------------------------------

    private static void assertCleared(Harness h, MockHttpServletResponse response) {
        String cleared = h.bindingSetCookie(response);
        assertTrue(cleared.contains("Max-Age=0"), cleared);
        assertEquals("", cookieValue(cleared), cleared);
    }

    private static String cookieValue(String setCookie) {
        String pair = setCookie.substring(0, setCookie.indexOf(';') < 0 ? setCookie.length() : setCookie.indexOf(';'));
        return pair.substring(pair.indexOf('=') + 1);
    }

    private record Login(String state, String nonce, String name, String value) {
        Cookie cookie() {
            return new Cookie(name, value);
        }
    }

    /** One mock AXIAM, one client, one store, one route pair. */
    private static final class Harness implements AutoCloseable {
        final MockWebServer server = new MockWebServer();
        final AtomicInteger tokenRequests = new AtomicInteger();
        final AtomicReference<String> nonce = new AtomicReference<>("none");
        final List<OidcTokenSet> successCalls = new ArrayList<>();
        final MemoryOidcStateStore store = new MemoryOidcStateStore();
        final AxiamClient client;
        final RouterFunction<ServerResponse> routes;
        final String redirectUri;
        final OctetKeyPair key;
        final String base;

        Harness(String redirectUri) throws Exception {
            this(redirectUri, o -> o);
        }

        Harness(String redirectUri, java.util.function.UnaryOperator<AxiamOidcLoginRoutes.Options> customize)
                throws Exception {
            this.redirectUri = redirectUri;
            this.key = OidcTestSupport.generateEd25519KeyPair("key-1");
            server.start();
            this.base = server.url("/").toString();
            String trimmed = base.substring(0, base.length() - 1);
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    String path = request.getPath();
                    if (path.contains("jwks")) {
                        return OidcTestSupport.jwksResponse(key.toPublicJWK());
                    }
                    if (path.contains("/oauth2/token")) {
                        tokenRequests.incrementAndGet();
                        try {
                            String idToken = OidcTestSupport.signEdDsa(key,
                                    OidcTestSupport.validIdTokenClaims(trimmed, "my-app", nonce.get()));
                            return OidcTestSupport.tokenResponse("access-1", null, idToken);
                        } catch (Exception e) {
                            throw new IllegalStateException(e);
                        }
                    }
                    return OidcTestSupport.discoveryResponse(base);
                }
            });
            this.client = AxiamClient.builder(base, TENANT).oidcClientId("my-app").build();
            this.routes = AxiamOidcLoginRoutes.routes(client, store, customize.apply(
                    new AxiamOidcLoginRoutes.Options(
                            "/oidc/login", "/oidc/callback", redirectUri, null, null, successCalls::add)));
        }

        /** Runs the login route and returns the state, nonce and binding cookie it issued. */
        Login login() throws Exception {
            MockHttpServletResponse response = dispatch("GET", "/oidc/login", null);
            assertEquals(302, response.getStatus());
            String query = URI.create(response.getHeader("Location")).getRawQuery();
            String state = null;
            String nonceValue = null;
            for (String pair : query.split("&")) {
                if (pair.startsWith("state=")) {
                    state = pair.substring("state=".length());
                } else if (pair.startsWith("nonce=")) {
                    nonceValue = pair.substring("nonce=".length());
                }
            }
            assertNotNull(state);
            assertNotNull(nonceValue);
            nonce.set(nonceValue);
            // Tolerant of a login that sets no cookie, so the callback tests assert on the callback's own
            // behaviour (the glue that sets none is pinned by the login-response tests above).
            String setCookie = bindingSetCookie(response);
            if (setCookie.isEmpty()) {
                return new Login(state, nonceValue, "__Host-axiam_oidc_bind", "no-cookie-was-issued");
            }
            String name = setCookie.substring(0, setCookie.indexOf('='));
            return new Login(state, nonceValue, name, cookieValue(setCookie));
        }

        MockHttpServletResponse callback(String state, String code, Cookie cookie) throws Exception {
            return dispatch("GET", "/oidc/callback?state=" + state + "&code=" + code, cookie);
        }

        /** Rewrites the parked entry's return_to, as a caller-supplied store or older glue might have left it. */
        void replaceReturnTo(Login login, String returnTo) {
            OidcStateEntry entry = store.consume(login.state);
            assertNotNull(entry);
            store.save(new OidcStateEntry(entry.state(), entry.nonce(), entry.codeVerifier(), entry.redirectUri(),
                    returnTo, entry.bindingDigest()));
        }

        /** The one {@code Set-Cookie} naming the binding cookie, or the empty string when there is none. */
        String bindingSetCookie(MockHttpServletResponse response) {
            for (String header : response.getHeaders("Set-Cookie")) {
                if (header.startsWith("__Host-axiam_oidc_bind=") || header.startsWith("axiam_oidc_bind=")) {
                    return header;
                }
            }
            return "";
        }

        MockHttpServletResponse dispatch(String method, String uri, Cookie cookie) throws Exception {
            return dispatchOn(routes, method, uri, cookie);
        }

        MockHttpServletResponse dispatchOn(RouterFunction<ServerResponse> routes, String method, String uri,
                Cookie cookie) throws Exception {
            String path = uri.contains("?") ? uri.substring(0, uri.indexOf('?')) : uri;
            MockHttpServletRequest request = new MockHttpServletRequest(method, path);
            if (uri.contains("?")) {
                request.setQueryString(uri.substring(uri.indexOf('?') + 1));
                for (String pair : uri.substring(uri.indexOf('?') + 1).split("&")) {
                    String[] kv = pair.split("=", 2);
                    request.addParameter(kv[0], java.net.URLDecoder.decode(kv.length > 1 ? kv[1] : "", "UTF-8"));
                }
            }
            if (cookie != null) {
                request.setCookies(cookie);
            }
            ServerRequest serverRequest = ServerRequest.create(request, CONVERTERS);
            HandlerFunction<ServerResponse> handler = routes.route(serverRequest).orElseThrow();
            ServerResponse serverResponse = handler.handle(serverRequest);
            MockHttpServletResponse response = new MockHttpServletResponse();
            serverResponse.writeTo(request, response, new ServerResponse.Context() {
                @Override
                public List<HttpMessageConverter<?>> messageConverters() {
                    return CONVERTERS;
                }
            });
            return response;
        }

        @Override
        public void close() throws Exception {
            client.close();
            server.close();
        }
    }
}
