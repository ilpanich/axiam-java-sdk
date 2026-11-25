package io.axiam.sdk.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.annotations.AxiamRequireRole;
import io.axiam.sdk.annotations.AxiamRequireScope;
import io.axiam.sdk.internal.JwksVerifier;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * CONTRACT.md &sect;11.2 rule 11 (contract 1.68; N15, D-1): {@code @AxiamRequireRole} reads only
 * the {@code roles} claim and fails closed when it is absent. The whole chain runs: a signed token
 * goes through {@link AxiamAuthenticationFilter} and then {@link AxiamAuthorizationInterceptor}
 * over MockMvc, so the Spring authorities the filter builds are what the guard decides on.
 */
class AxiamRequireRoleClaimTest {

    private static final String TENANT = "tenant-a";

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void scopeNamedLikeTheRoleWithNoRolesClaimIsForbidden() throws Exception {
        // The N15 bypass: a roleless user whose token carries scope "openid admin".
        assertStatus(claims().claim("scope", "openid admin"), "/adminonly", 403);
    }

    @Test
    void rolesClaimHoldingTheRoleIsAllowedWhateverTheScope() throws Exception {
        assertStatus(claims().claim("scope", "openid").claim("roles", List.of("admin")), "/adminonly", 200);
    }

    @Test
    void emptyRolesArrayIsForbidden() throws Exception {
        assertStatus(claims().claim("scope", "openid").claim("roles", List.of()), "/adminonly", 403);
    }

    @Test
    void rolesAreMatchedCaseSensitively() throws Exception {
        assertStatus(claims().claim("scope", "openid").claim("roles", List.of("Admin")), "/adminonly", 403);
    }

    @Test
    void rolesClaimThatIsAStringNotAnArrayIsForbidden() throws Exception {
        assertStatus(claims().claim("scope", "openid").claim("roles", "admin"), "/adminonly", 403);
    }

    @Test
    void rolesArrayWithANonStringEntryIsForbidden() throws Exception {
        assertStatus(claims().claim("scope", "openid").claim("roles", List.of("admin", 7)), "/adminonly", 403);
    }

    @Test
    void aScopeNamedRoleUnderscoreAdminCannotSatisfyTheRoleGuard() throws Exception {
        // Spring's hasRole("admin") reads ROLE_admin; a scope must not be able to mint that entry.
        assertStatus(claims().claim("scope", "openid ROLE_admin"), "/adminonly", 403);
    }

    @Test
    void springAuthoritiesCarryRolesAsRoleEntriesAndScopesUnderScopePrefix() throws Exception {
        OctetKeyPair key = new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-1").generate();
        try (MockWebServer server = jwks(key)) {
            AxiamAuthenticationFilter filter =
                    new AxiamAuthenticationFilter(new JwksVerifier(server.url("/").toString()), TENANT);
            String token = sign(key, claims().claim("scope", "openid ROLE_root").claim("roles", List.of("admin")));
            org.springframework.mock.web.MockHttpServletRequest request =
                    new org.springframework.mock.web.MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + token);
            filter.doFilter(request, new org.springframework.mock.web.MockHttpServletResponse(),
                    (req, res) -> { });

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            List<String> names = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
            assertTrue(names.contains("ROLE_admin"), names.toString());
            assertTrue(names.contains("SCOPE_openid"), names.toString());
            assertTrue(names.contains("SCOPE_ROLE_root"), names.toString());
            assertFalse(names.contains("ROLE_root"), "a scope must never become a role entry: " + names);
            assertFalse(names.contains("openid"), "scopes are no longer verbatim authorities: " + names);
        }
    }

    // --- require_scope (CONTRACT.md §11.2 rule 11 (d), (g)) -----------------

    @Test
    void requireScopePassesWhenTheScopeClaimContainsTheScope() throws Exception {
        assertStatus(claims().claim("scope", "openid admin"), "/scopeadmin", 200);
    }

    @Test
    void requireScopeIsNotSatisfiedByTheRolesClaim() throws Exception {
        assertStatus(claims().claim("scope", "openid").claim("roles", List.of("admin")), "/scopeadmin", 403);
    }

    @Test
    void requireScopeWithNoScopeClaimIsForbidden() throws Exception {
        assertStatus(claims().claim("roles", List.of("admin")), "/scopeadmin", 403);
    }

    @Test
    void requireScopeMatchesWholeEntriesNotSubstrings() throws Exception {
        assertStatus(claims().claim("scope", "administrator"), "/scopeadmin", 403);
    }

    @Test
    void requireScopeIsCaseSensitive() throws Exception {
        assertStatus(claims().claim("scope", "Admin"), "/scopeadmin", 403);
    }

    @Test
    void requireScopeWithAScopeClaimThatIsNotAStringIsForbidden() throws Exception {
        assertStatus(claims().claim("scope", List.of("admin")), "/scopeadmin", 403);
    }

    @Test
    void requireScopeWithNoIdentityIs401() throws Exception {
        try (MockWebServer axiam = new MockWebServer();
                AxiamClient client = AxiamClient.builder(axiam.url("/").toString(), "acme").build()) {
            MockMvcBuilders.standaloneSetup(new Controller())
                    .addInterceptors(new AxiamAuthorizationInterceptor(client))
                    .build()
                    .perform(get("/scopeadmin"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void authenticationExposesAbsentAndEmptyRolesAsDifferentThings() throws Exception {
        OctetKeyPair key = new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-1").generate();
        try (MockWebServer server = jwks(key)) {
            AxiamAuthenticationFilter filter =
                    new AxiamAuthenticationFilter(new JwksVerifier(server.url("/").toString()), TENANT);
            for (Object[] c : new Object[][] {
                {null, null}, {List.of(), List.of()}, {List.of("a", "b"), List.of("a", "b")}, {"admin", null}}) {
                ClaimsBuilder cb = claims();
                if (c[0] != null) {
                    cb.claim("roles", c[0]);
                }
                SecurityContextHolder.clearContext();
                org.springframework.mock.web.MockHttpServletRequest request =
                        new org.springframework.mock.web.MockHttpServletRequest();
                request.addHeader("Authorization", "Bearer " + sign(key, cb));
                filter.doFilter(request, new org.springframework.mock.web.MockHttpServletResponse(),
                        (req, res) -> { });
                AxiamAuthentication auth = (AxiamAuthentication)
                        SecurityContextHolder.getContext().getAuthentication();
                org.junit.jupiter.api.Assertions.assertEquals(c[1], auth.roles(), String.valueOf(c[0]));
            }
        }
    }

    // --- harness -----------------------------------------------------------

    private static void assertStatus(Map<String, Object> claims, String path, int expected) throws Exception {
        OctetKeyPair key = new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-1").generate();
        try (MockWebServer server = jwks(key);
                MockWebServer axiam = new MockWebServer();
                AxiamClient client = AxiamClient.builder(axiam.url("/").toString(), "acme").build()) {
            AxiamAuthenticationFilter filter =
                    new AxiamAuthenticationFilter(new JwksVerifier(server.url("/").toString()), TENANT);
            MockMvc mvc = MockMvcBuilders.standaloneSetup(new Controller())
                    .addFilters(filter)
                    .addInterceptors(new AxiamAuthorizationInterceptor(client))
                    .build();
            mvc.perform(get(path).header("Authorization", "Bearer " + sign(key, claims)))
                    .andExpect(status().is(expected));
        }
    }

    private static void assertStatus(ClaimsBuilder claims, String path, int expected) throws Exception {
        assertStatus(claims.map, path, expected);
    }

    /** Tiny fluent claim map; JWTClaimsSet.Builder would coerce the wrong-typed claims these tests need. */
    private static final class ClaimsBuilder {
        final Map<String, Object> map = new LinkedHashMap<>();

        ClaimsBuilder claim(String name, Object value) {
            map.put(name, value);
            return this;
        }
    }

    private static ClaimsBuilder claims() {
        return new ClaimsBuilder()
                .claim("sub", "user-1")
                .claim("tenant_id", TENANT)
                .claim("exp", System.currentTimeMillis() / 1000 + 900);
    }

    private static String sign(OctetKeyPair key, ClaimsBuilder claims) throws Exception {
        return sign(key, claims.map);
    }

    private static String sign(OctetKeyPair key, Map<String, Object> claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("at+jwt"))
                .keyID(key.getKeyID())
                .build();
        JWSObject jws = new JWSObject(header, new Payload(claims));
        jws.sign(new Ed25519Signer(key));
        return jws.serialize();
    }

    private static MockWebServer jwks(OctetKeyPair key) throws Exception {
        MockWebServer server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(List.of(key.toPublicJWK())).toString());
            }
        });
        server.start();
        return server;
    }

    @RestController
    static class Controller {
        @AxiamRequireRole({"admin"})
        @GetMapping("/adminonly")
        String adminOnly() {
            return "admin";
        }

        @AxiamRequireScope({"admin"})
        @GetMapping("/scopeadmin")
        String scopeAdmin() {
            return "scope-admin";
        }
    }
}
