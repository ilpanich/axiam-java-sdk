package io.axiam.sdk.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.axiam.sdk.internal.JwksVerifier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md §10.1 rule 8 — "subject of the decision" (SEC-085, §15.3.1).
 *
 * <p>Rules 1-7 ask whether the token is good. Rule 8 asks whether it is the
 * token the decision is even ABOUT. SEC-085 satisfied all seven and was still
 * an authentication bypass: the PHP guard routed a failed verification into a
 * second, successful one against the <em>application's own</em> session, so the
 * caller was admitted as the app's service account — in an IAM integration
 * typically far more privileged than the user whose request it replaced.
 *
 * <p>This filter is structurally safe from that shape: it is constructed with a
 * {@link JwksVerifier} and a configured tenant id, never a logged-in client, so
 * there is no second credential in scope to substitute. These tests pin that
 * property instead of assuming it — the guardrail §15.3.1 asks for — and they
 * fail if anyone ever threads a client or session into the filter's inputs.
 *
 * <p>Spring adds a wrinkle worth pinning separately: the filter writes to the
 * ambient {@link SecurityContextHolder}. A rejected caller must not merely be
 * refused a new authentication — it must not inherit one that was already
 * there, which is the servlet-container analogue of the SEC-085 substitution.
 */
class Rule8CallerCredentialTest {

    private static final String CONFIGURED_TENANT = "tenant-a";

    /** The identity an SEC-085-shaped fallback would silently admit callers as. */
    private static final String APP_PRINCIPAL = "app-service-account";

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aFailedCallerTokenIsRejectedAndNoIdentityIsAuthenticated() throws Exception {
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);

            // Correctly signed, right tenant, expired. It fails rule 2 and
            // nothing else, so the only way to admit it is to decide on some
            // other credential.
            String expired = signEdDsa(keyPair, claims(CONFIGURED_TENANT, "caller-1", -900_000));

            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + expired);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingChain chain = new RecordingChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "SECURITY: the guard admitted a caller whose token failed verification");
            assertNull(
                    SecurityContextHolder.getContext().getAuthentication(),
                    "no identity may be authenticated for a rejected caller");
            assertEquals(401, response.getStatus());
        }
    }

    @Test
    void aRejectedCallerDoesNotInheritAPreexistingAuthentication() throws Exception {
        // The Spring-shaped version of the SEC-085 bypass. If the filter simply
        // declines to authenticate rather than actively rejecting, a caller
        // presenting a bad token rides in on whatever the ambient
        // SecurityContext already held — which in a real deployment is often
        // the application's own service account.
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);

            // Prime the ambient context with the application's own identity, so
            // the substitution is genuinely available rather than absent for an
            // incidental reason.
            SecurityContextHolder.getContext().setAuthentication(new AppOwnAuthentication());
            assertEquals(
                    APP_PRINCIPAL,
                    SecurityContextHolder.getContext().getAuthentication().getName(),
                    "precondition: the ambient identity must really be present, "
                            + "otherwise this test cannot distinguish the safe shape from the vulnerable one");

            String expired = signEdDsa(keyPair, claims(CONFIGURED_TENANT, "caller-1", -900_000));
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + expired);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingChain chain = new RecordingChain();

            filter.doFilter(request, response, chain);

            assertFalse(chain.invoked, "the request must not reach the endpoint");
            assertEquals(401, response.getStatus());

            Authentication after = SecurityContextHolder.getContext().getAuthentication();
            if (after != null) {
                assertFalse(
                        APP_PRINCIPAL.equals(after.getName()),
                        "SECURITY: the rejected caller inherited the application's own identity ("
                                + APP_PRINCIPAL + ") — rule 8 violated");
            }
        }
    }

    @Test
    void theAuthenticatedIdentityIsAlwaysTheCallersOwn() throws Exception {
        // The positive half: a guard that preferred an ambient credential would
        // pass the negative tests above while still being wrong.
        OctetKeyPair keyPair = generateEd25519KeyPair("key-1");
        try (MockWebServer server = startJwksServer(keyPair)) {
            AxiamAuthenticationFilter filter = filterFor(server, CONFIGURED_TENANT);

            SecurityContextHolder.getContext().setAuthentication(new AppOwnAuthentication());

            String callerToken = signEdDsa(keyPair, claims(CONFIGURED_TENANT, "caller-1", 900_000));
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Bearer " + callerToken);
            MockHttpServletResponse response = new MockHttpServletResponse();
            RecordingChain chain = new RecordingChain();

            filter.doFilter(request, response, chain);

            assertTrue(chain.invoked, "a valid caller token must be admitted");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertEquals("caller-1", auth.getName(), "the authenticated identity must be the caller's");
            assertFalse(
                    APP_PRINCIPAL.equals(auth.getName()),
                    "SECURITY: the filter authenticated the application's own principal");
        }
    }

    @Test
    void theFilterConstructorExposesNoSecondCredential() {
        // The shape of the bug: PHP's guard could reach a stateful session
        // through the client it held. Keep the filter's dependency surface free
        // of anything like that, so the properties above cannot be quietly
        // undone by widening the constructor later.
        Constructor<?>[] ctors = AxiamAuthenticationFilter.class.getConstructors();
        assertEquals(1, ctors.length, "the filter must have exactly one public constructor");

        Class<?>[] params = ctors[0].getParameterTypes();
        assertEquals(2, params.length, "the filter takes a verifier and a configured tenant, nothing more");
        assertEquals(JwksVerifier.class, params[0]);
        assertEquals(String.class, params[1]);

        // And no field may hold something session-shaped, which would put a
        // second credential in reach even with a narrow constructor.
        for (Field f : AxiamAuthenticationFilter.class.getDeclaredFields()) {
            String type = f.getType().getSimpleName();
            for (String forbidden : new String[] {"AxiamClient", "Session", "TokenManager", "Credentials"}) {
                assertFalse(
                        type.contains(forbidden),
                        "field " + f.getName() + " is a " + type
                                + " — a second credential in the guard makes rule 8 violable");
            }
        }
    }

    // --- helpers ---------------------------------------------------------------

    /** Stands in for the application's own authenticated principal. */
    private static final class AppOwnAuthentication
            extends org.springframework.security.authentication.AbstractAuthenticationToken {
        AppOwnAuthentication() {
            super(java.util.List.of());
            setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return "";
        }

        @Override
        public Object getPrincipal() {
            return APP_PRINCIPAL;
        }

        @Override
        public String getName() {
            return APP_PRINCIPAL;
        }
    }

    private static final class RecordingChain implements FilterChain {
        private boolean invoked;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) {
            this.invoked = true;
        }
    }

    private static AxiamAuthenticationFilter filterFor(MockWebServer server, String configuredTenantId) {
        JwksVerifier verifier = new JwksVerifier(server.url("/").toString());
        return new AxiamAuthenticationFilter(verifier, configuredTenantId);
    }

    private static MockWebServer startJwksServer(OctetKeyPair keyPair) throws Exception {
        MockWebServer server = new MockWebServer();
        for (int i = 0; i < 6; i++) {
            server.enqueue(new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody(new JWKSet(keyPair.toPublicJWK()).toString()));
        }
        server.start();
        return server;
    }

    private static OctetKeyPair generateEd25519KeyPair(String kid) throws Exception {
        return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
    }

    private static JWTClaimsSet claims(String tenantId, String subject, long expiresInMillis) {
        return new JWTClaimsSet.Builder()
                .subject(subject)
                .claim("tenant_id", tenantId)
                .claim("scope", "documents:read")
                .expirationTime(new Date(System.currentTimeMillis() + expiresInMillis))
                .build();
    }

    private static String signEdDsa(OctetKeyPair keyPair, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(JOSEObjectType.JWT)
                .keyID(keyPair.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(keyPair));
        return jwt.serialize();
    }
}
