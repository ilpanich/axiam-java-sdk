package io.axiam.example.springboot;

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

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.client.RestTestClient;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the complete application context and drives the CONTRACT.md &sect;11
 * declarative authorization path end-to-end: {@code GET /documents/{id}} is
 * guarded by {@link DocumentController}'s
 * {@link io.axiam.sdk.annotations.AxiamRequireAccess @AxiamRequireAccess}, which
 * the AXIAM auto-configuration enforces via
 * {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor} after
 * {@link io.axiam.sdk.spring.AxiamAuthenticationFilter} authenticates the
 * request.
 *
 * <p>A single {@link MockWebServer} plays the AXIAM server for BOTH the JWKS
 * fetch ({@code /oauth2/jwks}) and the authorization check
 * ({@code /api/v1/authz/check}); its {@link Dispatcher} routes by path and
 * allows only the {@link #ALLOWED_DOC} resource, so the same running context
 * exercises allow (200), deny (403), unauthenticated (401), and non-UUID
 * resource (400) outcomes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DocumentAuthorizationIT {

    private static final String CONFIGURED_TENANT = "example-tenant";
    private static final String ALLOWED_DOC = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private static final String DENIED_DOC = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    private static MockWebServer axiamServer;
    private static OctetKeyPair keyPair;

    @DynamicPropertySource
    static void axiamProperties(DynamicPropertyRegistry registry) throws Exception {
        keyPair = new OctetKeyPairGenerator(Curve.Ed25519).keyID("key-1").generate();
        axiamServer = new MockWebServer();
        axiamServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                String path = request.getPath() == null ? "" : request.getPath();
                if (path.startsWith("/oauth2/jwks")) {
                    return jwksResponse(keyPair.toPublicJWK());
                }
                if (path.startsWith("/api/v1/authz/check")) {
                    String body = request.getBody().readUtf8();
                    boolean allowed = body.contains("\"resource_id\":\"" + ALLOWED_DOC + "\"");
                    return new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody("{\"allowed\":" + allowed + "}");
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        axiamServer.start();

        registry.add("axiam.base-url", () -> axiamServer.url("/").toString());
        registry.add("axiam.tenant-id", () -> CONFIGURED_TENANT);
    }

    @AfterAll
    static void stopServer() throws Exception {
        axiamServer.close();
    }

    @LocalServerPort
    private int port;

    private RestTestClient client() {
        return RestTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    @Test
    void allowedDocumentReturns200() throws Exception {
        String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT));
        client().get().uri("/documents/{id}", ALLOWED_DOC)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).value(body -> assertThat(body).contains("user-1"));
    }

    @Test
    void deniedDocumentReturns403() throws Exception {
        String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT));
        client().get().uri("/documents/{id}", DENIED_DOC)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void unauthenticatedRequestReturns401() {
        client().get().uri("/documents/{id}", ALLOWED_DOC)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void nonUuidResourceReturns400() throws Exception {
        String token = signEdDsa(keyPair, claims(CONFIGURED_TENANT));
        client().get().uri("/documents/{id}", "not-a-uuid")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isBadRequest();
    }

    private static JWTClaimsSet claims(String tenantId) {
        return new JWTClaimsSet.Builder()
                .subject("user-1")
                .claim("tenant_id", tenantId)
                .claim("scope", "documents:read")
                .expirationTime(new Date(System.currentTimeMillis() + 900_000))
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

    private static MockResponse jwksResponse(OctetKeyPair publicKey) {
        String body = new JWKSet(List.of(publicKey)).toString();
        return new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
