package io.axiam.sdk;

import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.oidc.VerifiedLogoutToken;
import io.axiam.sdk.testutil.OidcTestSupport;
import io.axiam.sdk.testutil.TestCerts;
import io.axiam.sdk.testutil.TestCerts.Identity;

import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * CONTRACT.md &sect;6: {@code customCa} is the sanctioned private-CA mechanism, so the JWKS fetch behind local
 * verification has to honour it exactly as REST and gRPC do. The JWKS here is served over HTTPS by a certificate
 * that ONLY the {@code customCa} trusts; the fetch must succeed through that CA and nothing else is relaxed.
 */
class AxiamClientJwksCustomCaTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String CLIENT_ID = "my-app";
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

    @TempDir
    Path tempDir;

    @Test
    void theJwksFetchTrustsTheClientsCustomCa() throws Exception {
        Identity server = TestCerts.selfSignedIdentity(tempDir, "localhost-jwks-server");
        OctetKeyPair key = OidcTestSupport.generateEd25519KeyPair("logout-kid");
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(
                io.axiam.sdk.internal.TlsSupport.keyManagers(server.certPem(), server.keyPem()),
                null, new SecureRandom());

        try (MockWebServer mock = new MockWebServer()) {
            mock.useHttps(serverContext.getSocketFactory(), false);
            String base = "https://127.0.0.1:" + mock.getPort() + "/";
            mock.enqueue(OidcTestSupport.discoveryResponse(base));
            mock.enqueue(OidcTestSupport.jwksResponse(key.toPublicJWK()));
            mock.start();

            String issuer = base.substring(0, base.length() - 1);
            long now = System.currentTimeMillis() / 1000L;
            String token = OidcTestSupport.signEdDsa(key, new JWTClaimsSet.Builder()
                    .issuer(issuer).audience(CLIENT_ID).subject("user-1").jwtID("jti-1")
                    .issueTime(new Date(now * 1000L)).expirationTime(new Date((now + 120) * 1000L))
                    .claim("sid", "session-abc").claim("events", Map.of(EVENT, Map.of())).build());

            try (AxiamClient c = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId(CLIENT_ID).customCa(server.certPem()).build()) {
                VerifiedLogoutToken verified = c.verifyLogoutToken(token, null);
                assertEquals("session-abc", verified.sid());
            }
        }
    }
}
