package io.axiam.sdk;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Rounds out {@link ActingTenantTest} with the branches it does not reach: closing a
 * REBOUND handle must not tear down the shared transport out from under the primary
 * (and every other rebound) handle, and {@code authenticateDeviceAsync()}.
 */
class ActingTenantCoverageTest {

    private static final String TENANT_ID = "acme";

    @Test
    void closingARoundHandleDoesNotShutDownTheSharedTransport() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/json").setBody("{\"allowed\":true}"));
            server.start();

            try (AxiamClient base = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                AxiamClient rebound = base.actingTenant(
                        UUID.fromString("55555555-5555-4555-8555-555555555555"));
                rebound.close();
                rebound.close(); // idempotent

                // base's shared httpClient must still work after a rebound handle closed.
                base.checkAccess("read", "documents/1");
                rebound.close(); // still a no-op
            }
            // The primary's own close() (the try-with-resources above) tears the
            // shared transport down; a call afterward would fail, which is not what
            // this test checks — one call already having succeeded above is.
            assertEquals(1, server.getRequestCount());
        }
    }

    @Test
    void authenticateDeviceAsyncAdoptsTheToken() throws Exception {
        java.nio.file.Path tempDir = java.nio.file.Files.createTempDirectory("device-async");
        try {
            var identity = io.axiam.sdk.testutil.TestCerts.selfSignedIdentity(tempDir, "async-device");
            try (MockWebServer server = new MockWebServer()) {
                server.enqueue(new MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"access_token\":\"async-token\",\"token_type\":\"Bearer\","
                                + "\"expires_in\":900}"));
                server.start();

                try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                        .clientCertificate(identity.certPem(), identity.keyPem())
                        .build()) {
                    DeviceToken token = client.authenticateDeviceAsync().get();
                    assertEquals("async-token", token.accessToken().expose());
                }
                RecordedRequest request = server.takeRequest();
                assertTrue(request.getPath().endsWith("/api/v1/auth/device"));
            }
        } finally {
            deleteRecursively(tempDir);
        }
    }

    private static void deleteRecursively(java.nio.file.Path path) throws Exception {
        if (!java.nio.file.Files.exists(path)) {
            return;
        }
        try (var stream = java.nio.file.Files.walk(path)) {
            stream.sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            java.nio.file.Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // best-effort cleanup
                        }
                    });
        }
    }
}
