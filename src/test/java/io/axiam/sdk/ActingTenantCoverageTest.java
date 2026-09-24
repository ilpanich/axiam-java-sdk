package io.axiam.sdk;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Rounds out {@link ActingTenantTest} with the branch it does not reach: closing a
 * REBOUND handle must not tear down the shared transport out from under the primary
 * (and every other rebound) handle.
 *
 * <p>{@code authenticateDeviceAsync()} coverage lives in {@link DeviceAuthTest} —
 * {@code authenticateDevice()} itself is a separate contract piece (&sect;6.1 rules
 * 6-10) from acting tenant (&sect;5.2 rule 1), added in a later commit than this
 * class, so a device-auth test does not belong here.
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
}
