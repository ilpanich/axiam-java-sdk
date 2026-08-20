package io.axiam.sdk.examples.opaquelogin;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.LoginResult;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.opaque.OpaqueEnrollment;

import java.util.Arrays;

/**
 * Demonstrates the OPAQUE (RFC 9807) login path (CONTRACT.md &sect;23),
 * importing ONLY public SDK entry points.
 *
 * <p>OPAQUE proves the password to the server without the password — or
 * anything from which it can be cheaply recovered — ever crossing the wire.
 * What the server receives is a blinded group element and a MAC, neither
 * useful without the account's registration record <em>and</em> the tenant's
 * OPRF seed. So a TLS-terminating proxy, an accidentally verbose request log
 * or a heap dump cannot capture a plaintext password, and a stolen record
 * database is not offline-crackable on its own — the pre-computation
 * resistance the SRP-6a this replaces could not offer. It does
 * <strong>not</strong> protect against a compromised AXIAM server.
 *
 * <p>Four things this example is built to show:
 *
 * <ol>
 *   <li>{@link AxiamClient#opaqueAvailable()} is asked FIRST, and genuinely
 *       answers {@code false}: the protocol comes from
 *       {@code libaxiam_opaque_ffi} through JNA, and both are optional.</li>
 *   <li>{@link AxiamClient#loginOpaque} returns the SAME {@link LoginResult} as
 *       {@link AxiamClient#login}, MFA branch included, so the result handling
 *       below is identical to {@code examples/login-mfa}.</li>
 *   <li>A tenant with {@code opaque_mode: disabled} answers the start endpoint
 *       with {@code 404}, which reaches the caller as {@link NetworkError} and
 *       NOT as a credential failure — so falling back to {@code login()} is
 *       correct and safe. An {@link AuthError} is the opposite case and must
 *       NOT be retried that way.</li>
 *   <li>A tenant with {@code opaque_mode: required} answers {@code /auth/login}
 *       with {@code 403}, which is an {@link AuthzError}. A user whose password
 *       is perfectly good must never be shown "invalid username or
 *       password".</li>
 * </ol>
 *
 * <p>Illustrative and compilable; running it end-to-end requires a reachable
 * AXIAM server with OPAQUE enabled for the tenant, and the shared library on
 * {@code java.library.path} (or {@code AXIAM_OPAQUE_LIBRARY} pointing at it).
 */
public final class OpaqueLoginExample {

    private OpaqueLoginExample() {
    }

    /**
     * Runs the example.
     *
     * @param args unused; configuration comes from the environment
     */
    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenantId = getenv("AXIAM_TENANT_ID", "acme");
        String username = getenv("AXIAM_USERNAME", "alice");
        // A char[] rather than a String so it can be cleared. The SDK clears
        // every copy it makes; it cannot clear the caller's.
        char[] password = readPassword();

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenantId).build()) {
            LoginResult result;

            // Ask up front rather than discovering the gap mid-exchange. Unlike
            // the srpAvailable() this replaces — hard-coded true on the JVM —
            // this can really be false: net.java.dev.jna:jna is an optional
            // dependency, and the shared library is a per-platform release
            // asset rather than a Maven artifact.
            if (!client.opaqueAvailable()) {
                System.out.println("libaxiam_opaque_ffi is not installed — using password login");
                result = client.login(username, new String(password));
            } else {
                try {
                    // OPAQUE first, password second. The reverse order would
                    // mean a tenant running `opaque_mode: optional` never sees
                    // a single OPAQUE login — which is the mode operators run
                    // for the whole of a migration.
                    result = client.loginOpaque(username, password.clone());
                } catch (NetworkError e) {
                    if (!e.getMessage().contains("opaque_mode is disabled")) {
                        // A key-stretching function this build cannot perform,
                        // or a cost outside the accepted band. A configuration
                        // problem: falling back would hide it, and the
                        // plaintext would go to the server anyway.
                        throw e;
                    }
                    System.out.println("OPAQUE unavailable on this tenant (" + e.getMessage()
                            + ") — falling back to password login");
                    result = client.login(username, new String(password));
                } catch (AuthError e) {
                    // This covers BOTH halves of the mutual authentication: the
                    // envelope only opens under the right password, and KE2's
                    // MAC only verifies if the server actually holds the
                    // record. Do NOT retry over login(), which would hand the
                    // plaintext to an endpoint that just failed to prove it
                    // holds the record (§23.4 rule 7).
                    System.err.println("login failed: " + e.getMessage());
                    System.err.println("Not retrying with a password.");
                    return;
                } catch (AuthzError e) {
                    // opaque_mode: required, reached through login() elsewhere
                    // in an application. The credentials were never examined.
                    System.err.println("this tenant refuses password login: " + e.getMessage());
                    return;
                }
            }

            if (result.mfaRequired()) {
                // Identical to the non-OPAQUE path — that is the point of the
                // same-result-type requirement.
                String code = System.getenv("AXIAM_TOTP_CODE");
                if (code == null || code.isEmpty()) {
                    System.err.println("MFA required; set AXIAM_TOTP_CODE");
                    return;
                }
                result = client.verifyMfa(result.challengeToken(), code);
            }

            System.out.println("authenticated as " + result.user().userId());

            // Enrolment, for any request that SETS a password. The server
            // cannot build a registration record — it never sees the plaintext
            // — so it has to arrive with the request or not at all.
            //
            // Note what is NOT passed. No identity: a record binds to a
            // credential identifier the server chooses, so unlike the SRP
            // verifier this replaces there is no username/email confusion that
            // can produce a credential no login will ever satisfy. And no
            // group or KDF: those come from the register/start response, so a
            // caller cannot pick a cost the server will not honour.
            char[] newPassword = getenv("AXIAM_NEW_PASSWORD", "").toCharArray();
            if (newPassword.length > 0) {
                try {
                    OpaqueEnrollment enrolment = client.opaqueEnrollment(newPassword);
                    // Send this as the `opaque` member of the change-password
                    // body. Never log the record itself.
                    System.out.println("enrolment ready for session "
                            + enrolment.opaqueSession());
                } finally {
                    Arrays.fill(newPassword, '\0');
                }
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Reads the password without it ever becoming a {@code String}, where
     * available. {@code System.console()} is null under an IDE or a piped
     * stdin, so the environment is the documented fallback.
     */
    private static char[] readPassword() {
        java.io.Console console = System.console();
        if (console != null) {
            char[] typed = console.readPassword("password: ");
            if (typed != null && typed.length > 0) {
                return typed;
            }
        }
        return getenv("AXIAM_PASSWORD", "").toCharArray();
    }

    private static String getenv(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isEmpty() ? fallback : value;
    }
}
