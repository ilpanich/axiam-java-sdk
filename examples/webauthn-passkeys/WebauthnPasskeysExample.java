package io.axiam.sdk.examples.webauthnpasskeys;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.webauthn.WebauthnChallenge;
import io.axiam.sdk.webauthn.WebauthnCredential;
import io.axiam.sdk.webauthn.WebauthnLoginResult;

/**
 * CONTRACT.md &sect;24 — WebAuthn / passkeys, from the JVM.
 *
 * <p><strong>The JVM has no authenticator.</strong> &sect;24.6b's linked-API
 * helper is deliberately absent from this SDK, and &sect;24.6b rule 2 forbids
 * emulating one in software: a "credential" held in process memory is not a
 * second factor. What this SDK ships is the relying-party half — the calls
 * that talk to AXIAM — plus &sect;24.6a's JSON bridge, which is the piece that
 * makes it fully usable from an Android app without a single platform class
 * reaching this artifact.
 *
 * <p>Three demonstrations:
 *
 * <ol>
 *   <li><strong>Enrolment</strong> — {@code webauthnRegisterStart} /
 *       {@code webauthnRegisterFinish}, with the authenticator step stubbed.
 *   <li><strong>Android</strong> — the same two calls, wired to Credential
 *       Manager. Shown as a documented snippet because it needs an Android
 *       runtime; the SDK side of it is exactly the code above.
 *   <li><strong>Sign-in</strong> — the discoverable ("passkey autofill")
 *       ceremony, which needs no username at all.
 * </ol>
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ORG=...
 * java WebauthnPasskeysExample.java}
 */
public final class WebauthnPasskeysExample {

    public static void main(String[] args) {
        String baseUrl = env("AXIAM_BASE_URL", "https://axiam.example.com");
        String tenant = env("AXIAM_TENANT", "acme");
        String org = env("AXIAM_ORG", "globex");

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenant).orgSlug(org).build()) {
            enrolAPasskey(client);
            signInWithADiscoverableCredential(client);
        }
        androidCredentialManager();
    }

    // ------------------------------------------------------------------
    // 1. Enrolment — requires a session (§24.1)
    // ------------------------------------------------------------------

    private static void enrolAPasskey(AxiamClient client) {
        System.out.println("== enrolling a passkey ==");
        try {
            client.login("alice@example.com", System.getenv("AXIAM_PASSWORD"));

            // The server chooses every option: the challenge, the RP id, the
            // algorithms, the attestation policy, whether a resident key is
            // required. This SDK defaults nothing and validates nothing —
            // §24.0 — because a client that "helpfully" filled in a missing
            // field would be overriding a policy decision it cannot see.
            WebauthnChallenge challenge = client.webauthnRegisterStart();
            System.out.println("  options: " + challenge.challenge());

            // Hand challenge.challenge() to the authenticator. On a browser
            // that is navigator.credentials.create(); on Android it is
            // CreatePublicKeyCredentialRequest (below). Here it is a stub.
            String authenticatorResponse = createCredentialSomehow();

            WebauthnCredential credential = client.webauthnRegisterFinish(
                    challenge.stateToken(), "Alice's laptop", authenticatorResponse);
            System.out.println("  enrolled: " + credential.name()
                    + " (" + credential.credentialType() + "), id " + credential.id());
        } catch (AuthzError e) {
            // §24.4 rule 1: a 403 here is the tenant's ATTESTATION POLICY
            // rejecting this particular authenticator, and the server's
            // message is the only place that says which one would be
            // accepted. Printing a generic "forbidden" strands the person
            // holding the key.
            System.out.println("  policy refused this authenticator: " + e.getMessage());
        } catch (AuthError e) {
            System.out.println("  not signed in — passkey enrolment needs a session: " + e.getMessage());
        } catch (RuntimeException e) {
            // §24.4 rule 2: a 503 from register/start means the tenant's
            // attestation policy needs FIDO metadata the server cannot reach.
            // That is a CONFIGURATION state, not a transient one — the SDK
            // does not retry it, and neither should this loop.
            System.out.println("  enrolment unavailable: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // 2. Android — the §24.6a JSON bridge
    // ------------------------------------------------------------------

    /**
     * Android's Credential Manager is a string-in / string-out API, which is
     * precisely why this artifact stays a plain JVM library with no AAR and no
     * Android dependency: {@code challenge.requestJson()} goes in,
     * {@code registrationResponseJson} comes back, and the SDK passes both
     * through byte-for-byte.
     *
     * <pre>{@code
     * // build.gradle.kts — the SDK is a plain JVM dependency
     * implementation("io.github.ilpanich:axiam-sdk:<version>")
     * implementation("androidx.credentials:credentials:1.3.0")
     * implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
     *
     * val challenge = client.webauthnRegisterStart()
     *
     * val response = CredentialManager.create(context).createCredential(
     *     context,
     *     CreatePublicKeyCredentialRequest(
     *         // Verbatim. Not re-serialized, not "normalized", not merged
     *         // with a local default — §24.0.
     *         requestJson = challenge.requestJson(),
     *     ),
     * ) as CreatePublicKeyCredentialResponse
     *
     * client.webauthnRegisterFinish(
     *     challenge.stateToken(),
     *     "Pixel 9",
     *     response.registrationResponseJson,   // verbatim again
     * )
     * }</pre>
     *
     * <p>Sign-in is the mirror image: {@code webauthnDiscoverableStart(null)},
     * {@code GetCredentialRequest(listOf(GetPublicKeyCredentialOption(
     * requestJson = challenge.requestJson())))}, then
     * {@code webauthnDiscoverableFinish(challenge.stateToken(),
     * credential.authenticationResponseJson)}.
     */
    private static void androidCredentialManager() {
        System.out.println("== Android: see this method's javadoc ==");
    }

    // ------------------------------------------------------------------
    // 3. Sign-in — the discoverable ceremony (§24.1)
    // ------------------------------------------------------------------

    private static void signInWithADiscoverableCredential(AxiamClient client) {
        System.out.println("== signing in with a passkey ==");
        try {
            // No username. The authenticator already knows which accounts it
            // holds for this RP, so the workspace — not the user — is what the
            // server needs, and it comes from the client's own configuration
            // when the argument is null.
            WebauthnChallenge challenge = client.webauthnDiscoverableStart(null);

            String assertion = getCredentialSomehow();

            WebauthnLoginResult result =
                    client.webauthnDiscoverableFinish(challenge.stateToken(), assertion);

            // As of contract 1.28 the server sets the session cookie triple on
            // this response as well, so the client is signed in for every
            // cookie-driven call that follows. Before that fix a completed
            // ceremony left the browser with no session at all.
            System.out.println("  signed in, session " + result.sessionId()
                    + " valid for " + result.expiresIn() + "s");
        } catch (AuthError e) {
            System.out.println("  the assertion did not verify: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------

    /** Stands in for {@code navigator.credentials.create()}. */
    private static String createCredentialSomehow() {
        return """
                {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
                 "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                             "attestationObject":"o2NmbXRkbm9uZQ"},
                 "type":"public-key","clientExtensionResults":{}}""";
    }

    /** Stands in for {@code navigator.credentials.get()}. */
    private static String getCredentialSomehow() {
        return """
                {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
                 "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                             "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                             "userHandle":"dXNlci1oYW5kbGU"},
                 "type":"public-key","clientExtensionResults":{}}""";
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private WebauthnPasskeysExample() {
    }
}
