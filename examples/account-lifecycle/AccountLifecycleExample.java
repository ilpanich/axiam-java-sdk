package io.axiam.sdk.examples.accountlifecycle;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.LoginResult;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.account.MfaEnrollment;
import io.axiam.sdk.account.PasswordResetConfirmation;
import io.axiam.sdk.account.PasswordResetContext;
import io.axiam.sdk.account.PasswordResetRequest;

import java.util.UUID;

/**
 * CONTRACT.md &sect;25 — account lifecycle and MFA enrolment: the calls a user
 * makes about their own account, none of which is administration.
 *
 * <p>Four demonstrations:
 *
 * <ol>
 *   <li><strong>Forced enrolment</strong> — the third {@code login} outcome.
 *       A tenant that requires MFA meets an account that has none, and the
 *       login is neither a success nor a failure.
 *   <li><strong>Voluntary enrolment</strong> — the same two calls from inside
 *       an existing session.
 *   <li><strong>Email verification</strong> — unauthenticated, because a user
 *       whose address is unverified may have no session at all.
 *   <li><strong>Password reset</strong> — including the &sect;23 detour that a
 *       tenant with OPAQUE enabled forces, and the enumeration guarantee that
 *       makes the first call return nothing useful on purpose.
 * </ol>
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_TENANT_ID=...
 * java AccountLifecycleExample.java}
 */
public final class AccountLifecycleExample {

    public static void main(String[] args) {
        String baseUrl = env("AXIAM_BASE_URL", "https://axiam.example.com");
        String tenant = env("AXIAM_TENANT", "acme");
        UUID tenantId = UUID.fromString(env("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000"));

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenant).orgSlug("globex").build()) {
            loginWithForcedEnrolment(client);
            enrolVoluntarily(client);
            verifyAnEmailAddress(client, tenantId);
            resetAPassword(client, tenantId);
        }
    }

    // ------------------------------------------------------------------
    // 1. The third login outcome (§25.2 rule 1)
    // ------------------------------------------------------------------

    private static void loginWithForcedEnrolment(AxiamClient client) {
        System.out.println("== login ==");
        LoginResult result = client.login("alice@example.com", System.getenv("AXIAM_PASSWORD"));

        if (result.mfaSetupRequired()) {
            // Not a failure. The tenant requires MFA, this account has none,
            // and the server handed back a setup token to finish with. There
            // is no session yet — the token IS the credential for the next
            // two calls.
            Sensitive setupToken = java.util.Objects.requireNonNull(result.setupToken());

            MfaEnrollment enrollment = client.mfaSetupEnroll(setupToken);
            System.out.println("  scan this: " + enrollment.totpUri().expose());

            // mfaSetupConfirm completes the LOGIN, not just the enrolment: it
            // adopts credentials exactly as login() does (§25.2 rule 2), so
            // there is nothing left for the caller to install.
            LoginResult completed = client.mfaSetupConfirm(setupToken, promptForCode());
            System.out.println("  signed in as " + completed.user());

        } else if (result.mfaRequired()) {
            // The account already HAS a factor — challenge it, don't enrol.
            client.verifyMfa(java.util.Objects.requireNonNull(result.challengeToken()), promptForCode());
            System.out.println("  signed in after an MFA challenge");

        } else {
            System.out.println("  signed in as " + result.user());
        }
    }

    // ------------------------------------------------------------------
    // 2. Voluntary enrolment (§25.1)
    // ------------------------------------------------------------------

    private static void enrolVoluntarily(AxiamClient client) {
        System.out.println("== enrolling TOTP from inside a session ==");
        MfaEnrollment enrollment = client.mfaEnroll();

        // Both halves are Sensitive, and the second one matters: the otpauth
        // URI CONTAINS the secret (§25.3). Wrapping the bare secret and then
        // printing the URI into a log leaks exactly the same bytes.
        System.out.println("  secret (redacted in toString): " + enrollment.secretBase32());
        renderQrCode(enrollment.totpUri().expose());

        if (client.mfaConfirm(promptForCode())) {
            System.out.println("  MFA is live on this account");
        }

        // Note what did NOT happen: the §17 decision memo was not cleared.
        // The subject has not changed, and discarding a warm memo on an
        // unrelated profile action costs a round trip on every check that
        // follows (§25.2 rule 3).
    }

    // ------------------------------------------------------------------
    // 3. Email verification (§25.1) — no session required
    // ------------------------------------------------------------------

    private static void verifyAnEmailAddress(AxiamClient client, UUID tenantId) {
        System.out.println("== verifying an email address ==");
        try {
            // The tenant is a BODY field here. §12.1 rule 2's ?tenant_id=
            // convention is scoped to /oauth2/*, and this is not one of those.
            client.verifyEmail(Sensitive.of(tokenFromTheVerificationMail()), tenantId);
            System.out.println("  verified");
        } catch (RuntimeException e) {
            System.out.println("  that link has expired — sending another");
            client.resendVerification("alice@example.com", tenantId);
        }
    }

    // ------------------------------------------------------------------
    // 4. Password reset (§25.4)
    // ------------------------------------------------------------------

    private static void resetAPassword(AxiamClient client, UUID tenantId) {
        System.out.println("== resetting a password ==");

        // Returns void, whether or not the address exists, and this SDK
        // exposes no way to tell the two apart. That is not an omission to
        // improve on: a client that surfaced a "no such user" state — even one
        // inferred from timing — would turn the endpoint into the account
        // enumeration oracle its uniform response exists to prevent.
        client.requestPasswordReset(new PasswordResetRequest("alice@example.com"));
        System.out.println("  if that address has an account, a mail is on its way");

        Sensitive token = Sensitive.of(tokenFromTheResetMail());

        // Ask the context BEFORE building anything. On a tenant with §23
        // enabled the client has to construct an OPAQUE registration record,
        // and building one needs parameters it cannot know before it has a
        // token to ask with. Sending a plaintext password to a tenant in
        // opaque_mode: required is refused, and refused late (§25.4 rule 1).
        try {
            PasswordResetContext context = client.passwordResetContext(token);

            if (context.opaque() != null) {
                System.out.println("  this tenant uses OPAQUE: " + context.opaque());
                // Build the record with the SDK's §23 helpers, then:
                //   client.confirmPasswordReset(new PasswordResetConfirmation(
                //           token, Sensitive.of(newPassword), tenantId, record));
            } else {
                client.confirmPasswordReset(new PasswordResetConfirmation(
                        token, Sensitive.of("a new correct horse battery staple"), tenantId));
                System.out.println("  password changed");
            }
        } catch (RuntimeException e) {
            // A 404 means unknown, expired OR already-consumed, deliberately
            // without distinguishing them (§25.4 rule 3). Neither does this.
            System.out.println("  that reset link is no longer usable");
        }
    }

    // ------------------------------------------------------------------

    private static String promptForCode() {
        return env("AXIAM_TOTP_CODE", "123456");
    }

    private static String tokenFromTheVerificationMail() {
        return env("AXIAM_VERIFY_TOKEN", "paste-the-token-from-the-mail");
    }

    private static String tokenFromTheResetMail() {
        return env("AXIAM_RESET_TOKEN", "paste-the-token-from-the-mail");
    }

    private static void renderQrCode(String otpauthUri) {
        System.out.println("  [QR code for " + otpauthUri.substring(0, 20) + "...]");
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private AccountLifecycleExample() {
    }
}
