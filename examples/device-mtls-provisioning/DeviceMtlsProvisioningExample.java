package io.axiam.sdk.examples.devicemtlsprovisioning;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.PageRequest;
import io.axiam.sdk.management.models.BindCertificate;
import io.axiam.sdk.management.models.CaCertificate;
import io.axiam.sdk.management.models.Certificate;
import io.axiam.sdk.management.models.CertificateStatus;
import io.axiam.sdk.management.models.CertificateType;
import io.axiam.sdk.management.models.CreateCertificateRequest;
import io.axiam.sdk.management.models.CreateServiceAccountRequest;
import io.axiam.sdk.management.models.GeneratedCertificate;
import io.axiam.sdk.management.models.KeyAlgorithm;
import io.axiam.sdk.management.models.ServiceAccountCreatedResponse;
import io.axiam.sdk.management.models.ServiceAccountResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.UUID;

/**
 * Provisions an IoT device with an mTLS identity, then lets the device
 * authenticate with it.
 *
 * <p>Two halves, and the split between them is the point.
 *
 * <p><strong>The operator half</strong> ({@code provision}) runs once, on a
 * machine an administrator controls, against an authenticated CONTRACT.md
 * &sect;27 management client. It creates the device's service account, mints a
 * Device certificate from the tenant's signing CA, binds the two, and writes the
 * private key to disk. That key is returned by exactly one call and never again
 * (&sect;27.5) — no later {@code get} has a field where it was — so losing the
 * response means revoking the certificate and minting another.
 *
 * <p><strong>The device half</strong> ({@code run}) runs on the device, forever
 * after, with no password and no management access at all. It presents the
 * certificate and key as a &sect;6.1 mutual-TLS identity and does nothing else
 * privileged.
 *
 * <p>Run:
 * <pre>{@code
 * AXIAM_BASE_URL=https://axiam.example.com \
 * AXIAM_TENANT=acme \
 * AXIAM_ADMIN=admin@example.com \
 * AXIAM_ADMIN_PASSWORD=... \
 *   java DeviceMtlsProvisioningExample.java provision sensor-42
 *
 *   java DeviceMtlsProvisioningExample.java run     sensor-42
 *   java DeviceMtlsProvisioningExample.java revoke  sensor-42
 * }</pre>
 */
public final class DeviceMtlsProvisioningExample {

    private static final String BASE_URL = getenv("AXIAM_BASE_URL", "https://localhost:8443");
    private static final String TENANT = getenv("AXIAM_TENANT", "acme");
    private static final String ADMIN = getenv("AXIAM_ADMIN", "admin@example.com");
    private static final String ADMIN_PASSWORD = getenv("AXIAM_ADMIN_PASSWORD", "");

    /** Where the device's certificate and private key are written, and read back. */
    private static final Path IDENTITY_DIR =
            Path.of(getenv("AXIAM_DEVICE_DIR", "./device-identity"));

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: provision|run|revoke <device-name>");
            System.exit(2);
            return;
        }
        String device = args[1];
        try {
            switch (args[0]) {
                case "provision" -> provision(device);
                case "run" -> run(device);
                case "revoke" -> revoke(device);
                default -> {
                    System.err.println("usage: provision|run|revoke <device-name>");
                    System.exit(2);
                }
            }
        } catch (ValidationError e) {
            // §27.4 rule 7: the server rejected the input, and said which parts.
            System.err.println("rejected: " + e.getMessage() + " " + e.fields());
            System.exit(1);
        }
    }

    /**
     * Creates the device's identity and writes it to disk, once.
     *
     * <p>Every step is a §27 management write, and §27.4 rule 8 does not retry
     * writes — generating a certificate twice mints two, and only one of them
     * ends up on the device.
     */
    private static void provision(String device) throws IOException {
        try (AxiamClient client = client()) {
            client.login(ADMIN, ADMIN_PASSWORD);

            // 1. The signing CA this tenant's device certificates chain to.
            //    {org_id} defaults from the client (§27.4 rule 3). {tenant_id}
            //    does NOT on this route: under caCertificates it names the
            //    tenant being administered rather than the calling context, so
            //    it is an ordinary argument — which is what resolvedTenantId()
            //    is public for.
            UUID tenantId = client.resolvedTenantId().orElseThrow(() -> new IllegalStateException(
                    "login did not resolve a tenant UUID; cannot address signing CAs"));
            CaCertificate issuer = client.management().caCertificates()
                    .listSigningCasAll(tenantId, PageRequest.of(100)).stream()
                    .filter(ca -> ca.status() == CertificateStatus.ACTIVE)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("tenant '" + TENANT
                            + "' has no active signing CA; generate one with "
                            + "caCertificates().generateSigningCa(...) first"));

            // 2. The service account the device authenticates as.
            ServiceAccountCreatedResponse account;
            try {
                account = client.management().serviceAccounts()
                        .create(new CreateServiceAccountRequest(
                                "IoT device " + device + ", mTLS identity", device));
            } catch (ConflictError e) {
                // Already provisioned. Re-minting a certificate for an existing
                // account is a decision an operator should make deliberately,
                // so this stops rather than quietly issuing a second identity.
                throw new IllegalStateException("a service account named '" + device
                        + "' already exists; revoke its certificate and delete it first, "
                        + "or pick another name", e);
            }

            // 3. The certificate. privateKeyPem comes back from THIS call and no
            //    other — certificates().get() has no field where it was.
            GeneratedCertificate certificate = client.management().certificates()
                    .generate(new CreateCertificateRequest(
                            CertificateType.DEVICE,
                            issuer.id(),
                            KeyAlgorithm.ED25519,
                            null,
                            "CN=" + device + ",OU=devices,O=" + TENANT,
                            825));

            // 4. Write it down before doing anything else that could fail. The
            //    key is a Sensitive, so expose() is the one explicit unwrap
            //    (§27.5) — printing `certificate` anywhere shows [SENSITIVE].
            writeSecret(IDENTITY_DIR.resolve(device + "-key.pem"),
                    certificate.privateKeyPem().expose());
            Files.createDirectories(IDENTITY_DIR);
            Files.writeString(IDENTITY_DIR.resolve(device + "-cert.pem"),
                    certificate.publicCertPem()
                            + (certificate.chainPem() == null ? "" : certificate.chainPem()));

            // 5. Bind the certificate to the account, so presenting it
            //    authenticates as that principal.
            client.management().serviceAccounts()
                    .bindCertificate(account.id(), new BindCertificate(certificate.id()));

            System.out.println("provisioned " + device);
            System.out.println("  service account : " + account.id());
            System.out.println("  certificate     : " + certificate.id()
                    + " (" + certificate.fingerprint() + ")");
            System.out.println("  valid until     : " + certificate.notAfter());
            System.out.println("  identity written: " + IDENTITY_DIR + "/");
        }
    }

    /**
     * Authenticates as the device, with the identity provisioning wrote.
     *
     * <p>No password, no management surface, no secret in the environment — the
     * private key on disk <em>is</em> the credential. Presenting it never
     * relaxes server verification (§6.1 rule 2): strict TLS stays fully on.
     */
    private static void run(String device) throws IOException {
        Path cert = IDENTITY_DIR.resolve(device + "-cert.pem");
        Path key = IDENTITY_DIR.resolve(device + "-key.pem");
        if (!Files.exists(cert) || !Files.exists(key)) {
            throw new IllegalStateException("no identity for '" + device + "' in "
                    + IDENTITY_DIR + "/; provision it first");
        }
        try (AxiamClient device0 = AxiamClient.builder(BASE_URL, TENANT)
                .clientCertificate(Files.readAllBytes(cert), Files.readAllBytes(key))
                .build()) {
            System.out.println(device + " may publish telemetry: "
                    + device0.can("telemetry:publish", "device/" + device));
        }
    }

    /**
     * Revokes the device's certificate — the decommissioning path.
     *
     * <p>Deleting the service account alone leaves a valid certificate in the
     * field; revoking the certificate is what actually stops the device
     * authenticating.
     */
    private static void revoke(String device) {
        try (AxiamClient client = client()) {
            client.login(ADMIN, ADMIN_PASSWORD);

            List<ServiceAccountResponse> accounts = client.management().serviceAccounts()
                    .listAll(PageRequest.of(200)).stream()
                    .filter(a -> a.name().equals(device)).toList();
            if (accounts.isEmpty()) {
                throw new IllegalStateException("no service account named '" + device + "'");
            }

            for (Certificate certificate : client.management().certificates()
                    .listAll(PageRequest.of(200))) {
                if (!certificate.subject().startsWith("CN=" + device + ",")) {
                    continue;
                }
                try {
                    client.management().certificates().revoke(certificate.id());
                } catch (NotFoundError e) {
                    continue;
                }
                System.out.println("revoked " + certificate.id());
            }

            client.management().serviceAccounts().delete(accounts.get(0).id());
            System.out.println("deleted service account " + accounts.get(0).id());
        }
    }

    private static AxiamClient client() {
        return AxiamClient.builder(BASE_URL, TENANT).orgSlug(TENANT).build();
    }

    /**
     * Writes {@code content} readable only by this user.
     *
     * <p>The mode is set at creation rather than afterwards: a chmod after the
     * fact leaves a window in which the key is world-readable, which on a shared
     * provisioning host is the whole exposure.
     */
    private static void writeSecret(Path path, String content) throws IOException {
        Files.createDirectories(path.getParent());
        Files.deleteIfExists(path);
        try {
            Files.createFile(path, PosixFilePermissions
                    .asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            // Not a POSIX filesystem. Fall back to the closest thing available
            // rather than writing a key with default permissions silently.
            Files.createFile(path);
            path.toFile().setReadable(false, false);
            path.toFile().setReadable(true, true);
            path.toFile().setWritable(false, false);
            path.toFile().setWritable(true, true);
        }
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }

    private static String getenv(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private DeviceMtlsProvisioningExample() {
    }
}
