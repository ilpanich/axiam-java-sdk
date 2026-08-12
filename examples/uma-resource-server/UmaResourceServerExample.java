package io.axiam.sdk.examples.umaresourceserver;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.annotations.AxiamRequireAccess;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.oidc.ResourceSet;
import io.axiam.sdk.spring.AxiamAuthorizationInterceptor;
import io.axiam.sdk.spring.UmaChallenger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * UMA 2.0 (CONTRACT.md &sect;20) &mdash; the <strong>resource-server</strong>
 * half of the pair.
 *
 * <p>The situation: this service holds invoices that belong to <em>users</em>,
 * not to itself. When someone asks for one, the useful answer is not just "no"
 * &mdash; it is "not with what you're carrying, and here is where to go and get
 * better". That actionable refusal is what UMA adds over plain RBAC.
 *
 * <p>What this shows, in order:
 *
 * <ol>
 *   <li>Mint a <strong>PAT</strong> &mdash; a client-credentials token carrying
 *       {@code uma_protection}. &sect;20.2 rule 1 requires a <em>client</em>
 *       token: a minted ticket is bound to the {@code client_id} that minted
 *       it, so a user token cannot stand in.</li>
 *   <li><strong>Register</strong> the resource this service guards. The
 *       returned id <em>is</em> the AXIAM resource id &mdash; there is no
 *       parallel resource store to keep in sync.</li>
 *   <li>Add a {@link UmaChallenger} to the &sect;11
 *       {@link AxiamAuthorizationInterceptor}, so a denial carries
 *       {@code WWW-Authenticate: UMA} with a fresh ticket.</li>
 * </ol>
 *
 * <p>Its counterpart is {@code examples/uma-client/UmaClientExample.java},
 * which consumes that header.
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_OIDC_CLIENT_ID=... AXIAM_OIDC_CLIENT_SECRET=... mvn spring-boot:run}
 * &mdash; {@code GET /invoices/{invoiceId}} is the guarded route.
 */
@SpringBootApplication
public class UmaResourceServerExample implements WebMvcConfigurer {

    private final AxiamClient client;
    private final UmaChallenger challenger;

    /** Builds the client, mints the PAT, registers the resource. */
    public UmaResourceServerExample() {
        this.client = AxiamClient.builder(
                        getenv("AXIAM_BASE_URL", "https://localhost:8443"),
                        getenv("AXIAM_TENANT_SLUG", "acme"))
                .oidcClientId(getenv("AXIAM_OIDC_CLIENT_ID", "invoices-resource-server"))
                .oidcClientSecret(getenv("AXIAM_OIDC_CLIENT_SECRET", "resource-server-secret"))
                .build();

        // ---- 1. The PAT ----
        //
        // §20.2 rule 1: a client-credentials token carrying `uma_protection`.
        // Not a user token, and not this client's ambient session — the SDK
        // will not substitute either, and the Protection API would refuse them.
        OidcTokenSet session = client.loginClientCredentials("uma_protection", null, null);
        Sensitive pat = session.accessToken();

        // ---- 2. Registration ----
        //
        // Registering the same name twice creates two resources, so a real
        // service registers once at provisioning time and stores the id, or
        // reconciles by listing. Inline here because it is the step that shows
        // the returned id is the AXIAM resource id.
        ResourceSet registered = client.umaRegisterResource(pat, ResourceSet.of(
                "invoice-7",
                "invoice",
                // The declared scopes are the allow-list the permission endpoint
                // validates a ticket request against. A resource registered with
                // none can never appear in a ticket.
                List.of("invoices:read", "invoices:approve")));
        System.out.println("registered invoice-7 as " + registered.id());
        System.out.println("try:  curl -i http://127.0.0.1:8081/invoices/" + registered.id());

        // ---- 3. The challenger ----
        //
        // `asUri` names where the caller should redeem the ticket. Read it from
        // the discovery document rather than assembling it by hand — a
        // deployment is free to move its endpoints, which is why §12.3 rule 6
        // forbids hardcoding them.
        OidcConfiguration configuration = client.oidcDiscover();
        this.challenger = new UmaChallenger("invoices", configuration.issuer(), pat, client);
    }

    /**
     * Registers the interceptor.
     *
     * <p>The load-bearing argument is the second one. Without it this is the
     * ordinary &sect;11 interceptor and a denial is a bare 403; with it, the
     * denial carries a ticket and the caller can act on it.
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AxiamAuthorizationInterceptor(client, challenger));
    }

    /** The guarded resource. */
    @Bean
    InvoiceController invoiceController() {
        return new InvoiceController();
    }

    /** Serves invoices to callers the engine allowed. */
    @RestController
    public static class InvoiceController {

        /**
         * Reached only when the engine allowed it &mdash; including honouring
         * any deny rule, which UMA does not bypass: the ticket minted on the
         * refusal asks for the same action this check just evaluated, so the
         * same grants and denies apply to whatever RPT comes back.
         *
         * @param invoiceId the invoice, whose path variable is also the AXIAM
         *                  resource id the check runs against
         * @return the invoice
         */
        @AxiamRequireAccess(action = "invoices:read", resourceParam = "invoiceId")
        @GetMapping("/invoices/{invoiceId}")
        public Map<String, Object> readInvoice(@PathVariable("invoiceId") UUID invoiceId) {
            return Map.of("id", invoiceId, "total", "42.00", "currency", "EUR");
        }
    }

    /**
     * Starts the service.
     *
     * @param args ignored; configuration comes from the environment
     */
    public static void main(String[] args) {
        SpringApplication.run(UmaResourceServerExample.class, args);
    }

    private static String getenv(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
