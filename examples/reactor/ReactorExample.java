package io.axiam.sdk.examples.reactor;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.annotations.OnReactorEvent;
import io.axiam.sdk.reactor.ReactorDecision;
import io.axiam.sdk.reactor.ReactorEvent;
import io.axiam.sdk.reactor.ReactorEvents;
import io.axiam.sdk.reactor.ReactorHandlers;
import io.axiam.sdk.reactor.ReactorServeOptions;
import io.axiam.sdk.reactor.ReactorServer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * A working reactor (CONTRACT.md &sect;22): subscribe to hook events on the AMQP
 * bus, decide, and answer allow / deny / mutate under a signed,
 * timeout-bounded, field-allow-listed protocol.
 *
 * <p>This one does two jobs, one per event:
 *
 * <ul>
 *   <li>{@code token.pre_issue} &mdash; <strong>enrich</strong>. Adds a cost
 *       centre and department claim under the {@code ext.} namespace, which is
 *       the entire allow-list for this event. Nothing outside {@code ext.} is
 *       reachable: a reply setting {@code sub} is refused by the server exactly
 *       as a forged one is.</li>
 *   <li>{@code login.post_auth} &mdash; <strong>veto or step up</strong>. Denies
 *       an embargoed region outright, and demands MFA for an administrative
 *       sign-in. This event is veto-only, so no patch is possible here at
 *       all.</li>
 * </ul>
 *
 * <p>What the runtime does for you, before this handler ever runs: rejects
 * {@code key_version < 2}, verifies the HMAC over the canonical bytes, checks
 * freshness in both directions, and checks the nonce. What it does after: signs
 * the reply with the same tenant subkey and publishes it to the delivery's
 * {@code reply_to}, with {@code correlation_id} inside the signed body &mdash;
 * which is the field the server actually authenticates.
 *
 * <p><strong>Throwing is a supported answer.</strong> If your backing service is
 * down, let the exception out: the runtime publishes <em>nothing</em>, and the
 * registration's {@code failure_policy} ({@code fail_open} for
 * {@code token.pre_issue}, {@code fail_closed} for {@code login.post_auth})
 * decides what that costs. Returning {@code allow} because you could not reach
 * your fraud service is how a {@code fail_closed} setting gets defeated from
 * inside the process that was supposed to honour it.
 *
 * <p><strong>Register first.</strong> The queue this consumes is declared by the
 * <em>server</em>, from a registration made through
 * {@code POST /api/v1/reactors}. This process never declares or binds anything:
 *
 * <pre>{@code
 * POST /api/v1/reactors
 * {
 *   "name": "claims-enricher",
 *   "events": ["token.pre_issue", "login.post_auth"],
 *   "mode": "intercept",
 *   "priority": 10,
 *   "timeout_ms": 500
 * }
 * }</pre>
 *
 * <p>Omitting {@code failure_policy} there gives the strictest default among the
 * events named &mdash; {@code fail_closed}, because this registration can veto a
 * login.
 *
 * <p>Run:
 * {@code AXIAM_AMQP_URI=amqps://broker:5671 AXIAM_TENANT_ID=... AXIAM_REACTOR_ID=...
 * AXIAM_AMQP_SUBKEY_HEX=... java ReactorExample.java}
 */
public final class ReactorExample {

    private static final Logger LOG = LoggerFactory.getLogger(ReactorExample.class);

    private static final String EMBARGOED_REGION = "KP";

    public static void main(String[] args) throws Exception {
        // §8b: amqps:// only. HMAC gives authenticity across broker hops; it does
        // not give confidentiality, and a reactor reply is an instruction to
        // change a token. There is no verification-skip switch in this SDK and no
        // plaintext fallback — a failed amqps:// connection is an error to
        // surface, not a condition to work around.
        String amqpUri = required("AXIAM_AMQP_URI");
        UUID tenantId = UUID.fromString(required("AXIAM_TENANT_ID"));
        UUID reactorId = UUID.fromString(required("AXIAM_REACTOR_ID"));

        // §22.12: the tenant AMQP signing key is a credential. Wrapped in
        // Sensitive so it cannot leak through toString(), Jackson, or a
        // reconnect diagnostic. Fetch it from the management API — never
        // hardcode it, and never log it at any level.
        Sensitive subkeyHex = Sensitive.of(required("AXIAM_AMQP_SUBKEY_HEX"));

        ConnectionFactory factory = new ConnectionFactory();
        factory.setUri(amqpUri);
        factory.setAutomaticRecoveryEnabled(true);

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {

            ReactorServeOptions options = ReactorServeOptions
                    .builder(channel, tenantId, subkeyHex)
                    // The queue belongs to THIS registration. The runtime derives
                    // it from our own reactor id and consumes it; it declares
                    // nothing and binds nothing (§22.1).
                    .reactorId(reactorId)
                    // One handler per event (§22.14) instead of a switch whose
                    // `default` arm answers `allow` on behalf of code that never
                    // ran. A misspelled name is refused HERE, at wiring time,
                    // rather than becoming an event that silently never fires.
                    .handler(ReactorHandlers.of(new Decisions()).handler())
                    .logger(LOG)
                    .build();

            try (ReactorServer server = ReactorServer.reactorServe(options)) {
                LOG.info("axiam reactor serving {} — Ctrl+C to stop", server.queue());
                Runtime.getRuntime().addShutdownHook(new Thread(server::close));
                Thread.currentThread().join();
            }
        }
    }

    /**
     * The decision functions, one per event (CONTRACT.md &sect;22.14).
     *
     * <p>Bound declaratively rather than through a {@code switch}: a misspelled
     * event name is refused when {@link ReactorHandlers#of} reads the
     * annotation, and an event this reactor did not bind produces
     * <strong>no reply</strong>, so the registration's {@code failure_policy}
     * decides rather than a {@code default} arm in this file deciding on its
     * behalf.
     */
    public static final class Decisions {

        /**
         * Enriches a token being issued.
         *
         * @param event the verified event
         * @return the decision to sign and publish
         */
        @OnReactorEvent(ReactorEvents.TOKEN_PRE_ISSUE)
        public ReactorDecision enrichToken(ReactorEvent event) {
            String subject = text(event, "sub");
            if (subject == null) {
                return ReactorDecision.allow();
            }

            // An earlier reactor in the chain may already have set claims. This
            // is read-only context: the server merges, later priority winning a
            // contested key, so echoing these back is not how a field is
            // preserved.
            Map<String, String> alreadySet = event.priorPatch();

            Map<String, String> patch = new LinkedHashMap<>();
            if (!alreadySet.containsKey("ext.cost_center")) {
                patch.put("ext.cost_center", costCentreFor(subject));
            }
            patch.put("ext.department", "engineering");

            // `ext.` is the whole allow-list here — `sub`, `aud`, `exp`, `scope`
            // and every other standard claim are unreachable, which is the
            // point. Note this SDK never trims a patch for you: a forbidden key
            // is sent as written and refused by the server, so you find out.
            return patch.isEmpty() ? ReactorDecision.allow() : ReactorDecision.mutate(patch);
        }

        /**
         * Vetoes or steps up an interactive sign-in.
         *
         * @param event the verified event
         * @return the decision to sign and publish
         */
        @OnReactorEvent(ReactorEvents.LOGIN_POST_AUTH)
        public ReactorDecision screenLogin(ReactorEvent event) {
            String region = text(event, "region");
            if (EMBARGOED_REGION.equals(region)) {
                // The reason is audited. A deny with no reason still denies; the
                // reason is for the audit trail, not for the decision.
                return ReactorDecision.deny("sign-in from an embargoed region");
            }

            if ("true".equals(text(event, "is_admin"))) {
                // allow + require_mfa: proceed only after step-up. Valid on
                // login.post_auth ONLY — the server refuses it anywhere else
                // before it even looks at the decision. Sticky across the chain:
                // once any reactor demands step-up, no later one can clear it.
                //
                // A SAML or OIDC sign-in has no step-up branch, so this answer
                // FAILS those logins rather than being silently dropped. If your
                // tenant federates, deny here and drive enrolment out of band
                // instead.
                return ReactorDecision.allowRequiringStepUp();
            }

            return ReactorDecision.allow();
        }
    }

    private static String costCentreFor(String subject) {
        return Integer.toString(Math.floorMod(subject.hashCode(), 100));
    }

    private static String text(ReactorEvent event, String field) {
        var node = event.payload().get(field);
        return node == null || node.isNull() ? null : node.asText();
    }

    private static String required(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " must be set");
        }
        return value;
    }

    private ReactorExample() {
    }
}
