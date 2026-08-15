package io.axiam.sdk.reactor;

import com.rabbitmq.client.Channel;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.telemetry.TelemetryHook;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/**
 * Configuration for {@link ReactorServer#reactorServe(ReactorServeOptions)}.
 *
 * <p>Build one with {@link #builder(Channel, UUID, Sensitive)}. Exactly one of
 * {@link Builder#handler(ReactorHandler)} (intercept) or
 * {@link Builder#listener(ReactorListener)} (observe) must be supplied, and
 * exactly one of {@link Builder#queue(String)} or
 * {@link Builder#reactorId(UUID)} must name the queue to consume.
 *
 * <p><strong>The queue is the server's, not yours.</strong> Whichever you use,
 * the runtime only ever <em>consumes</em> it. It declares no exchange, no queue
 * and no binding, and it cannot name a queue belonging to another reactor:
 * {@link Builder#reactorId(UUID)} derives {@code axiam.reactor.q.<tenant>.<id>}
 * from the tenant and reactor id this runtime is configured as, and nothing
 * else.
 */
public final class ReactorServeOptions {

    private final Channel channel;
    private final UUID tenantId;
    private final Sensitive signingKeyHex;
    private final String queue;
    private final @Nullable ReactorHandler handler;
    private final @Nullable ReactorListener listener;
    private final Logger logger;
    private final Duration freshnessSkew;
    private final Duration shutdownGrace;
    private final int prefetch;
    private final Clock clock;
    private final @Nullable TelemetryHook telemetryHook;

    private ReactorServeOptions(Builder builder) {
        this.channel = builder.channel;
        this.tenantId = builder.tenantId;
        this.signingKeyHex = builder.signingKeyHex;
        this.handler = builder.handler;
        this.listener = builder.listener;
        this.logger = builder.logger;
        this.freshnessSkew = builder.freshnessSkew;
        this.shutdownGrace = builder.shutdownGrace;
        this.prefetch = builder.prefetch;
        this.clock = builder.clock;
        this.telemetryHook = builder.telemetryHook;

        if ((builder.handler == null) == (builder.listener == null)) {
            throw new IllegalStateException(
                    "supply exactly one of handler(..) (mode: intercept) or listener(..) (mode: listen)");
        }
        if ((builder.queue == null) == (builder.reactorId == null)) {
            throw new IllegalStateException("supply exactly one of queue(..) or reactorId(..)");
        }
        this.queue = builder.queue != null
                ? builder.queue
                : ReactorProtocol.queueName(builder.tenantId, builder.reactorId);
    }

    /**
     * Starts building options for a reactor in {@code tenantId}.
     *
     * @param channel       an open AMQP channel. Its connection MUST have been
     *                      opened over {@code amqps://} with a trusted CA
     *                      (&sect;8b): a reactor reply is an instruction to change
     *                      a token, and HMAC gives authenticity, not
     *                      confidentiality. The caller owns the channel's
     *                      lifecycle.
     * @param tenantId      the tenant this reactor is registered in. An event
     *                      naming any other tenant is discarded.
     * @param signingKeyHex the tenant's HKDF-derived AMQP subkey, hex-encoded, as
     *                      the management API returns it — the same key the
     *                      server signed the event with. Wrapped in
     *                      {@link Sensitive} because it is a credential
     *                      (&sect;22.12): it is never logged at any level and
     *                      never appears in a reconnect diagnostic.
     * @return a builder
     */
    public static Builder builder(Channel channel, UUID tenantId, Sensitive signingKeyHex) {
        return new Builder(channel, tenantId, signingKeyHex);
    }

    /**
     * The channel to consume on.
     *
     * @return the channel
     */
    public Channel channel() {
        return channel;
    }

    /**
     * The tenant this reactor serves.
     *
     * @return the tenant id
     */
    public UUID tenantId() {
        return tenantId;
    }

    /**
     * The server-declared queue this runtime consumes.
     *
     * @return the queue name
     */
    public String queue() {
        return queue;
    }

    /**
     * The intercept handler, if this is an interceptor.
     *
     * @return the handler, or {@code null} when this runtime is a listener
     */
    public @Nullable ReactorHandler handler() {
        return handler;
    }

    /**
     * The listen callback, if this is a listener.
     *
     * @return the listener, or {@code null} when this runtime is an interceptor
     */
    public @Nullable ReactorListener listener() {
        return listener;
    }

    /**
     * Where rejection diagnostics go.
     *
     * @return the logger
     */
    public Logger logger() {
        return logger;
    }

    /**
     * The &sect;8 v2 freshness window.
     *
     * @return the acceptance window applied to {@code issued_at} in both directions
     */
    public Duration freshnessSkew() {
        return freshnessSkew;
    }

    /**
     * How long {@link ReactorServer#close()} waits for in-flight events to drain.
     *
     * @return the drain grace period
     */
    public Duration shutdownGrace() {
        return shutdownGrace;
    }

    /**
     * The channel QoS prefetch applied before consuming.
     *
     * @return the prefetch count
     */
    public int prefetch() {
        return prefetch;
    }

    /**
     * The clock used for freshness, deadlines and reply timestamps.
     *
     * @return the clock
     */
    public Clock clock() {
        return clock;
    }

    /**
     * The &sect;19 telemetry sink, if one was installed.
     *
     * @return the hook, or {@code null}
     */
    public @Nullable TelemetryHook telemetryHook() {
        return telemetryHook;
    }

    /**
     * The decoded signing key.
     *
     * <p>Package-private on purpose: {@link Sensitive} is the only public shape
     * this key has, and the decoded bytes never leave this package.
     *
     * @return a fresh copy of the key bytes
     */
    byte[] signingKey() {
        return HexFormat.of().parseHex(signingKeyHex.expose());
    }

    /** Fluent builder for {@link ReactorServeOptions}. */
    public static final class Builder {

        private static final Logger DEFAULT_LOGGER = LoggerFactory.getLogger(ReactorServer.class);

        private final Channel channel;
        private final UUID tenantId;
        private final Sensitive signingKeyHex;
        private @Nullable String queue;
        private @Nullable UUID reactorId;
        private @Nullable ReactorHandler handler;
        private @Nullable ReactorListener listener;
        private Logger logger = DEFAULT_LOGGER;
        private Duration freshnessSkew = ReactorProtocol.DEFAULT_FRESHNESS_SKEW;
        private Duration shutdownGrace = Duration.ofSeconds(10);
        private int prefetch = 16;
        private Clock clock = Clock.systemUTC();
        private @Nullable TelemetryHook telemetryHook;

        private Builder(Channel channel, UUID tenantId, Sensitive signingKeyHex) {
            this.channel = Objects.requireNonNull(channel, "channel");
            this.tenantId = Objects.requireNonNull(tenantId, "tenantId");
            this.signingKeyHex = Objects.requireNonNull(signingKeyHex, "signingKeyHex");
        }

        /**
         * Consumes a queue named explicitly — use this when the registration's
         * queue name was handed to you rather than derived.
         *
         * @param queue the server-declared queue name
         * @return this builder
         */
        public Builder queue(String queue) {
            this.queue = Objects.requireNonNull(queue, "queue");
            return this;
        }

        /**
         * Consumes the queue belonging to <em>this</em> reactor registration.
         *
         * @param reactorId this reactor's own registration id. The runtime will
         *                  not name a queue for any other reactor: a reactor that
         *                  can pick its own queue is a reactor that can read
         *                  another tenant's issuance events.
         * @return this builder
         */
        public Builder reactorId(UUID reactorId) {
            this.reactorId = Objects.requireNonNull(reactorId, "reactorId");
            return this;
        }

        /**
         * Registers the intercept handler ({@code mode: "intercept"}).
         *
         * @param handler the decision function
         * @return this builder
         */
        public Builder handler(ReactorHandler handler) {
            this.handler = Objects.requireNonNull(handler, "handler");
            return this;
        }

        /**
         * Registers the observe callback ({@code mode: "listen"}). The runtime
         * publishes nothing at all in this mode.
         *
         * @param listener the observer; must be idempotent
         * @return this builder
         */
        public Builder listener(ReactorListener listener) {
            this.listener = Objects.requireNonNull(listener, "listener");
            return this;
        }

        /**
         * Overrides the logger rejections are reported on.
         *
         * @param logger the SLF4J logger
         * @return this builder
         */
        public Builder logger(Logger logger) {
            this.logger = Objects.requireNonNull(logger, "logger");
            return this;
        }

        /**
         * Overrides the &sect;8 v2 freshness window.
         *
         * @param freshnessSkew the acceptance window; must be positive.
         *                      {@link ReactorProtocol#DEFAULT_FRESHNESS_SKEW}
         *                      (300 s) matches the server.
         * @return this builder
         */
        public Builder freshnessSkew(Duration freshnessSkew) {
            if (freshnessSkew.isNegative() || freshnessSkew.isZero()) {
                throw new IllegalArgumentException("freshnessSkew must be positive");
            }
            this.freshnessSkew = freshnessSkew;
            return this;
        }

        /**
         * Overrides how long {@link ReactorServer#close()} waits for in-flight
         * events to finish (&sect;18).
         *
         * @param shutdownGrace the drain grace period; must be positive
         * @return this builder
         */
        public Builder shutdownGrace(Duration shutdownGrace) {
            if (shutdownGrace.isNegative() || shutdownGrace.isZero()) {
                throw new IllegalArgumentException("shutdownGrace must be positive");
            }
            this.shutdownGrace = shutdownGrace;
            return this;
        }

        /**
         * Overrides the channel QoS prefetch.
         *
         * @param prefetch how many unacknowledged deliveries the broker may have
         *                 outstanding; must be positive. The server's own
         *                 per-tenant in-flight cap is
         *                 {@link ReactorProtocol#DEFAULT_MAX_IN_FLIGHT_PER_TENANT}.
         * @return this builder
         */
        public Builder prefetch(int prefetch) {
            if (prefetch <= 0) {
                throw new IllegalArgumentException("prefetch must be positive");
            }
            this.prefetch = prefetch;
            return this;
        }

        /**
         * Overrides the clock — for deterministic tests.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Installs a &sect;19 telemetry sink.
         *
         * @param telemetryHook receives one
         *                      {@code RequestStart}/{@code RequestEnd} pair per
         *                      dispatched event. A hook that throws cannot fail
         *                      the dispatch that fired it.
         * @return this builder
         */
        public Builder telemetryHook(TelemetryHook telemetryHook) {
            this.telemetryHook = Objects.requireNonNull(telemetryHook, "telemetryHook");
            return this;
        }

        /**
         * Validates and freezes the configuration.
         *
         * @return the immutable options
         * @throws IllegalStateException when neither or both of
         *                               handler/listener, or neither or both of
         *                               queue/reactorId, were supplied
         */
        public ReactorServeOptions build() {
            return new ReactorServeOptions(this);
        }
    }
}
