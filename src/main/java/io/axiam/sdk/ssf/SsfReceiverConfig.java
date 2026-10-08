package io.axiam.sdk.ssf;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.internal.LocalRefusal;

import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Configuration for an {@link SsfReceiver} (CONTRACT.md &sect;32.7:
 * {@code { issuer, audience, jwks_uri | discovery_url, access_token_provider }}).
 *
 * <p>{@link #toString()} shows the issuer, the audience, the key source and the
 * window, never the access token provider.
 */
public final class SsfReceiverConfig {

    /** The replay window's floor and default: seven days, the transmitter's buffer retention. */
    public static final Duration MIN_REPLAY_WINDOW = Duration.ofDays(7);

    private final String issuer;
    private final String audience;
    private final SsfKeySource keySource;
    private final @Nullable Supplier<Sensitive> accessTokenProvider;
    private final Duration replayWindow;
    private final ReplayStore replayStore;

    private SsfReceiverConfig(Builder b) {
        this.issuer = b.issuer;
        this.audience = b.audience;
        this.keySource = b.keySource;
        this.accessTokenProvider = b.accessTokenProvider;
        this.replayWindow = b.replayWindow;
        this.replayStore = b.replayStore != null ? b.replayStore : new MemoryReplayStore();
    }

    /**
     * Starts a configuration with the default replay window and store and no
     * poll credential.
     *
     * @param issuer    the transmitter's issuer &mdash; compared to {@code iss} exactly
     * @param audience  this receiver's audience &mdash; the stream's {@code audience}
     * @param keySource where the signing keys come from
     * @return a builder
     */
    public static Builder builder(String issuer, String audience, SsfKeySource keySource) {
        return new Builder(issuer, audience, keySource);
    }

    /** {@return the issuer} */
    public String issuer() {
        return issuer;
    }

    /** {@return the audience} */
    public String audience() {
        return audience;
    }

    /** {@return where the signing keys come from} */
    public SsfKeySource keySource() {
        return keySource;
    }

    /** {@return the poll credential's provider, or {@code null} for a push-only receiver} */
    public @Nullable Supplier<Sensitive> accessTokenProvider() {
        return accessTokenProvider;
    }

    /** {@return how long a {@code jti} is remembered} */
    public Duration replayWindow() {
        return replayWindow;
    }

    /** {@return where accepted {@code jti}s are kept} */
    public ReplayStore replayStore() {
        return replayStore;
    }

    @Override
    public String toString() {
        return "SsfReceiverConfig[issuer=" + issuer + ", audience=" + audience + ", keySource=" + keySource
                + ", replayWindow=" + replayWindow + "]";
    }

    /** Builds an {@link SsfReceiverConfig}. */
    public static final class Builder {
        private final String issuer;
        private final String audience;
        private final SsfKeySource keySource;
        private @Nullable Supplier<Sensitive> accessTokenProvider;
        private Duration replayWindow = MIN_REPLAY_WINDOW;
        private @Nullable ReplayStore replayStore;

        private Builder(String issuer, String audience, SsfKeySource keySource) {
            this.issuer = issuer;
            this.audience = audience;
            this.keySource = Objects.requireNonNull(keySource, "keySource");
        }

        /**
         * The bearer {@link SsfReceiver#poll} presents: a client-credentials
         * access token carrying {@code ssf.manage}, e.g. from
         * {@code client.loginClientCredentials(...)}. Called once per poll.
         *
         * @param provider supplies the token
         * @return this builder
         */
        public Builder accessTokenProvider(Supplier<Sensitive> provider) {
            this.accessTokenProvider = Objects.requireNonNull(provider, "provider");
            return this;
        }

        /**
         * How long a {@code jti} is remembered. At least
         * {@link #MIN_REPLAY_WINDOW} (seven days); shorter is refused at
         * {@link #build()}.
         *
         * @param window the replay window
         * @return this builder
         */
        public Builder replayWindow(Duration window) {
            this.replayWindow = Objects.requireNonNull(window, "window");
            return this;
        }

        /**
         * Where accepted {@code jti}s are kept; the default is a
         * {@link MemoryReplayStore}.
         *
         * @param store the store
         * @return this builder
         */
        public Builder replayStore(ReplayStore store) {
            this.replayStore = Objects.requireNonNull(store, "store");
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration
         * @throws io.axiam.sdk.errors.ValidationError when the replay window is
         *         below seven days, or the issuer or audience is empty
         */
        public SsfReceiverConfig build() {
            if (replayWindow.compareTo(MIN_REPLAY_WINDOW) < 0) {
                throw LocalRefusal.of("ssf.receiver", "replay_window",
                        "must be at least seven days, the transmitter's buffer retention (CONTRACT.md §32.7)");
            }
            if (issuer == null || issuer.isEmpty() || audience == null || audience.isEmpty()) {
                throw LocalRefusal.of("ssf.receiver", "issuer",
                        "issuer and audience are required (CONTRACT.md §32.7)");
            }
            return new SsfReceiverConfig(this);
        }
    }
}
