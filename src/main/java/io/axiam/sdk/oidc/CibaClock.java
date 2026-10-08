package io.axiam.sdk.oidc;

import java.time.Duration;
import java.time.Instant;

/**
 * The clock {@code AxiamClient.cibaAwait} waits on &mdash; injectable so its
 * schedule (CONTRACT.md &sect;33.7) is testable without sleeping.
 */
public interface CibaClock {

    /** {@return the current instant} */
    Instant now();

    /**
     * Waits {@code duration}.
     *
     * @param duration how long to wait
     * @throws InterruptedException if the wait is interrupted
     */
    void sleep(Duration duration) throws InterruptedException;

    /**
     * The real clock: {@link Instant#now()} and {@link Thread#sleep(Duration)}.
     *
     * @return the system clock
     */
    static CibaClock system() {
        return new CibaClock() {
            @Override
            public Instant now() {
                return Instant.now();
            }

            @Override
            public void sleep(Duration duration) throws InterruptedException {
                Thread.sleep(duration);
            }
        };
    }
}
