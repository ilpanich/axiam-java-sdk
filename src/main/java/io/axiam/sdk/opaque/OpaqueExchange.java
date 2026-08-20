package io.axiam.sdk.opaque;

import com.sun.jna.Pointer;
import io.axiam.sdk.errors.NetworkError;
import org.jspecify.annotations.Nullable;

import java.lang.ref.Cleaner;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One in-flight OPAQUE exchange, owning a native state handle.
 *
 * <p>The handle is <strong>single-use</strong>: the library consumes it in
 * {@code finish} whether that succeeds or fails. This class takes it out of a
 * one-shot slot, so a second {@code finish} raises a Java exception rather
 * than handing a dangling pointer across the ABI, and registers a
 * {@link Cleaner} so an exchange the caller abandoned — a login started and
 * never completed — is released rather than leaked. {@link #close} does the
 * same thing deterministically, which is what a caller who knows the exchange
 * is over should use.
 */
public abstract class OpaqueExchange implements AutoCloseable {

    private static final Cleaner CLEANER = Cleaner.create();

    /** The loaded library, shared with subclasses for their {@code finish}. */
    final OpaqueNative lib;

    private final Handle handle;
    private final Cleaner.Cleanable cleanable;
    private final String firstMessage;

    OpaqueExchange(OpaqueNative lib, Pointer handle, String firstMessage, boolean registration) {
        this.lib = lib;
        this.handle = new Handle(lib, handle, registration);
        this.firstMessage = firstMessage;
        // The action must not capture `this`, or the Cleaner keeps the very
        // object it is meant to notice becoming unreachable.
        this.cleanable = CLEANER.register(this, this.handle);
    }

    /** The first protocol message, hex — {@code RegistrationRequest} or {@code KE1}. */
    String firstMessage() {
        return firstMessage;
    }

    /**
     * Spends the handle.
     *
     * @return the handle, now owned by the caller and consumed by the library
     * @throws NetworkError if this exchange has already been completed
     */
    Pointer consume() {
        Pointer taken = handle.take();
        if (taken == null) {
            throw new NetworkError("OPAQUE: this exchange has already been completed");
        }
        return taken;
    }

    /**
     * Releases the exchange if it was never finished. Idempotent, and a no-op
     * once {@code finish} has spent the handle.
     */
    @Override
    public void close() {
        cleanable.clean();
    }

    /** The native handle, in a form the {@link Cleaner} can hold on its own. */
    private static final class Handle implements Runnable {
        private final OpaqueNative lib;
        private final boolean registration;
        private final AtomicReference<Pointer> slot;

        Handle(OpaqueNative lib, Pointer handle, boolean registration) {
            this.lib = lib;
            this.registration = registration;
            this.slot = new AtomicReference<>(handle);
        }

        @Nullable Pointer take() {
            return slot.getAndSet(null);
        }

        @Override
        public void run() {
            Pointer abandoned = take();
            if (abandoned == null) {
                return;
            }
            if (registration) {
                lib.axiam_opaque_registration_free(abandoned);
            } else {
                lib.axiam_opaque_login_free(abandoned);
            }
        }
    }
}
