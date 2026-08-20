package io.axiam.sdk.opaque;

import io.axiam.sdk.errors.NetworkError;
import org.jspecify.annotations.Nullable;

/**
 * Loads {@code libaxiam_opaque_ffi} once per process, memoizing failure as
 * well as success.
 *
 * <p>Two independent things can be absent, and both are normal:
 *
 * <ul>
 *   <li><strong>JNA.</strong> {@code net.java.dev.jna:jna} is an
 *       <em>optional</em> dependency of this SDK, so it does not reach a
 *       consumer's classpath transitively. A REST/gRPC consumer whose tenant
 *       does not use OPAQUE should not be made to carry it.</li>
 *   <li><strong>The shared library.</strong> It is a Rust {@code cdylib}
 *       published as a per-platform asset of the AXIAM release, not an
 *       artifact on Maven Central.</li>
 * </ul>
 *
 * <p>Either absence makes {@link Opaque#available()} report {@code false}
 * rather than throwing, so an application chooses the password path up front
 * instead of discovering the gap mid-login. Memoizing the failure matters as
 * much as memoizing the success: retrying {@code dlopen} on every login is a
 * per-request filesystem walk for a file that is not going to appear.
 */
final class OpaqueLibrary {

    /** Overrides the search: an absolute path to the shared library. */
    static final String LIBRARY_PROPERTY = "axiam.opaque.library";

    /** The environment variable form of {@link #LIBRARY_PROPERTY}. */
    static final String LIBRARY_ENV = "AXIAM_OPAQUE_LIBRARY";

    /**
     * The base name JNA expands per platform: {@code libaxiam_opaque_ffi.so},
     * {@code libaxiam_opaque_ffi.dylib}, {@code axiam_opaque_ffi.dll}.
     */
    private static final String LIBRARY_NAME = "axiam_opaque_ffi";

    private static final Object LOCK = new Object();

    private static @Nullable OpaqueNative library;
    private static boolean attempted;

    private OpaqueLibrary() {
    }

    /**
     * The library, or {@code null} when it — or JNA — is not present.
     *
     * @return the loaded binding, or {@code null}
     */
    static @Nullable OpaqueNative load() {
        synchronized (LOCK) {
            if (attempted) {
                return library;
            }
            attempted = true;
            library = attemptLoad();
            return library;
        }
    }

    private static @Nullable OpaqueNative attemptLoad() {
        try {
            String override = System.getProperty(LIBRARY_PROPERTY, System.getenv(LIBRARY_ENV));
            String target = override == null || override.isBlank() ? LIBRARY_NAME : override;
            return com.sun.jna.Native.load(target, OpaqueNative.class);
        } catch (NoClassDefFoundError | UnsatisfiedLinkError | RuntimeException e) {
            // NoClassDefFoundError: JNA itself is absent (optional dependency).
            // UnsatisfiedLinkError: JNA is here, the shared library is not, or
            // it loaded and is missing our symbols -- some other library of the
            // same name on the search path, which must be treated as absent
            // rather than called into.
            return null;
        }
    }

    /**
     * The library, or a refusal naming the artifact.
     *
     * <p>Never an {@link io.axiam.sdk.errors.AuthError}: absent is a
     * deployment fact, and reporting it as a credential failure would send a
     * user off to reset a password that works.
     *
     * @return the loaded binding
     * @throws NetworkError when it cannot be loaded
     */
    static OpaqueNative require() {
        OpaqueNative loaded = load();
        if (loaded == null) {
            throw new NetworkError("OPAQUE is not available: the shared library "
                    + "`libaxiam_opaque_ffi` could not be loaded. Download the asset for your "
                    + "platform from the axiam release page, then put it on java.library.path or "
                    + "set -D" + LIBRARY_PROPERTY + "=/path/to/it (or the " + LIBRARY_ENV
                    + " environment variable). This SDK's `jna` dependency is optional, so also "
                    + "check that net.java.dev.jna:jna is on the classpath.");
        }
        return loaded;
    }

    /**
     * Installs a binding, bypassing the loader. Test-only.
     *
     * @param stub the binding to install, or {@code null} for "absent"
     */
    static void setForTests(@Nullable OpaqueNative stub) {
        synchronized (LOCK) {
            library = stub;
            attempted = true;
        }
    }

    /** Forgets the memoized load. Test-only. */
    static void resetForTests() {
        synchronized (LOCK) {
            library = null;
            attempted = false;
        }
    }
}
