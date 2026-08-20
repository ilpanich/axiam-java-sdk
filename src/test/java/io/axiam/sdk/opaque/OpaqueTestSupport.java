package io.axiam.sdk.opaque;

import org.jspecify.annotations.Nullable;

/**
 * Reaches {@link OpaqueLibrary}'s package-private test hooks from tests that
 * live outside this package — {@code AxiamClientOpaqueLoginTest} in particular,
 * which drives the client, not the binding.
 *
 * <p>The hooks stay package-private in main sources on purpose: an installation
 * that can swap the OPAQUE implementation from application code is one where
 * "the password never leaves this process" is a claim rather than a property.
 */
public final class OpaqueTestSupport {

    private OpaqueTestSupport() {
    }

    /**
     * Installs a fake library and returns it for configuration.
     *
     * @return the installed fake
     */
    public static FakeOpaqueNative installFake() {
        FakeOpaqueNative fake = new FakeOpaqueNative();
        OpaqueLibrary.setForTests(fake);
        return fake;
    }

    /** Installs "no library at all" — the state of an installation that never
     * downloaded the artifact, or that lacks JNA. */
    public static void installAbsent() {
        OpaqueLibrary.setForTests(null);
    }

    /** Restores the real loader. */
    public static void reset() {
        OpaqueLibrary.resetForTests();
    }

    /**
     * Decodes one of the fake's hex payloads.
     *
     * @param hex the value the fake produced
     * @return the readable payload behind it
     */
    public static String decode(String hex) {
        byte[] raw = java.util.HexFormat.of().parseHex(hex);
        return new String(raw, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * The library override system property, so a test can prove the loader
     * honours it.
     *
     * @return the property name
     */
    public static String libraryProperty() {
        return OpaqueLibrary.LIBRARY_PROPERTY;
    }

    /**
     * Loads through the real loader, for the absent-library path.
     *
     * @return the binding, or {@code null}
     */
    public static @Nullable Object loadForTests() {
        return OpaqueLibrary.load();
    }
}
