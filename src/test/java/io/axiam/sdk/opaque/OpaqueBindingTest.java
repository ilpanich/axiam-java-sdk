package io.axiam.sdk.opaque;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JNA binding to {@code libaxiam_opaque_ffi}.
 *
 * <p>&sect;23.1 forbids this SDK from implementing OPAQUE, so there is no
 * cryptography here to test. What these cover is the part a binding gets
 * wrong: ownership of library-allocated strings, single-use state handles, the
 * key-stretching function the <em>server</em> named being the one used, and an
 * absent library reporting rather than resembling a wrong password.
 */
class OpaqueBindingTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Minted per run rather than written down. Nothing here depends on the
     * value — only on the two differing — and a literal that reads like a
     * credential is a finding for every secret scanner that looks at this
     * repository, which trains people to wave those findings through.
     */
    private static char[] password(String label) {
        byte[] entropy = new byte[8];
        RANDOM.nextBytes(entropy);
        return (label + "-" + HexFormat.of().formatHex(entropy)).toCharArray();
    }

    private static final char[] PASSWORD = password("correct");
    private static final char[] OTHER_PASSWORD = password("incorrect");

    private static final String KE2 = "ke2-hex";
    private static final String REGISTRATION_RESPONSE = "resp-hex";

    private FakeOpaqueNative lib;

    @BeforeEach
    void installFake() {
        lib = OpaqueTestSupport.installFake();
    }

    @AfterEach
    void restoreLoader() {
        OpaqueTestSupport.reset();
    }

    private static KsfParams argon2id() {
        ObjectNode wire = MAPPER.createObjectNode();
        wire.put("ksf", "argon2id");
        wire.put("memory_kib", 19456);
        wire.put("iterations", 2);
        wire.put("parallelism", 1);
        return KsfParams.fromWire(wire);
    }

    private static KsfParams scrypt() {
        ObjectNode wire = MAPPER.createObjectNode();
        wire.put("ksf", "scrypt");
        wire.put("log_n", 15);
        wire.put("r", 8);
        wire.put("p", 1);
        return KsfParams.fromWire(wire);
    }

    // -----------------------------------------------------------------
    // Availability (§23.2) -- reporting, never throwing
    // -----------------------------------------------------------------

    @Test
    @DisplayName("available() is true when the library loads and says yes")
    void availableWhenPresent() {
        assertTrue(Opaque.available());
    }

    @Test
    @DisplayName("a library that is present but built without OPAQUE reports false")
    void availableFalseWhenLibrarySaysNo() {
        // Present is not the same as usable, and answering from the file's
        // existence would strand a caller at login.
        lib.setAvailable(0);
        assertFalse(Opaque.available());
    }

    @Test
    @DisplayName("an absent library reports false rather than throwing")
    void availableFalseWhenAbsent() {
        OpaqueTestSupport.installAbsent();
        assertFalse(Opaque.available());
    }

    @Test
    @DisplayName("an absent library names the artifact, not the password")
    void absentLibraryNamesTheArtifact() {
        OpaqueTestSupport.installAbsent();
        NetworkError error = assertThrows(NetworkError.class,
                () -> Opaque.startLogin(PASSWORD));
        assertTrue(error.getMessage().contains("libaxiam_opaque_ffi"));
        assertTrue(error.getMessage().contains("AXIAM_OPAQUE_LIBRARY"));
        assertTrue(error.getMessage().contains("jna"));
    }

    @Test
    @DisplayName("the real loader treats an unloadable library as absent, and memoizes that")
    void realLoaderReportsAbsentRatherThanThrowing() {
        // No libaxiam_opaque_ffi is installed in CI, so this exercises the
        // genuine dlopen failure path -- including that retrying it is not a
        // per-login filesystem walk.
        OpaqueTestSupport.reset();
        System.setProperty(OpaqueTestSupport.libraryProperty(),
                "/nonexistent/libaxiam_opaque_ffi_absent.so");
        try {
            assertNull(OpaqueTestSupport.loadForTests());
            assertNull(OpaqueTestSupport.loadForTests());
        } finally {
            System.clearProperty(OpaqueTestSupport.libraryProperty());
            OpaqueTestSupport.reset();
        }
    }

    // -----------------------------------------------------------------
    // KsfParams -- absence preserved, bounds enforced (§23.4 rules 2-5)
    // -----------------------------------------------------------------

    @Test
    @DisplayName("fromWire preserves absence rather than defaulting to zero")
    void absenceIsPreserved() {
        KsfParams params = argon2id();
        assertEquals("argon2id", params.ksf());
        assertEquals(19456, params.memoryKib());
        // scrypt's fields do not apply. Reading them as 0 would stretch at the
        // wrong cost and fail against a record that is perfectly good.
        assertNull(params.logN());
        assertNull(params.r());
        assertNull(params.p());
    }

    @Test
    @DisplayName("a cost the named function needs but the server omitted is refused")
    void missingCostIsRefused() {
        ObjectNode wire = MAPPER.createObjectNode();
        wire.put("ksf", "argon2id");
        wire.put("iterations", 2);
        wire.put("parallelism", 1);
        NetworkError error = assertThrows(NetworkError.class,
                () -> KsfParams.fromWire(wire).build(lib));
        assertTrue(error.getMessage().contains("without `memory_kib`"));
        assertEquals(0, lib.ksfAlive());
    }

    @ParameterizedTest
    @CsvSource({
            "argon2id, memory_kib, 4096",
            "argon2id, memory_kib, 2097152",
            "argon2id, iterations, 0",
            "argon2id, iterations, 99",
            "argon2id, parallelism, 64",
            "scrypt, log_n, 13",
            "scrypt, log_n, 21",
            "scrypt, r, 0",
            "scrypt, p, 17",
    })
    @DisplayName("a cost outside the accepted band is refused, naming the field")
    void costsOutsideTheBandAreRefused(String ksf, String field, int value) {
        // A server is trusted to name its own policy, not to name a cost that
        // would wedge every device an account owns.
        ObjectNode wire = MAPPER.createObjectNode();
        wire.put("ksf", ksf);
        if ("argon2id".equals(ksf)) {
            wire.put("memory_kib", 19456);
            wire.put("iterations", 2);
            wire.put("parallelism", 1);
        } else {
            wire.put("log_n", 15);
            wire.put("r", 8);
            wire.put("p", 1);
        }
        wire.put(field, value);

        NetworkError error = assertThrows(NetworkError.class,
                () -> KsfParams.fromWire(wire).build(lib));
        assertTrue(error.getMessage().contains(field), error.getMessage());
        assertEquals(0, lib.ksfAlive());
    }

    @ParameterizedTest
    @ValueSource(strings = {"bcrypt", "pbkdf2_sha256", ""})
    @DisplayName("an unrecognised key-stretching function is refused, never substituted")
    void unknownKsfIsRefused(String ksf) {
        // Substituting produces a well-formed randomized password no AXIAM
        // server agrees with, which surfaces to the user as a wrong password.
        ObjectNode wire = MAPPER.createObjectNode();
        wire.put("ksf", ksf);
        assertThrows(NetworkError.class, () -> KsfParams.fromWire(wire).build(lib));
        assertEquals(0, lib.ksfAlive());
    }

    @Test
    @DisplayName("a null ksf handle reports the library's own message")
    void nullKsfHandleReportsLibraryMessage() {
        lib.fail("ksf_argon2id");
        NetworkError error = assertThrows(NetworkError.class, () -> argon2id().build(lib));
        assertTrue(error.getMessage().contains("argon2id parameters rejected"));
    }

    @Test
    @DisplayName("both key-stretching functions are reachable")
    void bothKsfsReachable() {
        for (KsfParams params : new KsfParams[] {argon2id(), scrypt()}) {
            lib.axiam_opaque_ksf_free(params.build(lib));
        }
        assertEquals(0, lib.ksfAlive());
    }

    // -----------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a registration round trip frees every allocation exactly once")
    void registrationRoundTrip() {
        RegistrationExchange exchange = Opaque.startRegistration(PASSWORD);
        assertEquals("req:" + new String(PASSWORD),
                OpaqueTestSupport.decode(exchange.request()));

        String record = exchange.finish(PASSWORD, REGISTRATION_RESPONSE, argon2id());

        assertTrue(OpaqueTestSupport.decode(record)
                .startsWith("record:" + new String(PASSWORD) + ":" + REGISTRATION_RESPONSE + ":"));
        // Two library allocations were handed over -- the request and the
        // record -- and both were released. A binding that leaks here leaks
        // once per enrolment.
        assertEquals(2, lib.freed().size());
        assertEquals(2, lib.freed().stream().distinct().count());
        assertEquals(0, lib.allocationsAlive());
        assertEquals(0, lib.ksfAlive());
        assertEquals(0, lib.statesAlive());
    }

    @Test
    @DisplayName("a failed registration start reports the library's message")
    void registrationStartFailure() {
        lib.fail("registration_start");
        NetworkError error = assertThrows(NetworkError.class,
                () -> Opaque.startRegistration(PASSWORD));
        assertTrue(error.getMessage().contains("registration could not be started"));
    }

    @Test
    @DisplayName("a failed registration finish still consumed the handle, and leaks nothing")
    void registrationFinishFailure() {
        lib.fail("registration_finish");
        RegistrationExchange exchange = Opaque.startRegistration(PASSWORD);
        NetworkError error = assertThrows(NetworkError.class,
                () -> exchange.finish(PASSWORD, REGISTRATION_RESPONSE, argon2id()));
        assertTrue(error.getMessage().contains("the envelope could not be sealed"));
        // The library consumes the state whether it succeeds or fails, so the
        // binding must not free it again -- and must not leak the ksf either.
        assertEquals(0, lib.statesAlive());
        assertEquals(0, lib.ksfAlive());
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    @Test
    @DisplayName("a login round trip frees every allocation exactly once")
    void loginRoundTrip() {
        LoginExchange exchange = Opaque.startLogin(PASSWORD);
        assertEquals("ke1:" + new String(PASSWORD), OpaqueTestSupport.decode(exchange.ke1()));

        String ke3 = exchange.finish(PASSWORD, KE2, scrypt());

        assertTrue(OpaqueTestSupport.decode(ke3)
                .startsWith("ke3:" + new String(PASSWORD) + ":" + KE2 + ":"));
        assertEquals(2, lib.freed().size());
        assertEquals(0, lib.allocationsAlive());
        assertEquals(0, lib.ksfAlive());
        assertEquals(0, lib.statesAlive());
    }

    @Test
    @DisplayName("a failed login start reports the library's message")
    void loginStartFailure() {
        lib.fail("login_start");
        NetworkError error = assertThrows(NetworkError.class, () -> Opaque.startLogin(PASSWORD));
        assertTrue(error.getMessage().contains("login could not be started"));
    }

    @Test
    @DisplayName("a failed login finish is an AuthError -- it IS the credential check")
    void failedLoginFinishIsAnAuthError() {
        // Both halves of the mutual authentication live here: the envelope only
        // opens under the right password, and KE2's MAC only verifies if the
        // server actually holds the record. AuthError rather than NetworkError
        // is what keeps a misconfigured KSF from being shown as a wrong password.
        lib.fail("login_finish");
        LoginExchange exchange = Opaque.startLogin(OTHER_PASSWORD);
        AuthError error = assertThrows(AuthError.class,
                () -> exchange.finish(OTHER_PASSWORD, KE2, argon2id()));
        assertTrue(error.getMessage().contains("invalid credentials"));
        assertEquals(0, lib.statesAlive());
        assertEquals(0, lib.ksfAlive());
    }

    @Test
    @DisplayName("a silent library still produces a sentence")
    void failedLoginFinishFallsBackWhenLibraryIsSilent() {
        lib.fail("login_finish");
        lib.failMessage("login_finish", "");
        LoginExchange exchange = Opaque.startLogin(OTHER_PASSWORD);
        AuthError error = assertThrows(AuthError.class,
                () -> exchange.finish(OTHER_PASSWORD, KE2, argon2id()));
        assertTrue(error.getMessage().contains("the OPAQUE envelope did not open"));
    }

    @Test
    @DisplayName("an exchange is single-use")
    void exchangeIsSingleUse() {
        LoginExchange exchange = Opaque.startLogin(PASSWORD);
        exchange.finish(PASSWORD, KE2, argon2id());
        NetworkError error = assertThrows(NetworkError.class,
                () -> exchange.finish(PASSWORD, KE2, argon2id()));
        assertTrue(error.getMessage().contains("already been completed"));
    }

    @Test
    @DisplayName("a refused ksf spends the handle, so a retry fails loudly")
    void refusedKsfStillSpendsTheHandle() {
        RegistrationExchange exchange = Opaque.startRegistration(PASSWORD);
        ObjectNode unknown = MAPPER.createObjectNode();
        unknown.put("ksf", "bcrypt");
        assertThrows(NetworkError.class,
                () -> exchange.finish(PASSWORD, REGISTRATION_RESPONSE, KsfParams.fromWire(unknown)));
        // The handle was taken before the ksf was built, so it is spent.
        // Retrying must fail rather than pass a dangling pointer across the ABI.
        NetworkError second = assertThrows(NetworkError.class,
                () -> exchange.finish(PASSWORD, REGISTRATION_RESPONSE, argon2id()));
        assertTrue(second.getMessage().contains("already been completed"));
    }

    @Test
    @DisplayName("close() releases an exchange that was never finished")
    void closeReleasesAnAbandonedExchange() {
        try (LoginExchange exchange = Opaque.startLogin(PASSWORD)) {
            assertEquals(1, lib.statesAlive());
            assertTrue(exchange.ke1().length() > 0);
        }
        assertEquals(0, lib.statesAlive());
    }

    @Test
    @DisplayName("close() after a finish is a no-op, not a double free")
    void closeAfterFinishIsIdempotent() {
        try (LoginExchange exchange = Opaque.startLogin(PASSWORD)) {
            exchange.finish(PASSWORD, KE2, argon2id());
            exchange.close();
        }
        assertEquals(0, lib.statesAlive());
    }

    @Test
    @DisplayName("an abandoned registration is released too")
    void closeReleasesAnAbandonedRegistration() {
        try (RegistrationExchange exchange = Opaque.startRegistration(PASSWORD)) {
            assertEquals(1, lib.statesAlive());
        }
        assertEquals(0, lib.statesAlive());
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    @Test
    @DisplayName("passwords cross the ABI as UTF-8, not as the platform charset")
    void passwordsCrossAsUtf8() {
        // A password that encoded differently under a different default locale
        // would derive a randomized password no AXIAM server agrees with, and
        // would surface as a wrong password on that machine only. The
        // conformance vectors require UTF-8.
        char[] accented = "pàsswörd-ünïcøde-🔐".toCharArray();
        LoginExchange exchange = Opaque.startLogin(accented);
        assertEquals("ke1:" + new String(accented), OpaqueTestSupport.decode(exchange.ke1()));
        exchange.close();
    }

    @Test
    @DisplayName("an empty password is still a password")
    void emptyPasswordIsEncoded() {
        LoginExchange exchange = Opaque.startLogin(new char[0]);
        assertEquals("ke1:", OpaqueTestSupport.decode(exchange.ke1()));
        exchange.close();
    }
}
