package io.axiam.sdk.opaque;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An in-process stand-in for {@code libaxiam_opaque_ffi}.
 *
 * <p>CONTRACT.md &sect;23.1 forbids this SDK from implementing OPAQUE, so there
 * is no cryptography to test. What there is — and what this fake exists to
 * exercise — is the ABI's <em>contract</em>:
 *
 * <ul>
 *   <li>every {@code char *} returned is heap-allocated and must be freed
 *       exactly once with {@code string_free};</li>
 *   <li>a state handle is CONSUMED by its {@code finish}, success or failure;</li>
 *   <li>a {@code null} return means failure, described by {@code last_error}.</li>
 * </ul>
 *
 * <p>Requiring the real shared library would give a suite that runs only where
 * a per-platform release asset happens to be installed — and it would be
 * testing {@code opaque-ke} rather than this binding. Cross-implementation
 * agreement is verified upstream by the conformance vectors.
 *
 * <p>Every value it returns is hex, as the real ABI's are: a fake that handed
 * back raw bytes would let a binding bug survive.
 */
public final class FakeOpaqueNative implements OpaqueNative {

    /** Allocations handed out and not yet freed, by address. */
    private final Map<Long, Memory> allocations = new HashMap<>();

    /** Live state handles, by address, mapped to their kind. */
    private final Map<Long, String> states = new HashMap<>();

    private final List<Long> freed = new ArrayList<>();
    private final Set<String> failing = new HashSet<>();
    private final Map<String, String> failMessages = new HashMap<>();

    private long nextHandle = 0x1000;
    private int ksfAlive;
    private int availableValue = 1;
    private String lastError = "";
    private Memory lastErrorBuffer;

    /**
     * Makes an entry point return {@code null} instead of working.
     *
     * @param entryPoint one of {@code ksf_argon2id}, {@code ksf_scrypt},
     *                   {@code registration_start}, {@code registration_finish},
     *                   {@code login_start}, {@code login_finish}
     */
    public void fail(String entryPoint) {
        failing.add(entryPoint);
    }

    /**
     * Overrides what {@code last_error} reports for a failing entry point.
     *
     * <p>An empty string models a library that failed without saying why — a
     * bug, but one the binding still has to produce a sentence for.
     *
     * @param entryPoint the entry point
     * @param message    the text to report
     */
    public void failMessage(String entryPoint, String message) {
        failMessages.put(entryPoint, message);
    }

    /**
     * Sets what {@code axiam_opaque_available} answers.
     *
     * @param value nonzero for "yes"
     */
    public void setAvailable(int value) {
        this.availableValue = value;
    }

    /**
     * Addresses passed to {@code string_free}, in order. A leak is an
     * allocation that never appears here; a double free appears twice.
     *
     * @return the free log
     */
    public List<Long> freed() {
        return freed;
    }

    /**
     * Key-stretching handles built and not yet released.
     *
     * @return the outstanding count, which must be zero after any {@code finish}
     */
    public int ksfAlive() {
        return ksfAlive;
    }

    /**
     * State handles neither consumed nor released.
     *
     * @return the outstanding count
     */
    public int statesAlive() {
        return states.size();
    }

    /**
     * Allocations handed out and never freed.
     *
     * @return the outstanding count
     */
    public int allocationsAlive() {
        return allocations.size();
    }

    // -- helpers -------------------------------------------------------

    private Pointer allocateHex(String payload) {
        byte[] hex = hex(payload.getBytes(StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
        Memory memory = new Memory(hex.length + 1L);
        memory.write(0, hex, 0, hex.length);
        memory.setByte(hex.length, (byte) 0);
        allocations.put(Pointer.nativeValue(memory), memory);
        return memory;
    }

    private static String hex(byte[] raw) {
        StringBuilder out = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

    private static String read(byte[] nulTerminated) {
        int length = nulTerminated.length;
        while (length > 0 && nulTerminated[length - 1] == 0) {
            length--;
        }
        return new String(nulTerminated, 0, length, StandardCharsets.UTF_8);
    }

    private Pointer newState(String kind) {
        nextHandle += 0x10;
        states.put(nextHandle, kind);
        return new Pointer(nextHandle);
    }

    private void consume(Pointer handle, String kind) {
        long address = Pointer.nativeValue(handle);
        String actual = states.remove(address);
        if (!kind.equals(actual)) {
            throw new AssertionError("handle 0x" + Long.toHexString(address)
                    + " was not a live " + kind + " (was " + actual + ")");
        }
    }

    private boolean failed(String entryPoint, String message) {
        if (!failing.contains(entryPoint)) {
            return false;
        }
        lastError = failMessages.getOrDefault(entryPoint, message);
        return true;
    }

    // -- the ABI -------------------------------------------------------

    @Override
    public void axiam_opaque_string_free(Pointer ptr) {
        long address = Pointer.nativeValue(ptr);
        if (allocations.remove(address) == null) {
            throw new AssertionError("free of 0x" + Long.toHexString(address)
                    + ", which this library never allocated (or already freed)");
        }
        freed.add(address);
    }

    @Override
    public Pointer axiam_opaque_last_error() {
        if (lastError.isEmpty()) {
            return null;
        }
        byte[] raw = lastError.getBytes(StandardCharsets.UTF_8);
        // Borrowed, not freed by the caller -- so it is held here rather than
        // registered as an allocation.
        lastErrorBuffer = new Memory(raw.length + 1L);
        lastErrorBuffer.write(0, raw, 0, raw.length);
        lastErrorBuffer.setByte(raw.length, (byte) 0);
        return lastErrorBuffer;
    }

    @Override
    public int axiam_opaque_available() {
        return availableValue;
    }

    @Override
    public Pointer axiam_opaque_ksf_argon2id(int memoryKib, int iterations, int parallelism) {
        if (failed("ksf_argon2id", "argon2id parameters rejected")) {
            return null;
        }
        ksfAlive++;
        return new Pointer(0xA0000L + memoryKib + iterations + parallelism);
    }

    @Override
    public Pointer axiam_opaque_ksf_scrypt(byte logN, int r, int p) {
        if (failed("ksf_scrypt", "scrypt parameters rejected")) {
            return null;
        }
        ksfAlive++;
        return new Pointer(0xB0000L + logN + r + p);
    }

    @Override
    public void axiam_opaque_ksf_free(Pointer ptr) {
        if (ptr == null) {
            throw new AssertionError("free of a null ksf handle");
        }
        ksfAlive--;
    }

    @Override
    public Pointer axiam_opaque_registration_start(byte[] password, PointerByReference outRequest) {
        if (failed("registration_start", "registration could not be started")) {
            return null;
        }
        outRequest.setValue(allocateHex("req:" + read(password)));
        return newState("registration");
    }

    @Override
    public Pointer axiam_opaque_registration_finish(Pointer state, byte[] password,
                                                    byte[] registrationResponse, Pointer ksf,
                                                    PointerByReference outExportKey) {
        consume(state, "registration");
        if (failed("registration_finish", "the envelope could not be sealed")) {
            return null;
        }
        if (ksf == null) {
            throw new AssertionError("registration_finish called with a null ksf");
        }
        return allocateHex("record:" + read(password) + ":" + read(registrationResponse)
                + ":" + Long.toHexString(Pointer.nativeValue(ksf)));
    }

    @Override
    public void axiam_opaque_registration_free(Pointer ptr) {
        consume(ptr, "registration");
    }

    @Override
    public Pointer axiam_opaque_login_start(byte[] password, PointerByReference outKe1) {
        if (failed("login_start", "login could not be started")) {
            return null;
        }
        outKe1.setValue(allocateHex("ke1:" + read(password)));
        return newState("login");
    }

    @Override
    public Pointer axiam_opaque_login_finish(Pointer state, byte[] password, byte[] ke2,
                                             Pointer ksf, PointerByReference outSessionKey,
                                             PointerByReference outExportKey) {
        consume(state, "login");
        if (failed("login_finish", "the envelope did not open")) {
            return null;
        }
        if (ksf == null) {
            throw new AssertionError("login_finish called with a null ksf");
        }
        return allocateHex("ke3:" + read(password) + ":" + read(ke2)
                + ":" + Long.toHexString(Pointer.nativeValue(ksf)));
    }

    @Override
    public void axiam_opaque_login_free(Pointer ptr) {
        consume(ptr, "login");
    }
}
