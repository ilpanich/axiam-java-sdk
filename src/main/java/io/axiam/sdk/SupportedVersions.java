package io.axiam.sdk;

/**
 * The range of Java versions this SDK is built and tested against.
 *
 * <p>The SDK is <em>compiled</em> against {@link #MIN_JAVA_RELEASE} — the
 * {@code maven.compiler.release} in {@code pom.xml}, which fixes both the
 * bytecode level and the API surface {@code javac} will allow — and
 * additionally <em>run</em> against {@link #NEWEST_TESTED_JAVA}. Those are two
 * different claims, and one JDK cannot make both: compiling to release 21
 * proves nothing about how the result behaves on a JDK 25 runtime, where a
 * removed internal, a changed default, or a strengthened module boundary shows
 * up only at execution.</p>
 *
 * <p>The bytecode level is recorded in the jar's class files and enforced by
 * every JVM that loads them, so the lower bound needs no help. The upper bound
 * has no such enforcement: a class file built for release 21 loads happily on
 * any later JVM whether or not anybody ever ran it there. These constants name
 * the end that nothing else records.</p>
 *
 * <p>{@code VersionPolicyTest} asserts both values against {@code pom.xml} and
 * the CI matrix, so they cannot drift from what is actually built and run.</p>
 *
 * @see <a href="https://github.com/ilpanich/axiam-java-sdk#supported-java-versions">Supported Java versions</a>
 */
public final class SupportedVersions {

    /**
     * The minimum Java feature version required to run this SDK.
     *
     * <p>Mirrors {@code maven.compiler.release} in {@code pom.xml}. A JVM older
     * than this cannot load the SDK's class files at all — it fails with
     * {@code UnsupportedClassVersionError} at link time.</p>
     */
    public static final int MIN_JAVA_RELEASE = 21;

    /**
     * The newest Java feature version this SDK has a green build against.
     *
     * <p>Mirrors the upper leg of the CI matrix, where the release-21 bytecode
     * is executed on a JDK 25 runtime. A newer JVM than this is expected to
     * work, but is not yet proven by a build.</p>
     */
    public static final int NEWEST_TESTED_JAVA = 25;

    private SupportedVersions() {
        throw new AssertionError("no instances");
    }
}
