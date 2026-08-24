package io.axiam.sdk;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Language-version support policy.
 *
 * <p>"Which Java does this SDK support?" is declared in three places that
 * nothing compares:</p>
 *
 * <ol>
 *   <li>{@code maven.compiler.release} in {@code pom.xml} — the bytecode level
 *       written into every class file, enforced by every JVM that loads them;</li>
 *   <li>the {@code java} matrix in {@code .github/workflows/sdk-ci-java.yml} —
 *       the only one that is ever <em>executed</em>;</li>
 *   <li>{@link SupportedVersions} — the only one a consumer can read.</li>
 * </ol>
 *
 * <p>Before this test existed CI ran one JDK, 21, matching the release level.
 * That agreed with itself and proved only half of what the SDK claims. The
 * bytecode level is self-enforcing downward — an older JVM fails with
 * {@code UnsupportedClassVersionError} and nobody is confused — but there is no
 * such enforcement upward: release-21 class files load happily on JDK 25
 * whether or not anyone ever ran them there, and a removed internal or a
 * strengthened module boundary surfaces only at execution.</p>
 *
 * <p>The policy pinned here is floor + newest, and the newest leg is the one
 * that carries the claim: it compiles to release 21 with JDK 25's compiler and
 * then runs the result on JDK 25.</p>
 */
class VersionPolicyTest {

    /** {@code <maven.compiler.release>21</maven.compiler.release>} in pom.xml. */
    private static final Pattern RELEASE =
            Pattern.compile("<maven\\.compiler\\.release>(\\d+)</maven\\.compiler\\.release>");

    /** {@code java: ['21', '25']} in the CI test matrix. */
    private static final Pattern CI_MATRIX =
            Pattern.compile("(?m)^\\s*java:\\s*\\[([^\\]]*)\\]\\s*$");

    /**
     * Locates the repository root by walking up from the working directory
     * until {@code pom.xml} is found. Surefire runs with the module directory
     * as the working directory, so this normally succeeds immediately.
     */
    private static Path repoRoot() {
        Path dir = Paths.get("").toAbsolutePath();
        while (dir != null) {
            if (Files.exists(dir.resolve("pom.xml"))
                    && Files.exists(dir.resolve(".github").resolve("workflows"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException(
                "could not locate the repository root from " + Paths.get("").toAbsolutePath());
    }

    private static String read(Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    /** The compiler release level declared in pom.xml. */
    private static int declaredRelease() throws IOException {
        Matcher m = RELEASE.matcher(read(repoRoot().resolve("pom.xml")));
        assertTrue(m.find(), "pom.xml declares no <maven.compiler.release>");
        return Integer.parseInt(m.group(1));
    }

    /** The JDK feature versions the gating CI job runs, ascending. */
    private static List<Integer> ciMatrix() throws IOException {
        String yaml = read(repoRoot().resolve(".github/workflows/sdk-ci-java.yml"));
        Matcher m = CI_MATRIX.matcher(yaml);

        List<String> found = new ArrayList<>();
        while (m.find()) {
            found.add(m.group(1));
        }
        assertEquals(1, found.size(),
                "expected exactly one `java:` matrix in sdk-ci-java.yml; a second would "
                        + "mean this test only checks one of them");

        List<Integer> versions = new ArrayList<>();
        for (String entry : found.get(0).split(",")) {
            String cleaned = entry.trim().replaceAll("^['\"]|['\"]$", "");
            if (!cleaned.isEmpty()) {
                versions.add(Integer.parseInt(cleaned));
            }
        }
        versions.sort(Integer::compareTo);
        return versions;
    }

    /**
     * The exported constant matches the bytecode level actually emitted.
     *
     * <p>It is the only part of the floor a consumer can read, so a stale value
     * is worse than none: a preflight built on it would report a minimum the
     * class files do not enforce.</p>
     */
    @Test
    void minJavaReleaseConstantMatchesPom() throws IOException {
        assertEquals(declaredRelease(), SupportedVersions.MIN_JAVA_RELEASE,
                "SupportedVersions.MIN_JAVA_RELEASE has drifted from maven.compiler.release");
    }

    /** The exported upper bound matches the newest JDK CI actually runs. */
    @Test
    void newestTestedConstantMatchesTopCiLeg() throws IOException {
        List<Integer> matrix = ciMatrix();
        assertEquals(matrix.get(matrix.size() - 1), SupportedVersions.NEWEST_TESTED_JAVA,
                "SupportedVersions.NEWEST_TESTED_JAVA claims a JDK that CI does not run");
    }

    /**
     * CI runs the floor, so the declared minimum is a JVM something executes on.
     *
     * <p>Compiling to release 21 is not the same as running on 21: the release
     * flag constrains the API surface {@code javac} accepts, but a reflective
     * lookup or a service-loader path that only exists on a newer JDK compiles
     * clean and fails at runtime.</p>
     */
    @Test
    void ciRunsTheDeclaredFloor() throws IOException {
        int floor = declaredRelease();
        assertTrue(ciMatrix().contains(floor),
                "pom.xml compiles to release " + floor + " but no CI leg runs that JDK");
    }

    /**
     * The gating matrix is exactly the two ends of the range.
     *
     * <p>Dropping the newest leg is the failure this whole class exists to
     * prevent: it is the only thing proving the SDK's bytecode actually runs on
     * a current JVM, and nothing else in the build would notice its absence.</p>
     */
    @Test
    void ciMatrixIsFloorAndNewest() throws IOException {
        List<Integer> matrix = ciMatrix();
        assertEquals(2, matrix.size(),
                "expected exactly 2 CI legs (floor + newest), got " + matrix);
        assertEquals(declaredRelease(), (int) matrix.get(0),
                "the lowest CI leg is not the declared release level");
        assertTrue(matrix.get(1) > matrix.get(0),
                "the newest CI leg must be newer than the floor, got " + matrix);
    }

    /** No CI leg runs a JVM too old to load the SDK's class files. */
    @Test
    void ciNeverRunsBelowTheFloor() throws IOException {
        int floor = declaredRelease();
        for (int version : ciMatrix()) {
            assertTrue(version >= floor,
                    "CI runs JDK " + version + ", below the release-" + floor + " floor — "
                            + "that JVM cannot load the SDK at all");
        }
    }

    /**
     * {@link SupportedVersions} is a constant holder, not a value type.
     *
     * <p>Asserted rather than assumed because the guard is easy to lose in a
     * refactor and silently harmless-looking when it goes: the class would
     * still work, it would just start showing up in consumers' code as
     * something instantiable that carries no state.</p>
     */
    @Test
    void supportedVersionsIsNotInstantiable() throws ReflectiveOperationException {
        Constructor<SupportedVersions> ctor = SupportedVersions.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(ctor.getModifiers()),
                "SupportedVersions' constructor should be private");

        ctor.setAccessible(true);
        InvocationTargetException thrown = org.junit.jupiter.api.Assertions.assertThrows(
                InvocationTargetException.class, ctor::newInstance);
        assertInstanceOf(AssertionError.class, thrown.getCause());
    }

    /**
     * The JVM running this suite is inside the declared range.
     *
     * <p>{@code mvn test} runs on each matrix leg, so this executes on both and
     * closes the loop from the running side.</p>
     */
    @Test
    void runningJvmIsInsideTheDeclaredRange() {
        int running = Runtime.version().feature();
        assertTrue(running >= SupportedVersions.MIN_JAVA_RELEASE,
                "tests are running on JDK " + running + ", below the declared floor "
                        + SupportedVersions.MIN_JAVA_RELEASE);
        assertTrue(running <= SupportedVersions.NEWEST_TESTED_JAVA,
                "tests are running on JDK " + running + ", above the newest declared "
                        + SupportedVersions.NEWEST_TESTED_JAVA + " — add the CI leg and "
                        + "raise SupportedVersions.NEWEST_TESTED_JAVA");
    }
}
