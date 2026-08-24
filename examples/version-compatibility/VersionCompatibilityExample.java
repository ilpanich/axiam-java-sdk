package io.axiam.sdk.examples.versioncompatibility;

import io.axiam.sdk.SupportedVersions;

/**
 * Reports the running JVM against the range of Java versions this SDK is built
 * and tested against (CONTRACT-independent; this is a packaging concern, not a
 * protocol one). Imports ONLY public SDK entry points.
 *
 * <p>The lower bound needs no help from anyone: the SDK's class files carry a
 * bytecode level, and a JVM older than that refuses to load them with
 * {@code UnsupportedClassVersionError}. The upper bound has no such
 * enforcement — release-21 class files load happily on any later JVM whether or
 * not anybody ever ran them there, and a removed internal, a changed default or
 * a strengthened module boundary surfaces only at execution. This example
 * reports which side of that line the current JVM is on.</p>
 *
 * <p>Useful as a container-image or startup check, particularly where the build
 * JDK and the runtime JDK are chosen by different teams — a jar built against
 * release 21 in CI and deployed onto whatever the base image happens to ship.</p>
 *
 * <p>Run: {@code java VersionCompatibilityExample.java}</p>
 */
public final class VersionCompatibilityExample {

    public static void main(String[] args) {
        int running = Runtime.version().feature();

        System.out.printf("running JVM:        %s (%s %s)%n",
                Runtime.version(),
                System.getProperty("java.vendor"),
                System.getProperty("java.vm.name"));
        System.out.printf("SDK minimum:        Java %d%n", SupportedVersions.MIN_JAVA_RELEASE);
        System.out.printf("newest tested:      Java %d%n", SupportedVersions.NEWEST_TESTED_JAVA);

        if (running < SupportedVersions.MIN_JAVA_RELEASE) {
            // Practically unreachable: this class could not have loaded on such
            // a JVM in the first place. Kept because the check costs nothing and
            // a modular/multi-release layout could make it reachable later.
            System.err.printf(
                    "UNSUPPORTED: Java %d is below the SDK's Java %d floor. The JVM cannot "
                            + "load the SDK's class files.%n",
                    running, SupportedVersions.MIN_JAVA_RELEASE);
            System.exit(1);
        }

        if (running > SupportedVersions.NEWEST_TESTED_JAVA) {
            // Not an error. The SDK targets a fixed bytecode level and the JVM
            // is backward compatible; this runtime simply has no green build.
            System.out.printf(
                    "UNTESTED: Java %d is newer than %d, the newest release this SDK has a "
                            + "green build against. Expected to work, but not yet proven.%n",
                    running, SupportedVersions.NEWEST_TESTED_JAVA);
            return;
        }

        System.out.printf("SUPPORTED: Java %d is inside the tested range.%n", running);

        if (running == SupportedVersions.MIN_JAVA_RELEASE) {
            System.out.printf(
                    "NOTE: Java %d is the oldest release this SDK supports; it is the leg that "
                            + "will be dropped first.%n",
                    SupportedVersions.MIN_JAVA_RELEASE);
        }
    }

    private VersionCompatibilityExample() {
        throw new AssertionError("no instances");
    }
}
