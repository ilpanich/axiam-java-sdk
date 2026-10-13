package io.axiam.sdk.examples;

import org.junit.jupiter.api.Test;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * An example that constructs a generated record by its canonical constructor stops compiling
 * the day the record gains a component (CONTRACT.md contract 1.61 added {@code userId} to
 * {@code CreateCertificateRequest}), and nothing else in the build compiles {@code examples/}.
 * This compiles the examples that build such records against the classes under test, so the
 * next model addition fails here rather than in a reader's editor (R161-java-01).
 */
class ExamplesCompileTest {

    private static final List<Path> EXAMPLES = List.of(
            Path.of("examples", "device-mtls-provisioning", "DeviceMtlsProvisioningExample.java"));

    @Test
    void theExamplesThatBuildGeneratedRecordsCompile() throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assumeTrue(compiler != null, "needs a JDK, not a JRE");
        for (Path example : EXAMPLES) {
            assumeTrue(Files.isRegularFile(example), example + " is not next to the build");
        }

        Path out = Files.createTempDirectory("examples-compile");
        try {
            DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
            boolean ok;
            try (StandardJavaFileManager files = compiler.getStandardFileManager(diagnostics, null, null)) {
                ok = compiler.getTask(null, files, diagnostics,
                        List.of("-proc:none", "-d", out.toString(),
                                "-classpath", System.getProperty("java.class.path")),
                        null, files.getJavaFileObjectsFromPaths(EXAMPLES)).call();
            }
            StringBuilder errors = new StringBuilder();
            for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
                if (d.getKind() == Diagnostic.Kind.ERROR) {
                    errors.append(d.getSource() == null ? "" : d.getSource().getName())
                            .append(':').append(d.getLineNumber()).append(": ")
                            .append(d.getMessage(null)).append('\n');
                }
            }
            assertEquals("", errors.toString(), "the examples must compile");
            assertTrue(ok);
        } finally {
            try (var walk = Files.walk(out)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }
}
