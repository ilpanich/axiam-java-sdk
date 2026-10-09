package io.axiam.sdk.management;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The generated call-site documentation says what the types do (CONTRACT.md &sect;27.4 rule 5,
 * &sect;31.3 rule 2; contract 1.59 R-28, R-29). Read from the committed sources, which
 * {@code scripts/gen_management.py --check} keeps equal to the generator's output, so a
 * template that drifts back fails here.
 */
class GeneratedDocumentationTest {

    private static final Path API = Path.of("src/main/java/io/axiam/sdk/management");
    private static final Path MODELS = API.resolve("models");

    /** Each generated method's Javadoc, keyed by the method's declaration line. */
    private static List<String[]> methodDocs(Path file) throws IOException {
        String source = Files.readString(file);
        Matcher m = Pattern.compile("/\\*\\*(.*?)\\*/\\s*\\n\\s*(public [^\\n]*\\()", Pattern.DOTALL).matcher(source);
        List<String[]> out = new ArrayList<>();
        while (m.find()) {
            String declaration = source.substring(m.start(2), source.indexOf('{', m.start(2)));
            out.add(new String[] {m.group(1).replaceAll("\\s*\\n\\s*\\*\\s?", " "), declaration});
        }
        return out;
    }

    private static List<Path> apis() throws IOException {
        try (Stream<Path> files = Files.list(API)) {
            return files.filter(p -> p.getFileName().toString().endsWith("Api.java")).sorted().toList();
        }
    }

    /**
     * R-28 (F-J11): "Every field of the body is required" appears only where it is true &mdash;
     * on a replacement whose body has no optional member.
     */
    @Test
    void aReplacementSaysEveryFieldIsRequiredOnlyWhenEveryFieldIs() throws IOException {
        int replacements = 0;
        for (Path api : apis()) {
            for (String[] doc : methodDocs(api)) {
                if (!doc[0].contains("This is a REPLACEMENT")) {
                    continue;
                }
                replacements++;
                Matcher body = Pattern.compile("\\b(\\w+) body\\)").matcher(doc[1]);
                assertTrue(body.find(), doc[1]);
                boolean optional = Files.readString(MODELS.resolve(body.group(1) + ".java")).contains("@Nullable");
                if (optional) {
                    assertTrue(!doc[0].contains("Every field of the body is required"),
                            api.getFileName() + " " + doc[1] + ": " + body.group(1) + " has optional members");
                    assertTrue(doc[0].contains("takes its default"), doc[1]);
                }
            }
        }
        assertEquals(8, replacements, "every replace-style operation was read");
    }

    /**
     * R-28: a body that is not a sparse update is not called one. "Left unchanged" is what a
     * sparse <em>update</em> does; {@code parse_sp_metadata} stores nothing.
     */
    @Test
    void onlyASparseUpdateBodySaysWhatIsLeftNullIsLeftUnchanged() throws IOException {
        String parse = Files.readString(MODELS.resolve("ParseSamlSpMetadata.java"));
        assertTrue(!parse.contains("left unchanged"), "ParseSamlSpMetadata is not an update");
        assertTrue(Files.readString(MODELS.resolve("UpdateDirectoryConfig.java")).contains("left unchanged"));
        try (Stream<Path> files = Files.list(MODELS)) {
            for (Path model : files.toList()) {
                assertTrue(!Files.readString(model).contains("six nulls"), model + " counts components wrongly");
            }
        }
    }

    /** R-29 (F-J12): &sect;31.3 rule 2 is documented at both call sites, create included. */
    @Test
    void theCredentialUrlBindingIsDocumentedAtBothScimTargetCallSites() throws IOException {
        for (String[] doc : methodDocs(API.resolve("ScimTargetsApi.java"))) {
            if (doc[1].contains(" create(") || doc[1].contains(" update(")) {
                assertTrue(doc[0].contains("The credential is bound to its URL"), doc[1]);
                assertTrue(doc[0].contains("§31.3 rule 2"), doc[1]);
            }
        }
    }
}
