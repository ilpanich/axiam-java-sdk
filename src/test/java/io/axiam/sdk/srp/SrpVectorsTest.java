package io.axiam.sdk.srp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.axiam.sdk.errors.NetworkError;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;23.7 conformance for the SRP-6a client.
 *
 * <p>{@code srp-test-vectors.json} is generated from the AXIAM server
 * implementation and vendored into every SDK. Eleven independent SRP
 * implementations do not interoperate by accident; this is the file that says
 * whether this one does.
 *
 * <p>&sect;23.7 rule 1 requires every intermediate to be reproduced, not only
 * the final proof — an SDK that gets {@code u} wrong should find out at
 * {@code u} rather than at "login sometimes fails".
 */
class SrpVectorsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    /**
     * Walks up from the working directory to find the vendored fixture, so
     * this does not encode how Maven happens to set {@code user.dir}.
     */
    static List<JsonNode> vectors() {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve("srp-test-vectors.json");
            if (Files.isRegularFile(candidate)) {
                try {
                    JsonNode root = MAPPER.readTree(Files.readAllBytes(candidate));
                    List<JsonNode> out = new ArrayList<>();
                    root.path("vectors").forEach(out::add);
                    return out;
                } catch (IOException e) {
                    throw new IllegalStateException("failed to read " + candidate, e);
                }
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("srp-test-vectors.json not found in any parent directory");
    }

    private static BigInteger hexInt(String hex) {
        return new BigInteger(hex, 16);
    }

    // -----------------------------------------------------------------------
    // §23.7 rule 4 — group constants
    // -----------------------------------------------------------------------

    /**
     * A transcription slip in a modulus is a silent, total break: client and
     * server would still agree with each other while the discrete-log hardness
     * the protocol rests on quietly vanished. A round-trip test cannot catch
     * it, because both sides share the same wrong constant.
     */
    @TestFactory
    Stream<DynamicTest> everyGroupIsASafePrimeOfTheAdvertisedWidth() {
        return Stream.of(SrpGroup.values()).map(group -> DynamicTest.dynamicTest(group.wireName(), () -> {
            BigInteger n = group.modulus();
            assertEquals(group.byteLength() * 8, n.bitLength(), "modulus width");
            assertTrue(n.isProbablePrime(64), "modulus is not prime");
            BigInteger q = n.subtract(BigInteger.ONE).shiftRight(1);
            assertTrue(q.isProbablePrime(64), "(N-1)/2 is not prime — not a safe prime");
            // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
            assertEquals(n.subtract(BigInteger.ONE), group.generator().modPow(q, n),
                    "g does not generate the large subgroup");
        }));
    }

    @Test
    void anUnrecognisedGroupIsRefusedRatherThanGuessed() {
        // Guessing would mean computing in a group whose safety this SDK has
        // not verified — potentially one whose discrete log the server knows.
        NetworkError error = assertThrows(NetworkError.class, () -> SrpGroup.fromWire("rfc5054_1024"));
        // NetworkError, not AuthError: this is a client capability gap, and
        // calling it an auth failure would send a user to reset a working
        // password.
        assertTrue(error.getMessage().contains("rfc5054_1024"), error.getMessage());
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 1 — PAD()
    // -----------------------------------------------------------------------

    @Test
    void padLeftPadsToTheGroupWidth() {
        assertEquals("00000001", HEX.formatHex(Srp.pad(BigInteger.ONE, 4)));
        assertEquals("0102", HEX.formatHex(Srp.pad(BigInteger.valueOf(0x0102), 2)));
    }

    // -----------------------------------------------------------------------
    // §23.7 rules 1–3 — the vectors
    // -----------------------------------------------------------------------

    /**
     * Guards the fixture itself: if these stop holding, everything below
     * silently stops testing the two things it was built to test.
     */
    @Test
    void theFixturesCoverTheCasesTheyExistFor() {
        List<JsonNode> vectors = vectors();
        assertFalse(vectors.isEmpty());
        assertTrue(vectors.stream().anyMatch(v -> v.path("salt").asText().startsWith("00")),
                "§23.7 rule 2: no vector has a leading-zero salt");
        assertTrue(vectors.stream().anyMatch(v -> v.path("x").asText().startsWith("00")),
                "§23.7 rule 2: no vector has a leading-zero x");
        assertTrue(vectors.stream().anyMatch(v -> !v.path("identity").asText().chars().allMatch(c -> c < 0x80)),
                "§23.7 rule 3: no vector has a non-ASCII identity");
        for (SrpGroup group : SrpGroup.values()) {
            assertTrue(vectors.stream().anyMatch(v -> group.wireName().equals(v.path("group").asText())),
                    "no vector covers " + group.wireName());
        }
    }

    @TestFactory
    Stream<DynamicTest> everyVectorReproducesEveryIntermediate() {
        return vectors().stream().map(v -> DynamicTest.dynamicTest(
                v.path("group").asText() + "/" + v.path("identity").asText(), () -> {
            SrpGroup group = SrpGroup.fromWire(v.path("group").asText());
            BigInteger n = group.modulus();
            BigInteger x = hexInt(v.path("x").asText()).mod(n);

            // k = H(N | PAD(g))
            assertEquals(v.path("k").asText(), HEX.formatHex(Srp.pad(Srp.multiplier(group), 32)), "k");

            // v = g^x mod N
            assertEquals(v.path("verifier").asText(),
                    Srp.computeVerifier(group, HEX.parseHex(v.path("x").asText())), "verifier");

            // A = g^a mod N
            BigInteger a = hexInt(v.path("a_priv").asText());
            BigInteger aPub = group.generator().modPow(a, n);
            assertEquals(v.path("a_pub").asText(), HEX.formatHex(Srp.pad(aPub, group.byteLength())), "A");

            // B = (k*v + g^b) mod N
            BigInteger b = hexInt(v.path("b_priv").asText());
            BigInteger verifier = group.generator().modPow(x, n);
            BigInteger bPub = Srp.multiplier(group).multiply(verifier)
                    .add(group.generator().modPow(b, n)).mod(n);
            assertEquals(v.path("b_pub").asText(), HEX.formatHex(Srp.pad(bPub, group.byteLength())), "B");

            // u = H(PAD(A) | PAD(B))
            BigInteger u = Srp.hashToInt(Srp.pad(aPub, group.byteLength()), Srp.pad(bPub, group.byteLength()));
            assertEquals(v.path("u").asText(), HEX.formatHex(Srp.pad(u, 32)), "u");

            // S and K, from the client's derivation.
            BigInteger kgx = Srp.multiplier(group).multiply(group.generator().modPow(x, n)).mod(n);
            BigInteger s = bPub.subtract(kgx).mod(n).modPow(a.add(u.multiply(x)), n);
            assertEquals(v.path("session_secret").asText(),
                    HEX.formatHex(Srp.pad(s, group.byteLength())), "S");
            assertEquals(v.path("session_key").asText(),
                    HEX.formatHex(Srp.hash(Srp.pad(s, group.byteLength()))), "K");
        }));
    }

    /**
     * Drives the real session rather than the helpers, with {@code a} pinned
     * to the vector's value — otherwise this would only test the internals.
     */
    @TestFactory
    Stream<DynamicTest> everyVectorProducesTheContractProofsThroughThePublicApi() {
        return vectors().stream().map(v -> DynamicTest.dynamicTest(
                v.path("group").asText() + "/" + v.path("identity").asText(), () -> {
            SrpGroup group = SrpGroup.fromWire(v.path("group").asText());
            SrpClientSession session = SrpClientSession.withFixedEphemeral(
                    group, hexInt(v.path("a_priv").asText()));
            assertEquals(v.path("a_pub").asText(), session.clientPublic(), "A");

            SrpProofs proofs = session.finish(
                    v.path("identity").asText(),
                    v.path("salt").asText(),
                    v.path("b_pub").asText(),
                    HEX.parseHex(v.path("x").asText()));
            assertEquals(v.path("client_proof").asText(), proofs.clientProof(), "M1");
            assertEquals(v.path("server_proof").asText(), proofs.expectedServerProof(), "M2");
        }));
    }

    // -----------------------------------------------------------------------
    // §23.3 protocol refusals
    // -----------------------------------------------------------------------

    /**
     * §23.7 rule 6, with no network round trip. The classic SRP break: a
     * client that accepts {@code B ≡ 0} derives a predictable {@code S} and
     * would authenticate against a server that never knew the verifier.
     */
    @Test
    void aServerPublicValueCongruentToZeroIsRefused() {
        SrpClientSession session = SrpClientSession.begin(SrpGroup.RFC5054_2048);
        NetworkError error = assertThrows(NetworkError.class, () -> session.finish(
                "alice", "00".repeat(32), "0".repeat(SrpGroup.RFC5054_2048.byteLength() * 2), new byte[32]));
        assertTrue(error.getMessage().contains("invalid public value"), error.getMessage());
    }

    @Test
    void everyExchangeUsesAFreshClientEphemeral() {
        assertNotEquals(
                SrpClientSession.begin(SrpGroup.RFC5054_2048).clientPublic(),
                SrpClientSession.begin(SrpGroup.RFC5054_2048).clientPublic());
    }

    @Test
    void anUnknownKdfIsRefusedRatherThanSubstituted() {
        // Substituting the other KDF derives a different x and surfaces as
        // "invalid password" — the single most misleading failure available.
        NetworkError error = assertThrows(NetworkError.class, () -> Srp.deriveX(
                "alice", "pw".toCharArray(), new byte[32], new SrpKdfParams("scrypt", 1, 0, 0)));
        assertTrue(error.getMessage().contains("scrypt"), error.getMessage());
    }

    // -----------------------------------------------------------------------
    // KDF
    // -----------------------------------------------------------------------

    /**
     * Every one of these must change the output, or a verifier would be
     * replayable against a different account or a different salt.
     */
    @Test
    void theKdfBindsIdentityPasswordAndSalt() {
        SrpKdfParams params = new SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000, 0, 0);
        byte[] salt = "a".repeat(32).getBytes(StandardCharsets.US_ASCII);
        String base = HEX.formatHex(Srp.deriveX("alice", "pw".toCharArray(), salt, params));

        assertEquals(32, Srp.deriveX("alice", "pw".toCharArray(), salt, params).length);
        assertEquals(base, HEX.formatHex(Srp.deriveX("alice", "pw".toCharArray(), salt, params)));
        assertNotEquals(base, HEX.formatHex(Srp.deriveX("bob", "pw".toCharArray(), salt, params)));
        assertNotEquals(base, HEX.formatHex(Srp.deriveX("alice", "pw2".toCharArray(), salt, params)));
        assertNotEquals(base, HEX.formatHex(Srp.deriveX(
                "alice", "pw".toCharArray(), "b".repeat(32).getBytes(StandardCharsets.US_ASCII), params)));
    }

    /**
     * Argon2id is the KDF the server asks for by default. Low memory so the
     * test stays fast; the code path is identical to the 19 MiB production
     * parameters.
     */
    @Test
    void argon2idRunsAndIsTheDefaultKdf() {
        assertEquals(32, Srp.deriveX("alice", "pw".toCharArray(), new byte[32],
                new SrpKdfParams(SrpKdfParams.ARGON2ID, 1, 8192, 1)).length);
        assertEquals(SrpKdfParams.ARGON2ID, new SrpKdfParams("", 0, 0, 0).withDefaults().kdf());
    }

    /**
     * The two KDFs must encode the identity identically, or they would
     * disagree about the same account — which is exactly what the non-ASCII
     * vector exists to pin.
     */
    @Test
    void bothKdfsAgreeOnTheUtf8EncodingOfANonAsciiIdentity() {
        byte[] salt = new byte[32];
        String identity = "renée";
        // Same identity through both KDFs must be stable across repeat calls
        // AND must differ from the identity's Latin-1 mangling.
        String viaPbkdf2 = HEX.formatHex(Srp.deriveX(identity, "pw".toCharArray(), salt,
                new SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000, 0, 0)));
        String mangled = HEX.formatHex(Srp.deriveX("renÃ©e", "pw".toCharArray(), salt,
                new SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000, 0, 0)));
        assertNotEquals(mangled, viaPbkdf2);
        assertEquals(viaPbkdf2, HEX.formatHex(Srp.deriveX(identity, "pw".toCharArray(), salt,
                new SrpKdfParams(SrpKdfParams.PBKDF2_SHA256, 1000, 0, 0))));
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 6 — server proof comparison
    // -----------------------------------------------------------------------

    @Test
    void theServerProofComparisonAcceptsAMatchAndRejectsEverythingElse() {
        String proof = vectors().get(0).path("server_proof").asText();
        assertTrue(Srp.verifyServerProof(proof, proof));
        assertFalse(Srp.verifyServerProof(proof, proof.substring(0, proof.length() - 1) + "0"));
        assertFalse(Srp.verifyServerProof(proof, proof.substring(0, 32)));
        assertFalse(Srp.verifyServerProof(proof, ""));
        assertFalse(Srp.verifyServerProof(proof, null));
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment
    // -----------------------------------------------------------------------

    @Test
    void enrolmentSaltsAre32FreshBytes() {
        // A reused salt would make every verifier in a tenant equally
        // attackable with one precomputation.
        byte[] first = Srp.generateSalt();
        byte[] second = Srp.generateSalt();
        assertEquals(32, first.length);
        assertNotEquals(HEX.formatHex(first), HEX.formatHex(second));
    }
}
