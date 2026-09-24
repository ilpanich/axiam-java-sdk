package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.axiam.sdk.management.models.CertificateType;
import io.axiam.sdk.management.models.RoleUserAssignment;
import io.axiam.sdk.management.models.SubjectAltName;
import io.axiam.sdk.management.models.SubjectAltNameDns;
import io.axiam.sdk.management.models.SubjectAltNameIp;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;27.13 (contract 1.51) — the two generator defects C-1's EXECUTED
 * item 2 found and fixed, pinned here so a regenerated surface cannot reintroduce them.
 */
class Contract151ModelsTest {

    private static final ObjectMapper JSON = new ObjectMapper().registerModule(new JavaTimeModule());

    // ------------------------------------------------------------------
    // S-7: SubjectAltName is an externally tagged oneOf — {"dns": …} / {"ip": …},
    // never {}.
    // ------------------------------------------------------------------

    @Test
    void dnsSerializesAsExternallyTaggedNeverAsAnEmptyObject() throws Exception {
        SubjectAltName san = new SubjectAltNameDns("api.example.internal");
        String wire = JSON.writeValueAsString(san);
        assertEquals("{\"dns\":\"api.example.internal\"}", wire);
    }

    @Test
    void ipSerializesAsExternallyTagged() throws Exception {
        SubjectAltName san = new SubjectAltNameIp("10.0.0.5");
        String wire = JSON.writeValueAsString(san);
        assertEquals("{\"ip\":\"10.0.0.5\"}", wire);
    }

    @Test
    void dnsRoundTripsThroughDeserialization() throws Exception {
        SubjectAltName san = JSON.readValue("{\"dns\":\"*.example.internal\"}", SubjectAltName.class);
        assertInstanceOf(SubjectAltNameDns.class, san);
        assertEquals("*.example.internal", ((SubjectAltNameDns) san).dns());
    }

    @Test
    void ipRoundTripsThroughDeserialization() throws Exception {
        SubjectAltName san = JSON.readValue("{\"ip\":\"192.0.2.1\"}", SubjectAltName.class);
        assertInstanceOf(SubjectAltNameIp.class, san);
        assertEquals("192.0.2.1", ((SubjectAltNameIp) san).ip());
    }

    @Test
    void anEmptyObjectRefusesToDeserialize() {
        assertTrue(assertThrowsIoException(() -> JSON.readValue("{}", SubjectAltName.class))
                .getMessage().contains("names none of the permitted keys"));
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static java.io.IOException assertThrowsIoException(ThrowingRunnable r) {
        try {
            r.run();
        } catch (java.io.IOException e) {
            return e;
        } catch (Exception e) {
            throw new AssertionError("expected IOException, got " + e, e);
        }
        throw new AssertionError("expected IOException, nothing was thrown");
    }

    // ------------------------------------------------------------------
    // S-10: a required `inherit` on the three role-side listings decodes a
    // pre-1.51 server's omission as true, never fails, never reads as false.
    // ------------------------------------------------------------------

    @Test
    void inheritOmittedByAPre151ServerDecodesAsTrueNotFalse() throws Exception {
        String wire = "{\"user\":" + minimalUser() + ",\"resource_id\":null}"; // no "inherit" key at all
        RoleUserAssignment assignment = JSON.readValue(wire, RoleUserAssignment.class);

        assertEquals(null, assignment.inherit(), "the raw field stays null — it was never sent");
        assertTrue(assignment.inherits(),
                "§27.13 S-10 rule 3: absence means true, and a bare `boolean` that silently "
                        + "reads absence as false is the exact defect this accessor exists to avoid");
    }

    @Test
    void inheritStatedFalseDecodesAsFalse() throws Exception {
        String wire = "{\"user\":" + minimalUser() + ",\"resource_id\":null,\"inherit\":false}";
        RoleUserAssignment assignment = JSON.readValue(wire, RoleUserAssignment.class);
        assertEquals(Boolean.FALSE, assignment.inherit());
        assertEquals(false, assignment.inherits());
    }

    @Test
    void inheritStatedTrueDecodesAsTrue() throws Exception {
        String wire = "{\"user\":" + minimalUser() + ",\"resource_id\":null,\"inherit\":true}";
        RoleUserAssignment assignment = JSON.readValue(wire, RoleUserAssignment.class);
        assertTrue(assignment.inherits());
    }

    private static String minimalUser() {
        return "{\"created_at\":\"2026-08-26T00:00:00Z\",\"email\":\"u@example.test\","
                + "\"email_verified\":true,\"failed_login_attempts\":0,\"id\":\""
                + UUID.randomUUID() + "\",\"is_locked\":false,\"metadata\":{},\"mfa_enabled\":false,"
                + "\"status\":\"Active\",\"tenant_id\":\"" + UUID.randomUUID()
                + "\",\"updated_at\":\"2026-08-26T00:00:00Z\",\"username\":\"u\"}";
    }

    // ------------------------------------------------------------------
    // S-7 rule 2: an unrecognised CertificateType (e.g. a future value) decodes
    // openly rather than failing the whole response — already correct (needed a
    // test, not a fix), pinned here alongside its two 1.51 siblings.
    // ------------------------------------------------------------------

    @Test
    void serverCertificateTypeDecodesOpenlyAsAKnownConstant() {
        assertEquals(CertificateType.SERVER, CertificateType.fromWire("Server"));
    }

    @Test
    void anUnrecognisedCertificateTypeDecodesAsUnknownRatherThanFailing() {
        assertEquals(CertificateType.UNKNOWN, CertificateType.fromWire("SomeFutureType"));
    }
}
