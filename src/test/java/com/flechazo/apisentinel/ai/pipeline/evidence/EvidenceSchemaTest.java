package com.flechazo.apisentinel.ai.pipeline.evidence;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.flechazo.apisentinel.ai.pipeline.evidence.EvidenceField.*;
import static org.junit.jupiter.api.Assertions.*;

class EvidenceSchemaTest {

    @Test
    void normalize_mapsCommonAliases() {
        assertEquals("SQL_INJECTION", EvidenceSchema.normalize("SQLi"));
        assertEquals("SQL_INJECTION", EvidenceSchema.normalize("SQL 注入"));
        assertEquals("SQL_INJECTION", EvidenceSchema.normalize("sql_injection"));
        assertEquals("IDOR", EvidenceSchema.normalize("IDOR"));
        assertEquals("IDOR", EvidenceSchema.normalize("越权访问"));
        assertEquals("IDOR", EvidenceSchema.normalize("Broken Access Control"));
        assertEquals("SSRF", EvidenceSchema.normalize("ssrf"));
        assertEquals("XSS", EvidenceSchema.normalize("Reflected XSS"));
        assertEquals("COMMAND_INJECTION", EvidenceSchema.normalize("OS Command Injection"));
    }

    @Test
    void normalize_unknownTypeReturnsNull() {
        assertNull(EvidenceSchema.normalize("CSRF"));
        assertNull(EvidenceSchema.normalize("Open Redirect"));
        assertNull(EvidenceSchema.normalize(null));
    }

    @Test
    void missingRequired_idorMissingIdentityProof_reported() {
        Set<EvidenceField> submitted = EnumSet.of(SESSION_A_RESPONSE, SESSION_B_RESPONSE, ANONYMOUS_RESPONSE);
        List<EvidenceField> missing = EvidenceSchema.missingRequired("IDOR", submitted);
        assertEquals(List.of(IDENTITY_PROOF), missing);
    }

    @Test
    void missingRequired_idorComplete_empty() {
        Set<EvidenceField> submitted = EnumSet.of(SESSION_A_RESPONSE, SESSION_B_RESPONSE,
                ANONYMOUS_RESPONSE, IDENTITY_PROOF);
        assertTrue(EvidenceSchema.missingRequired("IDOR", submitted).isEmpty());
    }

    @Test
    void missingRequired_sqliMissingBaseline_reported() {
        Set<EvidenceField> submitted = EnumSet.of(INJECTED_RESPONSE, RESPONSE_DIFF, PAYLOAD_USED);
        assertEquals(List.of(BASELINE_RESPONSE), EvidenceSchema.missingRequired("SQLi", submitted));
    }

    @Test
    void missingRequired_uncoveredType_failsOpen() {
        // CSRF has no registered schema → never gated, even with no evidence.
        assertTrue(EvidenceSchema.missingRequired("CSRF", EnumSet.noneOf(EvidenceField.class)).isEmpty());
    }

    @Test
    void missingRequired_nullSubmitted_returnsAllRequired() {
        List<EvidenceField> missing = EvidenceSchema.missingRequired("SSRF", null);
        assertEquals(List.of(PAYLOAD_USED, INJECTED_RESPONSE, INTERNAL_INDICATOR), missing);
    }

    @Test
    void fromKey_roundTrips() {
        for (EvidenceField f : EvidenceField.values()) {
            assertEquals(f, EvidenceField.fromKey(f.key()));
        }
        assertNull(EvidenceField.fromKey("nonexistent_slot"));
        assertNull(EvidenceField.fromKey(null));
    }

    @Test
    void describe_joinsKeys() {
        assertEquals("baseline_response, payload_used",
                EvidenceSchema.describe(List.of(BASELINE_RESPONSE, PAYLOAD_USED)));
    }
}
