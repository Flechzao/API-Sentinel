package com.flechazo.apisentinel.poc;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ProofOfConcept record 单元测试
 *
 * @since 1.2.0
 */
class ProofOfConceptTest {

    private ProofOfConcept createSamplePoC() {
        return new ProofOfConcept(
                "SQL Injection",
                "CRITICAL",
                "SQL Injection in /api/users",
                "The endpoint is vulnerable to SQL injection via the 'id' parameter",
                "curl 'http://target/api/users?id=1%27%20OR%20%271%27=%271'",
                "import requests\nr = requests.get('http://target/api/users', params={'id': \"1' OR '1'='1\"})\nprint(r.text)",
                List.of(
                        "Identify the parameter 'id' in /api/users",
                        "Send request with payload: 1' OR '1'='1",
                        "Observe the response contains all users",
                        "Verify the injected condition evaluates to true",
                        "Confirm data extraction is possible",
                        "Document the impact"
                ),
                "Attacker can extract entire database contents",
                "/api/users",
                "1' OR '1'='1",
                "Response contains 150 user records instead of 1",
                "Use parameterized queries instead of string concatenation",
                95
        );
    }

    @Test
    void constructor_setsAllFields() {
        ProofOfConcept poc = createSamplePoC();

        assertEquals("SQL Injection", poc.vulnType());
        assertEquals("CRITICAL", poc.severity());
        assertEquals("SQL Injection in /api/users", poc.title());
        assertNotNull(poc.description());
        assertNotNull(poc.curlCommand());
        assertNotNull(poc.pythonScript());
        assertEquals(6, poc.steps().size());
        assertNotNull(poc.impact());
        assertEquals("/api/users", poc.affectedEndpoint());
        assertNotNull(poc.payload());
        assertNotNull(poc.evidence());
        assertNotNull(poc.remediation());
        assertEquals(95, poc.confidence());
    }

    @Test
    void toJson_containsAllFields() {
        ProofOfConcept poc = createSamplePoC();
        JsonObject json = poc.toJson();

        assertEquals("SQL Injection", json.get("vuln_type").getAsString());
        assertEquals("CRITICAL", json.get("severity").getAsString());
        assertTrue(json.has("title"));
        assertTrue(json.has("description"));
        assertTrue(json.has("curl_command"));
        assertTrue(json.has("python_script"));
        assertTrue(json.has("steps"));
        assertTrue(json.has("impact"));
        assertTrue(json.has("affected_endpoint"));
        assertTrue(json.has("payload"));
        assertTrue(json.has("evidence"));
        assertTrue(json.has("remediation"));
        assertEquals(95, json.get("confidence").getAsInt());
    }

    @Test
    void toJson_stepsArrayHasCorrectSize() {
        ProofOfConcept poc = createSamplePoC();
        JsonObject json = poc.toJson();

        assertEquals(6, json.getAsJsonArray("steps").size());
    }

    @Test
    void toJson_nullStepsReturnsEmptyArray() {
        ProofOfConcept poc = new ProofOfConcept(
                "XSS", "HIGH", "XSS Test", "desc",
                "curl cmd", "script", null, "impact", "/api", "payload", "evidence", "fix", 80
        );
        JsonObject json = poc.toJson();

        assertNotNull(json.getAsJsonArray("steps"));
        assertEquals(0, json.getAsJsonArray("steps").size());
    }

    @Test
    void toMarkdown_containsTitle() {
        ProofOfConcept poc = createSamplePoC();
        String md = poc.toMarkdown();

        assertTrue(md.contains("# PoC: SQL Injection in /api/users"));
    }

    @Test
    void toMarkdown_containsMetadata() {
        ProofOfConcept poc = createSamplePoC();
        String md = poc.toMarkdown();

        assertTrue(md.contains("**漏洞类型**: SQL Injection"));
        assertTrue(md.contains("**严重性**: CRITICAL"));
        assertTrue(md.contains("**置信度**: 95/100"));
        assertTrue(md.contains("**受影响端点**: `/api/users`"));
    }

    @Test
    void toMarkdown_containsAllSections() {
        ProofOfConcept poc = createSamplePoC();
        String md = poc.toMarkdown();

        assertTrue(md.contains("## 描述"));
        assertTrue(md.contains("## 影响"));
        assertTrue(md.contains("## 复现步骤"));
        assertTrue(md.contains("## cURL 命令"));
        assertTrue(md.contains("## Python 脚本"));
        assertTrue(md.contains("## Payload"));
        assertTrue(md.contains("## 证据"));
        assertTrue(md.contains("## 修复建议"));
    }

    @Test
    void toMarkdown_containsStepsNumbered() {
        ProofOfConcept poc = createSamplePoC();
        String md = poc.toMarkdown();

        assertTrue(md.contains("1. Identify the parameter"));
        assertTrue(md.contains("2. Send request with payload"));
        assertTrue(md.contains("3. Observe the response"));
    }

    @Test
    void toMarkdown_containsCodeBlocks() {
        ProofOfConcept poc = createSamplePoC();
        String md = poc.toMarkdown();

        assertTrue(md.contains("```bash\n"));
        assertTrue(md.contains("```python\n"));
    }

    @Test
    void toMarkdown_nullCurlOmitsSection() {
        ProofOfConcept poc = new ProofOfConcept(
                "XSS", "HIGH", "Test", "desc",
                null, "script", List.of("step1"), "impact", "/api", "payload", "evidence", "fix", 80
        );
        String md = poc.toMarkdown();

        assertFalse(md.contains("## cURL 命令"));
    }

    @Test
    void toMarkdown_nullPythonOmitsSection() {
        ProofOfConcept poc = new ProofOfConcept(
                "XSS", "HIGH", "Test", "desc",
                "curl", null, List.of("step1"), "impact", "/api", "payload", "evidence", "fix", 80
        );
        String md = poc.toMarkdown();

        assertFalse(md.contains("## Python 脚本"));
    }

    @Test
    void toMarkdown_emptyStepsOmitsSection() {
        ProofOfConcept poc = new ProofOfConcept(
                "XSS", "HIGH", "Test", "desc",
                "curl", "script", List.of(), "impact", "/api", "payload", "evidence", "fix", 80
        );
        String md = poc.toMarkdown();

        assertFalse(md.contains("## 复现步骤"));
    }

    @Test
    void toMarkdown_longEvidenceTruncated() {
        String longEvidence = "A".repeat(600);
        ProofOfConcept poc = new ProofOfConcept(
                "XSS", "HIGH", "Test", "desc",
                "curl", "script", List.of("step"), "impact", "/api", "payload", longEvidence, "fix", 80
        );
        String md = poc.toMarkdown();

        assertTrue(md.contains("..."), "超长证据应被截断并显示 ...");
        assertFalse(md.contains("A".repeat(600)), "不应包含完整的超长证据");
    }

    @Test
    void toMarkdown_shortEvidenceNotTruncated() {
        String shortEvidence = "Response: 1' OR '1'='1";
        ProofOfConcept poc = new ProofOfConcept(
                "SQLi", "HIGH", "Test", "desc",
                "curl", "script", List.of("step"), "impact", "/api", "payload", shortEvidence, "fix", 80
        );
        String md = poc.toMarkdown();

        assertTrue(md.contains(shortEvidence), "短证据不应被截断");
    }

    @Test
    void record_equalityWorks() {
        ProofOfConcept poc1 = createSamplePoC();
        ProofOfConcept poc2 = createSamplePoC();

        assertEquals(poc1, poc2);
        assertEquals(poc1.hashCode(), poc2.hashCode());
    }

    @Test
    void record_differentValuesNotEqual() {
        ProofOfConcept poc1 = createSamplePoC();
        ProofOfConcept poc2 = new ProofOfConcept(
                "XSS", "HIGH", "Different", "desc",
                "curl", "script", List.of("step"), "impact", "/api", "payload", "evidence", "fix", 80
        );

        assertNotEquals(poc1, poc2);
    }

    @Test
    void confidence_zeroIsValid() {
        ProofOfConcept poc = new ProofOfConcept(
                "XSS", "LOW", "Test", "desc",
                "curl", "script", List.of("step"), "impact", "/api", "payload", "evidence", "fix", 0
        );

        assertEquals(0, poc.confidence());
    }

    @Test
    void confidence_hundredIsValid() {
        ProofOfConcept poc = new ProofOfConcept(
                "SQLi", "CRITICAL", "Test", "desc",
                "curl", "script", List.of("step"), "impact", "/api", "payload", "evidence", "fix", 100
        );

        assertEquals(100, poc.confidence());
    }

    @Test
    void toJson_handlesNullFields() {
        ProofOfConcept poc = new ProofOfConcept(
                null, null, null, null,
                null, null, null, null, null, null, null, null, 0
        );
        JsonObject json = poc.toJson();

        // JSON should still have all keys, just with null values
        assertTrue(json.has("vuln_type"));
        assertTrue(json.has("severity"));
        assertTrue(json.has("title"));
    }

    @Test
    void toMarkdown_handlesNullFields() {
        ProofOfConcept poc = new ProofOfConcept(
                "Type", "HIGH", "Title", null,
                null, null, null, null, "/api", null, null, null, 50
        );
        String md = poc.toMarkdown();

        // Should not throw, should produce valid markdown
        assertNotNull(md);
        assertTrue(md.contains("# PoC: Title"));
    }
}
