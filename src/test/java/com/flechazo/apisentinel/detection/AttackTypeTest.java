package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 攻击类型分类系统单元测试
 *
 * @since 1.2.0
 */
class AttackTypeTest {

    @Test
    void getAll_returnsAllRegisteredTypes() {
        Map<String, AttackType.AttackTypeInfo> all = AttackType.getAll();

        assertNotNull(all);
        assertEquals(28, all.size(), "应注册 28 种攻击类型");
    }

    @Test
    void getAll_isUnmodifiable() {
        Map<String, AttackType.AttackTypeInfo> all = AttackType.getAll();

        assertThrows(UnsupportedOperationException.class, () -> {
            all.put("NEW_TYPE", null);
        });
    }

    @Test
    void get_existingType_returnsInfo() {
        AttackType.AttackTypeInfo info = AttackType.get(AttackType.BOLA);

        assertNotNull(info);
        assertEquals("BOLA", info.id());
        assertEquals("API1:2023", info.owaspMapping());
        assertEquals("CRITICAL", info.severity());
    }

    @Test
    void get_nonExistentType_returnsNull() {
        AttackType.AttackTypeInfo info = AttackType.get("NON_EXISTENT");

        assertNull(info);
    }

    @Test
    void getOwaspApiTop10_returnsExactly10Types() {
        List<String> top10 = AttackType.getOwaspApiTop10();

        assertEquals(10, top10.size());
        assertTrue(top10.contains(AttackType.BOLA));
        assertTrue(top10.contains(AttackType.BROKEN_AUTH));
        assertTrue(top10.contains(AttackType.BOPLA));
        assertTrue(top10.contains(AttackType.RESOURCE_CONSUMPTION));
        assertTrue(top10.contains(AttackType.BROKEN_FUNCTION_AUTH));
        assertTrue(top10.contains(AttackType.SENSITIVE_BUSINESS_FLOW));
        assertTrue(top10.contains(AttackType.SSRF));
        assertTrue(top10.contains(AttackType.SECURITY_MISCONFIG));
        assertTrue(top10.contains(AttackType.IMPROPER_INVENTORY));
        assertTrue(top10.contains(AttackType.UNSAFE_CONSUMPTION));
    }

    @Test
    void getCriticalTypes_returnsOnlyCriticalSeverity() {
        List<String> critical = AttackType.getCriticalTypes();

        assertFalse(critical.isEmpty());
        for (String type : critical) {
            AttackType.AttackTypeInfo info = AttackType.get(type);
            assertEquals("CRITICAL", info.severity(),
                    "类型 " + type + " 应为 CRITICAL 严重性");
        }

        // 验证包含已知的 CRITICAL 类型
        assertTrue(critical.contains(AttackType.BOLA));
        assertTrue(critical.contains(AttackType.BROKEN_AUTH));
        assertTrue(critical.contains(AttackType.SQL_INJECTION));
        assertTrue(critical.contains(AttackType.SSTI));
        assertTrue(critical.contains(AttackType.DESERIALIZATION));
    }

    @Test
    void getBySeverity_filtersCorrectly() {
        List<String> highTypes = AttackType.getBySeverity("HIGH");
        List<String> mediumTypes = AttackType.getBySeverity("MEDIUM");
        List<String> lowTypes = AttackType.getBySeverity("LOW");

        assertFalse(highTypes.isEmpty());
        assertFalse(mediumTypes.isEmpty());
        assertFalse(lowTypes.isEmpty());

        // 验证每个过滤结果的严重性
        for (String type : highTypes) {
            assertEquals("HIGH", AttackType.get(type).severity());
        }
        for (String type : mediumTypes) {
            assertEquals("MEDIUM", AttackType.get(type).severity());
        }
        for (String type : lowTypes) {
            assertEquals("LOW", AttackType.get(type).severity());
        }
    }

    @Test
    void getByTool_findsAssociatedTypes() {
        List<String> types = AttackType.getByTool("HeuristicScanTool");

        assertFalse(types.isEmpty());
        for (String type : types) {
            AttackType.AttackTypeInfo info = AttackType.get(type);
            assertTrue(info.detectors().stream()
                            .anyMatch(d -> d.equalsIgnoreCase("HeuristicScanTool")),
                    "类型 " + type + " 应关联 HeuristicScanTool");
        }
    }

    @Test
    void getByTool_caseInsensitive() {
        List<String> types1 = AttackType.getByTool("heuristicScanTool");
        List<String> types2 = AttackType.getByTool("HEURISTICSCANTOOL");
        List<String> types3 = AttackType.getByTool("HeuristicScanTool");

        assertEquals(types1, types2);
        assertEquals(types2, types3);
    }

    @Test
    void getByTool_nonExistentTool_returnsEmpty() {
        List<String> types = AttackType.getByTool("NonExistentTool");

        assertTrue(types.isEmpty());
    }

    @Test
    void getByPayloadCategory_findsAssociatedTypes() {
        List<String> types = AttackType.getByPayloadCategory("sqli");

        assertFalse(types.isEmpty());
        assertTrue(types.contains(AttackType.SQL_INJECTION));
    }

    @Test
    void getByPayloadCategory_caseInsensitive() {
        List<String> types1 = AttackType.getByPayloadCategory("ssrf");
        List<String> types2 = AttackType.getByPayloadCategory("SSRF");

        assertEquals(types1, types2);
    }

    @Test
    void getByPayloadCategory_nonExistentCategory_returnsEmpty() {
        List<String> types = AttackType.getByPayloadCategory("non-existent-category");

        assertTrue(types.isEmpty());
    }

    @Test
    void attackTypeInfo_hasAllRequiredFields() {
        for (AttackType.AttackTypeInfo info : AttackType.getAll().values()) {
            assertNotNull(info.id(), "id 不应为 null");
            assertNotNull(info.name(), "name 不应为 null");
            assertNotNull(info.description(), "description 不应为 null");
            assertNotNull(info.owaspMapping(), "owaspMapping 不应为 null");
            assertNotNull(info.severity(), "severity 不应为 null");
            assertNotNull(info.detectors(), "detectors 不应为 null");
            assertNotNull(info.payloadCategories(), "payloadCategories 不应为 null");

            assertFalse(info.id().isEmpty(), "id 不应为空");
            assertFalse(info.name().isEmpty(), "name 不应为空");
            assertFalse(info.description().isEmpty(), "description 不应为空");
            assertFalse(info.severity().isEmpty(), "severity 不应为空");
        }
    }

    @Test
    void attackTypeInfo_severityIsValid() {
        List<String> validSeverities = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

        for (AttackType.AttackTypeInfo info : AttackType.getAll().values()) {
            assertTrue(validSeverities.contains(info.severity()),
                    "类型 " + info.id() + " 的严重性 " + info.severity() + " 无效");
        }
    }

    @Test
    void attackTypeInfo_owaspMappingIsValid() {
        for (AttackType.AttackTypeInfo info : AttackType.getAll().values()) {
            String mapping = info.owaspMapping();
            // 要么是 "APIx:2023" 格式，要么是 "-" 表示非 OWASP API Top 10
            boolean validFormat = mapping.equals("-") ||
                    mapping.matches("API\\d+:2023");
            assertTrue(validFormat,
                    "类型 " + info.id() + " 的 OWASP 映射 " + mapping + " 格式无效");
        }
    }

    @Test
    void constants_matchRegistryKeys() {
        Map<String, AttackType.AttackTypeInfo> all = AttackType.getAll();

        // 验证所有常量都在注册表中
        assertTrue(all.containsKey(AttackType.BOLA));
        assertTrue(all.containsKey(AttackType.BROKEN_AUTH));
        assertTrue(all.containsKey(AttackType.BOPLA));
        assertTrue(all.containsKey(AttackType.RESOURCE_CONSUMPTION));
        assertTrue(all.containsKey(AttackType.BROKEN_FUNCTION_AUTH));
        assertTrue(all.containsKey(AttackType.SENSITIVE_BUSINESS_FLOW));
        assertTrue(all.containsKey(AttackType.SSRF));
        assertTrue(all.containsKey(AttackType.SECURITY_MISCONFIG));
        assertTrue(all.containsKey(AttackType.IMPROPER_INVENTORY));
        assertTrue(all.containsKey(AttackType.UNSAFE_CONSUMPTION));
        assertTrue(all.containsKey(AttackType.SQL_INJECTION));
        assertTrue(all.containsKey(AttackType.NOSQL_INJECTION));
        assertTrue(all.containsKey(AttackType.XSS));
        assertTrue(all.containsKey(AttackType.CSRF));
        assertTrue(all.containsKey(AttackType.PATH_TRAVERSAL));
        assertTrue(all.containsKey(AttackType.SSTI));
        assertTrue(all.containsKey(AttackType.XXE));
        assertTrue(all.containsKey(AttackType.DESERIALIZATION));
        assertTrue(all.containsKey(AttackType.OPEN_REDIRECT));
        assertTrue(all.containsKey(AttackType.REQUEST_SMUGGLING));
        assertTrue(all.containsKey(AttackType.GRAPHQL));
        assertTrue(all.containsKey(AttackType.FILE_UPLOAD));
        assertTrue(all.containsKey(AttackType.INFO_DISCLOSURE));
        assertTrue(all.containsKey(AttackType.WAF_BYPASS));
        assertTrue(all.containsKey(AttackType.BUSINESS_LOGIC));
        assertTrue(all.containsKey(AttackType.MASS_ASSIGNMENT));
        assertTrue(all.containsKey(AttackType.EXCESSIVE_DATA));
        assertTrue(all.containsKey(AttackType.INJECTION));
    }

    @Test
    void owaspTop10Types_haveCorrectMapping() {
        assertEquals("API1:2023", AttackType.get(AttackType.BOLA).owaspMapping());
        assertEquals("API2:2023", AttackType.get(AttackType.BROKEN_AUTH).owaspMapping());
        assertEquals("API3:2023", AttackType.get(AttackType.BOPLA).owaspMapping());
        assertEquals("API4:2023", AttackType.get(AttackType.RESOURCE_CONSUMPTION).owaspMapping());
        assertEquals("API5:2023", AttackType.get(AttackType.BROKEN_FUNCTION_AUTH).owaspMapping());
        assertEquals("API6:2023", AttackType.get(AttackType.SENSITIVE_BUSINESS_FLOW).owaspMapping());
        assertEquals("API7:2023", AttackType.get(AttackType.SSRF).owaspMapping());
        assertEquals("API8:2023", AttackType.get(AttackType.SECURITY_MISCONFIG).owaspMapping());
        assertEquals("API9:2023", AttackType.get(AttackType.IMPROPER_INVENTORY).owaspMapping());
        assertEquals("API10:2023", AttackType.get(AttackType.UNSAFE_CONSUMPTION).owaspMapping());
    }

    @Test
    void traditionalWebVulns_haveDashMapping() {
        // 传统 Web 漏洞不属于 OWASP API Top 10，映射为 "-"
        assertEquals("-", AttackType.get(AttackType.SQL_INJECTION).owaspMapping());
        assertEquals("-", AttackType.get(AttackType.XSS).owaspMapping());
        assertEquals("-", AttackType.get(AttackType.CSRF).owaspMapping());
        assertEquals("-", AttackType.get(AttackType.PATH_TRAVERSAL).owaspMapping());
    }

    @Test
    void bola_hasExpectedDetectorsAndCategories() {
        AttackType.AttackTypeInfo bola = AttackType.get(AttackType.BOLA);

        assertTrue(bola.detectors().contains("MineHistoryIdorTool"));
        assertTrue(bola.payloadCategories().contains("bola"));
        assertTrue(bola.payloadCategories().contains("idor"));
    }

    @Test
    void sqlInjection_hasExpectedDetectorsAndCategories() {
        AttackType.AttackTypeInfo sqli = AttackType.get(AttackType.SQL_INJECTION);

        assertTrue(sqli.detectors().contains("HeuristicScanTool"));
        assertTrue(sqli.detectors().contains("ActiveProbeTool"));
        assertTrue(sqli.payloadCategories().contains("sqli"));
    }
}
