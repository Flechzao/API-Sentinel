package com.flechazo.apisentinel.detection.template;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DetectionTemplate record 单元测试
 *
 * @since 1.2.0
 */
class DetectionTemplateTest {

    private DetectionTemplate createValidTemplate() {
        return new DetectionTemplate(
                "test-template",
                "Test Template",
                "high",
                "response-pattern",
                List.of(
                        new DetectionTemplate.Matcher("regex", "error.*sql", null, null, null, "or", "body", false)
                ),
                List.of("sqli", "injection"),
                "Test description",
                "Test remediation",
                Map.of("author", "test")
        );
    }

    @Test
    void constructor_setsAllFields() {
        DetectionTemplate template = createValidTemplate();

        assertEquals("test-template", template.id());
        assertEquals("Test Template", template.name());
        assertEquals("high", template.severity());
        assertEquals("response-pattern", template.type());
        assertEquals(1, template.matchers().size());
        assertEquals(2, template.tags().size());
        assertEquals("Test description", template.description());
        assertEquals("Test remediation", template.remediation());
        assertEquals("test", template.metadata().get("author"));
    }

    @Test
    void isValid_validTemplate_returnsTrue() {
        DetectionTemplate template = createValidTemplate();

        assertTrue(template.isValid());
    }

    @Test
    void isValid_nullId_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                null, "Name", "high", "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_blankId_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "   ", "Name", "high", "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_nullName_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "id", null, "high", "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_blankName_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "id", "  ", "high", "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_nullSeverity_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "id", "Name", null, "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_nullMatchers_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "id", "Name", "high", "type",
                null,
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_emptyMatchers_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "id", "Name", "high", "type",
                List.of(),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void isValid_invalidMatcherType_returnsFalse() {
        DetectionTemplate template = new DetectionTemplate(
                "id", "Name", "high", "type",
                List.of(new DetectionTemplate.Matcher("invalid_type", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertFalse(template.isValid());
    }

    @Test
    void summary_containsExpectedInfo() {
        DetectionTemplate template = createValidTemplate();
        String summary = template.summary();

        assertTrue(summary.contains("HIGH"));
        assertTrue(summary.contains("Test Template"));
        assertTrue(summary.contains("response-pattern"));
        assertTrue(summary.contains("1 matchers"));
        assertTrue(summary.contains("sqli"));
    }

    @Test
    void summary_nullTags_showsNone() {
        DetectionTemplate template = new DetectionTemplate(
                "id", "Name", "high", "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                null, null, null, Map.of()
        );

        String summary = template.summary();
        assertTrue(summary.contains("none"));
    }

    // Matcher tests

    @Test
    void matcher_defaultCondition_isOr() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "regex", ".*", null, null, null, null, null, false
        );

        assertEquals("or", matcher.condition());
    }

    @Test
    void matcher_defaultPart_isBody() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "regex", ".*", null, null, null, "or", null, false
        );

        assertEquals("body", matcher.part());
    }

    @Test
    void matcher_isValidType_regex() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "regex", ".*", null, null, null, "or", "body", false
        );

        assertTrue(matcher.isValidType());
    }

    @Test
    void matcher_isValidType_word() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "word", null, List.of("test"), null, null, "or", "body", false
        );

        assertTrue(matcher.isValidType());
    }

    @Test
    void matcher_isValidType_status() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "status", null, null, 200, null, "or", "body", false
        );

        assertTrue(matcher.isValidType());
    }

    @Test
    void matcher_isValidType_dsl() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "dsl", null, null, null, "status_code == 200", "or", "body", false
        );

        assertTrue(matcher.isValidType());
    }

    @Test
    void matcher_isValidType_invalid() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "invalid", null, null, null, null, "or", "body", false
        );

        assertFalse(matcher.isValidType());
    }

    @Test
    void matcher_isValidType_null() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                null, null, null, null, null, "or", "body", false
        );

        assertFalse(matcher.isValidType());
    }

    @Test
    void matcher_describe_regex() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "regex", "error.*sql", null, null, null, "or", "body", false
        );

        String desc = matcher.describe();
        assertTrue(desc.contains("Regex"));
        assertTrue(desc.contains("error.*sql"));
    }

    @Test
    void matcher_describe_word() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "word", null, List.of("error", "fail"), null, null, "or", "body", false
        );

        String desc = matcher.describe();
        assertTrue(desc.contains("Words"));
        assertTrue(desc.contains("error"));
        assertTrue(desc.contains("fail"));
    }

    @Test
    void matcher_describe_status() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "status", null, null, 404, null, "or", "body", false
        );

        String desc = matcher.describe();
        assertTrue(desc.contains("Status"));
        assertTrue(desc.contains("404"));
    }

    @Test
    void matcher_describe_dsl() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "dsl", null, null, null, "status_code == 200", "or", "body", false
        );

        String desc = matcher.describe();
        assertTrue(desc.contains("DSL"));
        assertTrue(desc.contains("status_code"));
    }

    @Test
    void matcher_describe_unknown() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "unknown", null, null, null, null, "or", "body", false
        );

        String desc = matcher.describe();
        assertEquals("Unknown", desc);
    }

    @Test
    void matcher_negativeFlag_works() {
        DetectionTemplate.Matcher matcher = new DetectionTemplate.Matcher(
                "regex", ".*", null, null, null, "or", "body", true
        );

        assertTrue(matcher.negative());
    }

    @Test
    void record_equality() {
        DetectionTemplate t1 = createValidTemplate();
        DetectionTemplate t2 = createValidTemplate();

        assertEquals(t1, t2);
        assertEquals(t1.hashCode(), t2.hashCode());
    }

    @Test
    void record_differentValues_notEqual() {
        DetectionTemplate t1 = createValidTemplate();
        DetectionTemplate t2 = new DetectionTemplate(
                "different-id", "Name", "high", "type",
                List.of(new DetectionTemplate.Matcher("regex", ".*", null, null, null, "or", "body", false)),
                List.of(), null, null, Map.of()
        );

        assertNotEquals(t1, t2);
    }
}
