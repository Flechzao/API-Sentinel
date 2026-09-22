package com.flechazo.apisentinel.detection.template;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TemplateParser 单元测试
 *
 * @since 1.2.0
 */
class TemplateParserTest {

    @Test
    void parse_simpleYaml_returnsTemplate() {
        String yaml = """
                id: test-template
                name: Test Template
                severity: high
                type: response-pattern
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("test-template", template.id());
        assertEquals("Test Template", template.name());
        assertEquals("high", template.severity());
        assertEquals("response-pattern", template.type());
    }

    @Test
    void parse_withTags_parsesTags() {
        String yaml = """
                id: test
                name: Test
                severity: high
                tags: sqli,injection,owasp-a03
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertNotNull(template.tags());
        assertEquals(3, template.tags().size());
        assertTrue(template.tags().contains("sqli"));
        assertTrue(template.tags().contains("injection"));
        assertTrue(template.tags().contains("owasp-a03"));
    }

    @Test
    void parse_withDescriptionAndRemediation_parsesBoth() {
        String yaml = """
                id: test
                name: Test
                severity: high
                description: This is a test description
                remediation: Fix the vulnerability
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("This is a test description", template.description());
        assertEquals("Fix the vulnerability", template.remediation());
    }

    @Test
    void parse_withRegexMatcher_parsesMatcher() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: regex
                    pattern: "(?i)(SQL syntax|mysql_fetch)"
                    condition: or
                    part: body
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertNotNull(template.matchers());
        assertEquals(1, template.matchers().size());

        DetectionTemplate.Matcher matcher = template.matchers().get(0);
        assertEquals("regex", matcher.type());
        assertTrue(matcher.pattern().contains("SQL syntax"));
        assertEquals("or", matcher.condition());
        assertEquals("body", matcher.part());
    }

    @Test
    void parse_withWordMatcher_parsesWords() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: word
                    words: ["syntax error", "mysql error"]
                    condition: or
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals(1, template.matchers().size());
        DetectionTemplate.Matcher matcher = template.matchers().get(0);
        assertEquals("word", matcher.type());
        assertNotNull(matcher.words());
        assertEquals(2, matcher.words().size());
        assertTrue(matcher.words().contains("syntax error"));
        assertTrue(matcher.words().contains("mysql error"));
    }

    @Test
    void parse_withStatusMatcher_parsesStatus() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: status
                    status: 500
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals(1, template.matchers().size());
        DetectionTemplate.Matcher matcher = template.matchers().get(0);
        assertEquals("status", matcher.type());
        assertEquals(500, matcher.status());
    }

    @Test
    void parse_withDslMatcher_parsesDsl() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: dsl
                    dsl: "status_code == 200 && contains(body, 'error')"
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals(1, template.matchers().size());
        DetectionTemplate.Matcher matcher = template.matchers().get(0);
        assertEquals("dsl", matcher.type());
        assertNotNull(matcher.dsl());
    }

    @Test
    void parse_withNegativeMatcher_parsesNegativeFlag() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: word
                    words: ["success"]
                    negative: true
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals(1, template.matchers().size());
        assertTrue(template.matchers().get(0).negative());
    }

    @Test
    void parse_multipleMatchers_parsesAll() {
        String yaml = """
                id: test
                name: Test
                severity: critical
                matchers:
                  - type: regex
                    pattern: "(?i)error"
                  - type: word
                    words: ["fail", "exception"]
                  - type: status
                    status: 500
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals(3, template.matchers().size());
        assertEquals("regex", template.matchers().get(0).type());
        assertEquals("word", template.matchers().get(1).type());
        assertEquals("status", template.matchers().get(2).type());
    }

    @Test
    void parse_skipsComments() {
        String yaml = """
                # This is a comment
                id: test
                name: Test
                # Another comment
                severity: high
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("test", template.id());
        assertEquals("Test", template.name());
        assertEquals("high", template.severity());
    }

    @Test
    void parse_skipsEmptyLines() {
        String yaml = """
                id: test

                name: Test

                severity: high
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("test", template.id());
        assertEquals("Test", template.name());
    }

    @Test
    void parse_defaultType_isResponsePattern() {
        String yaml = """
                id: test
                name: Test
                severity: high
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("response-pattern", template.type());
    }

    @Test
    void parse_defaultCondition_isOr() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: regex
                    pattern: "error"
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("or", template.matchers().get(0).condition());
    }

    @Test
    void parse_defaultPart_isBody() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: regex
                    pattern: "error"
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("body", template.matchers().get(0).part());
    }

    @Test
    void parse_fromFile_parsesCorrectly(@TempDir Path tempDir) throws IOException {
        Path yamlFile = tempDir.resolve("test.yaml");
        String content = """
                id: file-test
                name: File Test Template
                severity: medium
                type: request-pattern
                tags: test,file
                description: Test from file
                matchers:
                  - type: regex
                    pattern: "test.*pattern"
                """;
        Files.writeString(yamlFile, content);

        DetectionTemplate template = TemplateParser.parse(yamlFile);

        assertEquals("file-test", template.id());
        assertEquals("File Test Template", template.name());
        assertEquals("medium", template.severity());
        assertEquals("request-pattern", template.type());
        assertEquals(2, template.tags().size());
        assertEquals(1, template.matchers().size());
    }

    @Test
    void parse_emptyYaml_returnsEmptyTemplate() {
        String yaml = "";

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertNotNull(template);
    }

    @Test
    void parse_completeRealWorldTemplate() {
        String yaml = """
                id: custom-sqli-detection
                name: Custom SQL Injection Detection
                severity: critical
                type: response-pattern
                description: Detects SQL injection via error messages
                remediation: Use parameterized queries
                tags: sqli,injection,owasp-a03,critical
                matchers:
                  - type: regex
                    pattern: "(?i)(SQL syntax|mysql_fetch|ORA-\\\\d{5})"
                    condition: or
                    part: body
                  - type: word
                    words: ["syntax error", "mysql error"]
                    condition: or
                    part: body
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertEquals("custom-sqli-detection", template.id());
        assertEquals("Custom SQL Injection Detection", template.name());
        assertEquals("critical", template.severity());
        assertEquals("response-pattern", template.type());
        assertNotNull(template.description());
        assertNotNull(template.remediation());
        assertEquals(4, template.tags().size());
        assertEquals(2, template.matchers().size());

        assertTrue(template.isValid());
    }

    @Test
    void parse_tagsAsList_parsesCorrectly() {
        String yaml = """
                id: test
                name: Test
                severity: high
                tags:
                  - tag1
                  - tag2
                  - tag3
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);

        assertNotNull(template.tags());
        assertEquals(3, template.tags().size());
    }

    @Test
    void parse_matcherWithAllFields_parsesAll() {
        String yaml = """
                id: test
                name: Test
                severity: high
                matchers:
                  - type: regex
                    pattern: "error"
                    condition: and
                    part: headers
                    negative: true
                """;

        DetectionTemplate template = TemplateParser.parse(yaml);
        DetectionTemplate.Matcher matcher = template.matchers().get(0);

        assertEquals("regex", matcher.type());
        assertEquals("error", matcher.pattern());
        assertEquals("and", matcher.condition());
        assertEquals("headers", matcher.part());
        assertTrue(matcher.negative());
    }
}
