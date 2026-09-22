package com.flechazo.apisentinel.util;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BambdaBuilderTest {

    @Test
    void defaults_excludeMethods_andHasResponse() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("boolean hasResponse = requestResponse.response() != null;"), code);
        assertTrue(code.contains("String[] methodExclude = {"), code);
        assertTrue(code.contains("methodExcluded"), code);
        assertTrue(code.contains("!methodExcluded"), code);
        assertTrue(code.contains("!matchHideExt"), code); // hide ext default on
        assertTrue(code.trim().endsWith(";"), code);
    }

    @Test
    void domainWildcard_becomesRegex() {
        assertEquals("api\\.example\\.com", BambdaBuilder.escapeRegexKeepWildcard("api.example.com"));
        assertEquals(".*\\.test\\.com", BambdaBuilder.escapeRegexKeepWildcard("*.test.com"));

        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterDomainEnabled = true;
        s.domains = "*.test.com, evil.com";
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("domainExclude"), code);
        assertTrue(code.contains(".*\\\\.test\\\\.com") || code.contains(".*\\.test\\.com"), code);
        assertTrue(code.contains("!isExcludedDomain"), code);
    }

    @Test
    void searchLiteral_usesQuote_caseInsensitiveByDefault() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.searchFilterEnabled = true;
        s.searchTerm = "password";
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("Pattern.quote(\"password\")"), code);
        assertTrue(code.contains("Pattern.CASE_INSENSITIVE"), code);
        assertTrue(code.contains("searchMatched"), code);
    }

    @Test
    void searchNegative_negatesCondition() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.searchFilterEnabled = true;
        s.searchTerm = "x";
        s.searchNegative = true;
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("!searchMatched"), code);
    }

    @Test
    void mimeSubset_enablesMimeFilter_fullSetDoesNot() {
        BambdaFilterSettings subset = new BambdaFilterSettings();
        subset.mimeTypes = List.of("HTML", "Script");
        assertTrue(BambdaBuilder.build(subset).contains("mimeAllowed"));

        BambdaFilterSettings full = new BambdaFilterSettings();
        full.mimeTypes = BambdaFilterSettings.ALL_MIME;
        assertFalse(BambdaBuilder.build(full).contains("mimeAllowed"),
                "full MIME set means no MIME filter");
    }

    @Test
    void statusSubset_enablesStatusFilter() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.statusCodes = List.of("2xx [success]");
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("statusAllowed"), code);
        // 2xx band true, others false
        assertTrue(code.contains("statusCode >= 200 && statusCode < 300) { statusAllowed = true;"), code);
        assertTrue(code.contains("statusCode >= 400 && statusCode < 500) { statusAllowed = false;"), code);
    }

    @Test
    void keywordsInclude_stacksAsCondition() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterKeywordsEnabled = true;
        s.keywords = "admin,token";
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("containsAnyKeyword"), code);
        assertTrue(code.contains("String requestContent = requestResponse.request().toString();"), code);
    }

    @Test
    void inScope_usesRealApi_noReflection() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterInScope = true;
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("requestResponse.request().isInScope()"), code);
        assertFalse(code.contains("getMethod(\"isInScope\")"), "reflection hack should be gone: " + code);
    }

    @Test
    void parameterized_usesRealApi_noTryCatch() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterParameterized = true;
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("!requestResponse.request().parameters().isEmpty()"), code);
        assertFalse(code.contains("catch (Exception ignored)"), "try/catch hack should be gone: " + code);
    }

    @Test
    void keywordPatterns_areHoisted_notRecompiledPerEval() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterKeywordsEnabled = true;
        s.keywords = "admin";
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("Pattern[] keywordPatterns = {Pattern.compile("), code);
        assertFalse(code.contains("Pattern.compile(keyword)"), "should not recompile per match: " + code);
    }

    @Test
    void listenerPort_matchesNumeric() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.listenerPort = "8443";
        String code = BambdaBuilder.build(s);
        assertTrue(code.contains("listenerPort == 8443"), code);
        assertTrue(code.contains("matchPort"), code);
    }
}
