package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Guards for {@link GetBurpScanIssuesTool} — the bridge that exposes Burp's
 * native Scanner issues to the Agent as leads (not conclusions).
 *
 * <p>Covers the three degradation paths (null Burp API, null site map in
 * standalone CLI mode, empty issue list) and the host-filtering + JSON
 * shape on the happy path. Mock-based; no real Burp / network / LLM.
 */
class GetBurpScanIssuesToolTest {

    private GetBurpScanIssuesTool toolForHost(String host) {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1");
        entry.setDomain(host);
        // ToolContext(entry, provider, montoyaApi, codeIndex, repos, cfg, logger)
        return new GetBurpScanIssuesTool(
                new ToolContext(entry, null, null, null, List.of(), null, null));
    }

    private GetBurpScanIssuesTool toolWithApi(MontoyaApi api, String host) {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1");
        entry.setDomain(host);
        return new GetBurpScanIssuesTool(
                new ToolContext(entry, null, api, null, List.of(), null, null));
    }

    private AuditIssue mockIssue(String name, String host, String baseUrl,
                                 AuditIssueSeverity sev, AuditIssueConfidence conf,
                                 String detail) {
        AuditIssue issue = mock(AuditIssue.class);
        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn(host);
        when(issue.name()).thenReturn(name);
        when(issue.httpService()).thenReturn(svc);
        when(issue.baseUrl()).thenReturn(baseUrl);
        when(issue.severity()).thenReturn(sev);
        when(issue.confidence()).thenReturn(conf);
        when(issue.detail()).thenReturn(detail);
        when(issue.requestResponses()).thenReturn(List.of());
        return issue;
    }

    @Test
    void nullBurpApi_returnsError() {
        // ctx.montoyaApi() == null
        GetBurpScanIssuesTool tool = toolForHost("target.example.com");
        String out = tool.execute("{}");
        assertThat(out).contains("\"success\": false").contains("Burp API");
    }

    @Test
    void nullSiteMap_returnsStandaloneError() {
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.siteMap()).thenReturn(null); // HeadlessMontoyaApi standalone path
        GetBurpScanIssuesTool tool = toolWithApi(api, "target.example.com");
        String out = tool.execute("{}");
        assertThat(out).contains("\"success\": false").contains("站点地图");
    }

    @Test
    void emptyIssues_returnsEmptySuccess() {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        when(siteMap.issues()).thenReturn(List.of());
        when(api.siteMap()).thenReturn(siteMap);

        GetBurpScanIssuesTool tool = toolWithApi(api, "target.example.com");
        String out = tool.execute("{}");

        assertThat(out).contains("\"success\":true").contains("\"count\":0");
    }

    @Test
    void filtersByHostAndBuildsJson() {
        AuditIssue match = mockIssue("SQL injection", "target.example.com",
                "http://target.example.com/api/users/1",
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                "SQL error: syntax error near '1'");
        AuditIssue otherHost = mockIssue("XSS", "other.example.com",
                "http://other.example.com/x",
                AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE,
                "reflected");

        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        when(siteMap.issues()).thenReturn(List.of(match, otherHost));
        when(api.siteMap()).thenReturn(siteMap);

        GetBurpScanIssuesTool tool = toolWithApi(api, "target.example.com");
        String out = tool.execute("{}");

        // Only the same-host issue survives filtering
        assertThat(out).contains("SQL injection").contains("target.example.com");
        assertThat(out).doesNotContain("\"name\":\"XSS\"");
        // Severity / confidence surface as enum names
        assertThat(out).contains("HIGH").contains("FIRM");
        // Count reflects exactly one surviving issue
        assertThat(out).contains("\"count\":1");
        // The "leads not conclusions" guidance is attached
        assertThat(out).contains("仅作线索");
    }

    @Test
    void urlPrefixFurtherNarrows() {
        AuditIssue a = mockIssue("SQLi", "target.example.com",
                "http://target.example.com/api/users/1",
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "e1");
        AuditIssue b = mockIssue("Open redirect", "target.example.com",
                "http://target.example.com/api/orders/5",
                AuditIssueSeverity.LOW, AuditIssueConfidence.TENTATIVE, "e2");

        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        when(siteMap.issues()).thenReturn(List.of(a, b));
        when(api.siteMap()).thenReturn(siteMap);

        GetBurpScanIssuesTool tool = toolWithApi(api, "target.example.com");
        String out = tool.execute("{\"url_prefix\":\"/api/users\"}");

        assertThat(out).contains("SQLi");
        assertThat(out).doesNotContain("Open redirect");
        assertThat(out).contains("\"count\":1");
    }

    @Test
    void hostOverrideQueriesOtherHost() {
        // entry domain is target.example.com, but caller asks for other host
        AuditIssue other = mockIssue("XSS", "other.example.com",
                "http://other.example.com/x",
                AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE, "r");
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        when(siteMap.issues()).thenReturn(List.of(other));
        when(api.siteMap()).thenReturn(siteMap);

        GetBurpScanIssuesTool tool = toolWithApi(api, "target.example.com");
        String out = tool.execute("{\"host\":\"other.example.com\"}");

        assertThat(out).contains("XSS").contains("\"count\":1");
    }
}
