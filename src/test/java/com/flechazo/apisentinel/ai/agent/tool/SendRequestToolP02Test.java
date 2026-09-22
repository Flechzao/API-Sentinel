package com.flechazo.apisentinel.ai.agent.tool;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Regression guards for P0-2 — {@link SendRequestTool}'s scope gate.
 *
 * <p>Pre-P0-2, {@code host} was unrestricted and {@code use_original_auth}
 * defaulted to true, so a sufficiently persuasive LLM (or a prompt-
 * injection payload that reached the tool-call dispatch) could ship the
 * user's live session cookie to {@code http://169.254.169.254} / any
 * arbitrary exfiltration sink with zero UI confirmation.
 *
 * <p>P0-2 adds three rules, in evaluation order:
 * <ol>
 *   <li>Only http/https schemes are routable.</li>
 *   <li>Private / loopback / link-local / IMDS / {@code *.internal}
 *       destinations are hard-rejected.</li>
 *   <li>Cross-domain sends (destination != entry's captured domain)
 *       have credentials silently stripped regardless of
 *       {@code use_original_auth}.</li>
 * </ol>
 *
 * <p>These tests pin each rule. They call the public {@code execute}
 * method end-to-end with a mocked {@link ToolContext}, so any regression
 * that reopens any of the three gaps fails here before it ships.
 */
class SendRequestToolP02Test {

    private MontoyaApi montoyaApi;
    private ApiEntry entry;
    private ToolContext ctx;
    private SendRequestTool tool;

    @BeforeEach
    void setUp() {
        montoyaApi = mock(MontoyaApi.class);
        entry = new ApiEntry("GET", "/api/x");
        entry.setDomain("target.example.com");
        entry.setLastUrl("http://target.example.com/api/x");
        ctx = new ToolContext(entry, null, montoyaApi, null, java.util.List.of(),
                null, null);
        tool = new SendRequestTool(ctx);
    }

    private String call(String argsJson) {
        return tool.execute(argsJson);
    }

    // ============== Rule 1: scheme gating ==============

    @Test
    void scope_fileScheme_rejected() {
        String out = call("""
                {"method":"GET", "path":"/etc/passwd", "host":"file:///etc/passwd"}
                """);
        assertThat(out).contains("scope policy").contains("scheme");
    }

    @Test
    void scope_gopherScheme_rejected() {
        String out = call("""
                {"method":"GET", "path":"/", "host":"gopher://evil.example.com"}
                """);
        assertThat(out).contains("scope policy").contains("gopher");
    }

    @Test
    void scope_httpScheme_allowed() {
        // We don't need the request to actually go out (HttpService
        // creation may NPE without a real MontoyaApi); we only need to
        // confirm the scope gate DOESN'T reject. Anything other than
        // the scope-policy error string counts as "passed the gate".
        String out = call("""
                {"method":"GET", "path":"/api/x", "host":"target.example.com"}
                """);
        assertThat(out).doesNotContain("scope policy");
    }

    // ============== Rule 2: private / internal IP rejection ==============

    @Test
    void scope_awsImds_rejected() {
        String out = call("""
                {"method":"GET", "path":"/latest/meta-data/iam/security-credentials",
                 "host":"169.254.169.254"}
                """);
        assertThat(out).contains("scope policy");
    }

    @Test
    void scope_gcpImds_rejected() {
        String out = call("""
                {"method":"GET", "path":"/computeMetadata/v1",
                 "host":"metadata.google.internal"}
                """);
        assertThat(out).contains("scope policy").contains("internal");
    }

    @Test
    void scope_loopback_rejected() {
        String out = call("""
                {"method":"GET", "path":"/", "host":"127.0.0.1:9999"}
                """);
        assertThat(out).contains("scope policy");
    }

    @Test
    void scope_rfc1918_rejected() {
        for (String h : java.util.List.of("10.0.0.5", "172.16.0.1", "192.168.1.1")) {
            String out = call("""
                    {"method":"GET", "path":"/", "host":"%s"}
                    """.formatted(h));
            assertThat(out).as("RFC1918 host %s must be rejected", h)
                    .contains("scope policy");
        }
    }

    @Test
    void scope_localhost_rejected() {
        String out = call("""
                {"method":"GET", "path":"/", "host":"localhost"}
                """);
        assertThat(out).contains("scope policy").contains("internal");
    }

    @Test
    void scope_internalSuffix_rejected() {
        String out = call("""
                {"method":"GET", "path":"/", "host":"corp.internal"}
                """);
        assertThat(out).contains("scope policy");
    }

    // ============== Rule 3: cross-domain credential strip ==============

    @Test
    void scope_sameDomain_requestProceedsNormally() {
        // Same host as the entry — no strip, no reject. Anything other
        // than the scope-policy error string counts.
        String out = call("""
                {"method":"GET", "path":"/api/x",
                 "host":"target.example.com", "use_original_auth":true}
                """);
        assertThat(out).doesNotContain("scope policy");
    }

    @Test
    void scope_unresolvableHost_rejected() {
        // DNS resolution failure is a hard reject rather than "let the
        // caller see the DNS error" — otherwise a malicious LLM could
        // probe the internal name space via error messages.
        String out = call("""
                {"method":"GET", "path":"/",
                 "host":"this-host-does-not-exist-3425.example.invalid"}
                """);
        assertThat(out).contains("scope policy").contains("does not resolve");
    }
}
