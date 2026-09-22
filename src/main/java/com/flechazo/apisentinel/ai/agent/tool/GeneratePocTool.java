package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.poc.PoCGeneratorService;
import com.flechazo.apisentinel.poc.ProofOfConcept;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * generate_poc — 对已确认漏洞自动生成 Proof of Concept
 *
 * 参考 Strix (usestrix/strix) 的 PoC 自动生成理念：
 * 当漏洞被确认后，自动生成可执行的验证方案（cURL + Python + 复现步骤），
 * 帮助安全工程师快速复现和报告漏洞。
 *
 * 支持 15+ 种漏洞类型的模板化 PoC 生成：
 * SQL Injection, XSS, BOLA/IDOR, SSRF, Path Traversal, SSTI, XXE,
 * Command Injection, Mass Assignment, Auth Bypass, CSRF, Open Redirect,
 * NoSQL Injection 等。
 *
 * 零 LLM 调用，纯模板生成。
 */
public class GeneratePocTool implements AgentTool {

    private final ToolContext ctx;
    private final PoCGeneratorService pocService;
    private final List<ProofOfConcept> generatedPocs = new ArrayList<>();

    public GeneratePocTool(ToolContext ctx) {
        this.ctx = ctx;
        this.pocService = new PoCGeneratorService(ctx.logger());
    }

    public List<ProofOfConcept> getGeneratedPocs() {
        return generatedPocs;
    }

    @Override
    public String name() { return "generate_poc"; }

    @Override
    public boolean isReadOnly() { return false; } // can write files

    @Override
    public String description() {
        return "Generate a Proof of Concept (PoC) for a confirmed vulnerability. "
             + "Produces executable cURL commands, Python scripts, step-by-step reproduction "
             + "instructions, and impact assessment. Supports 15+ vulnerability types: "
             + "SQL Injection, XSS, BOLA/IDOR, SSRF, Path Traversal, SSTI, XXE, "
             + "Command Injection, Mass Assignment, Auth Bypass, CSRF, Open Redirect, NoSQL Injection. "
             + "Use after confirming a vulnerability via send_request, test_auth_bypass, or other "
             + "verification tools. Optionally saves the PoC as a Markdown file. "
             + "Zero LLM cost — pure template generation.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        props.add("vuln_type", prop("string", true,
                "Vulnerability type: SQL Injection, XSS, BOLA/IDOR, SSRF, Path Traversal, "
                + "SSTI, XXE, Command Injection, Mass Assignment, Auth Bypass, CSRF, "
                + "Open Redirect, NoSQL Injection, or any custom type"));

        props.add("severity", prop("string", false,
                "Severity: CRITICAL, HIGH, MEDIUM, LOW (default: HIGH)"));

        props.add("endpoint", prop("string", true,
                "Affected endpoint description (e.g. 'GET /api/users/{id}')"));

        props.add("url", prop("string", true,
                "Full URL of the vulnerable endpoint (e.g. 'https://target.com/api/users/1')"));

        props.add("method", prop("string", false,
                "HTTP method: GET, POST, PUT, DELETE, PATCH (default: GET)"));

        props.add("payload", prop("string", false,
                "The payload that triggered the vulnerability"));

        props.add("evidence", prop("string", false,
                "Evidence from the response proving the vulnerability (response snippet)"));

        props.add("description", prop("string", false,
                "Description of the vulnerability and how it was discovered"));

        props.add("remediation", prop("string", false,
                "Suggested fix for the vulnerability"));

        props.add("cookies", prop("string", false,
                "Authentication cookies (if needed to reproduce)"));

        props.add("headers", prop("string", false,
                "Additional request headers (one per line)"));

        props.add("confidence", prop("integer", false,
                "Confidence score 0-100 (default: 80)"));

        props.add("save_to_file", prop("string", false,
                "Optional: save PoC as Markdown file to this path (e.g. 'poc-sqli-001.md')"));

        schema.add("properties", props);
        schema.add("required", arr("vuln_type", "endpoint", "url"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args;
        try {
            args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        } catch (Exception e) {
            return err("Invalid JSON arguments: " + e.getMessage());
        }

        String vulnType = str(args, "vuln_type");
        String severity = str(args, "severity", "HIGH");
        String endpoint = str(args, "endpoint");
        String url = str(args, "url");
        String method = str(args, "method", "GET");
        String payload = str(args, "payload");
        String evidence = str(args, "evidence");
        String description = str(args, "description");
        String remediation = str(args, "remediation");
        String cookies = str(args, "cookies");
        String headers = str(args, "headers");
        int confidence = intVal(args, "confidence", 80);
        String saveToFile = str(args, "save_to_file");

        if (vulnType == null || vulnType.isEmpty()) {
            return err("vuln_type is required");
        }
        if (endpoint == null || endpoint.isEmpty()) {
            return err("endpoint is required");
        }
        if (url == null || url.isEmpty()) {
            return err("url is required");
        }

        // Generate PoC
        ProofOfConcept poc = pocService.generate(
                vulnType, severity, endpoint, method, url,
                payload, evidence, description, remediation,
                cookies, headers, confidence
        );

        generatedPocs.add(poc);

        // Build response
        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        out.addProperty("vuln_type", poc.vulnType());
        out.addProperty("severity", poc.severity());
        out.addProperty("title", poc.title());
        out.addProperty("confidence", poc.confidence());
        out.addProperty("affected_endpoint", poc.affectedEndpoint());

        out.addProperty("curl_command", poc.curlCommand());

        if (poc.pythonScript() != null) {
            out.addProperty("python_script", poc.pythonScript());
        }

        JsonArray stepsArr = new JsonArray();
        if (poc.steps() != null) {
            for (String step : poc.steps()) stepsArr.add(step);
        }
        out.add("steps", stepsArr);

        out.addProperty("impact", poc.impact());

        if (poc.remediation() != null) {
            out.addProperty("remediation", poc.remediation());
        }

        // Save to file if requested
        if (saveToFile != null && !saveToFile.isEmpty()) {
            try {
                Path filePath = Path.of(saveToFile);
                Files.writeString(filePath, poc.toMarkdown());
                out.addProperty("saved_to", filePath.toAbsolutePath().toString());
                out.addProperty("format", "markdown");
            } catch (IOException e) {
                out.addProperty("save_error", "Failed to save file: " + e.getMessage());
            }
        }

        out.addProperty("total_generated", generatedPocs.size());
        out.addProperty("next_step", "PoC 已生成。使用 curl 命令快速验证，或保存为 Markdown 报告附件");

        if (ctx.logger() != null) {
            ctx.logger().info("[generate_poc] Generated %s PoC for %s (severity: %s, confidence: %d)",
                    poc.vulnType(), poc.affectedEndpoint(), poc.severity(), poc.confidence());
        }

        return out.toString();
    }

    // ==================== Helper Methods ====================

    private static JsonObject prop(String type, boolean required, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private static JsonArray arr(String... values) {
        JsonArray a = new JsonArray();
        for (String v : values) a.add(v);
        return a;
    }

    private static String str(JsonObject obj, String key) {
        return str(obj, key, null);
    }

    private static String str(JsonObject obj, String key, String def) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return def;
    }

    private static int intVal(JsonObject obj, String key, int def) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            try {
                return obj.get(key).getAsInt();
            } catch (Exception e) {
                return def;
            }
        }
        return def;
    }

    private static String err(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("success", false);
        o.addProperty("error", msg);
        return o.toString();
    }
}
