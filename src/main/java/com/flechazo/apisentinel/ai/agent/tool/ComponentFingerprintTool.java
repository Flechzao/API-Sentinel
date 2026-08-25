package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.ComponentFingerprinter;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

/**
 * Passive component fingerprinting tool: identifies backend frameworks,
 * libraries and admin endpoints from the captured response (zero requests).
 * Lets the agent pick targeted test strategies (Fastjson → deserialization,
 * Nacos → auth bypass, Actuator → info leak…).
 */
public class ComponentFingerprintTool implements AgentTool {

    private final ToolContext ctx;

    public ComponentFingerprintTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "fingerprint_components"; }

    @Override
    public String description() {
        return "Passively identify backend components (frameworks, libraries, admin endpoints) "
             + "from the captured response — Fastjson, Log4j, Shiro, Spring Actuator, Nacos, "
             + "Drupal, Swagger, etc. Free, sends no requests. Run it early and let the result "
             + "guide which vulnerability classes to test.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject out = new JsonObject();
        ApiEntry entry = ctx.entry();
        if (entry == null || entry.getLastRawResponse() == null || entry.getLastRawResponse().isEmpty()) {
            out.addProperty("hint", "该接口暂无捕获的响应流量，无法指纹识别。");
            out.add("components", new JsonArray());
            return out.toString();
        }

        List<ComponentFingerprinter.ComponentInfo> components =
                ComponentFingerprinter.fingerprint(entry.getLastRawResponse(), entry.getLastUrl());

        JsonArray arr = new JsonArray();
        for (ComponentFingerprinter.ComponentInfo c : components) {
            JsonObject co = new JsonObject();
            co.addProperty("name", c.name());
            co.addProperty("risk", c.risk());
            co.addProperty("vuln", c.vuln());
            co.addProperty("evidence", c.evidence());
            arr.add(co);
        }
        out.add("components", arr);
        if (components.isEmpty()) {
            out.addProperty("note", "未识别出已知组件特征（不影响常规漏洞测试）。");
            out.addProperty("next_step", "无组件识别，按常规流程继续：调用 analyze_traffic 或 generate_payloads");
        } else {
            ComponentFingerprinter.ComponentInfo top = components.get(0);
            out.addProperty("recommendation",
                    "识别到 " + components.size() + " 个组件；风险最高：" + top.name()
                  + "（" + top.vuln() + "），建议优先针对性测试。");
            out.addProperty("next_step", buildNextStep(components));
        }
        return out.toString();
    }

    private String buildNextStep(List<ComponentFingerprinter.ComponentInfo> components) {
        for (var c : components) {
            String name = c.name() != null ? c.name().toLowerCase() : "";
            if (name.contains("shiro")) {
                return "建议: 识别到 Shiro，检查 rememberMe cookie 反序列化漏洞（CVE-2016-4437），调用 generate_payloads 生成反序列化 payload";
            }
            if (name.contains("fastjson")) {
                return "建议: 识别到 Fastjson，检查 @type 自动反序列化，调用 generate_payloads 生成 JNDI 注入 payload";
            }
            if (name.contains("log4j") || name.contains("log4shell")) {
                return "建议: 识别到 Log4j，检查 Log4Shell（CVE-2021-44228），调用 generate_payloads 生成 JNDI lookup payload";
            }
            if (name.contains("actuator")) {
                return "建议: 识别到 Spring Actuator，检查未授权访问的敏感端点（/env, /heapdump, /mappings）";
            }
            if (name.contains("nacos")) {
                return "建议: 识别到 Nacos，检查认证绕过漏洞（CVE-2021-29441），调用 send_request 测试未授权访问";
            }
            if (name.contains("swagger")) {
                return "建议: 识别到 Swagger UI，检查 /v2/api-docs 或 /swagger-ui.html 是否暴露敏感 API 文档";
            }
        }
        return "建议: 已识别组件特征，根据组件类型选择针对性的漏洞测试策略，调用 generate_payloads 生成 payload";
    }
}
