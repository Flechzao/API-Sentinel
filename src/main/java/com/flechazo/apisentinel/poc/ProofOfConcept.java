package com.flechazo.apisentinel.poc;

import com.google.gson.JsonObject;

import java.util.List;

/**
 * 一个自动生成的 Proof of Concept（PoC）漏洞验证方案。
 *
 * @param vulnType         漏洞类型（如 "SQL Injection", "BOLA/IDOR"）
 * @param severity         严重性（CRITICAL/HIGH/MEDIUM/LOW）
 * @param title            PoC 标题
 * @param description      漏洞描述和影响说明
 * @param curlCommand      可直接复制执行的 curl 命令
 * @param pythonScript     Python 复现脚本（适用于复杂漏洞）
 * @param steps            复现步骤（人类可读）
 * @param impact           影响评估（可造成的后果）
 * @param affectedEndpoint 受影响的端点
 * @param payload          实际使用的 payload
 * @param evidence         漏洞证据（如响应片段）
 * @param remediation      修复建议
 * @param confidence       置信度（0-100）
 */
public record ProofOfConcept(
        String vulnType,
        String severity,
        String title,
        String description,
        String curlCommand,
        String pythonScript,
        List<String> steps,
        String impact,
        String affectedEndpoint,
        String payload,
        String evidence,
        String remediation,
        int confidence
) {

    /** 将 PoC 序列化为 JSON */
    public JsonObject toJson() {
        JsonObject obj = new JsonObject();
        obj.addProperty("vuln_type", vulnType);
        obj.addProperty("severity", severity);
        obj.addProperty("title", title);
        obj.addProperty("description", description);
        obj.addProperty("curl_command", curlCommand);
        obj.addProperty("python_script", pythonScript);

        com.google.gson.JsonArray stepsArr = new com.google.gson.JsonArray();
        if (steps != null) {
            for (String step : steps) stepsArr.add(step);
        }
        obj.add("steps", stepsArr);

        obj.addProperty("impact", impact);
        obj.addProperty("affected_endpoint", affectedEndpoint);
        obj.addProperty("payload", payload);
        obj.addProperty("evidence", evidence);
        obj.addProperty("remediation", remediation);
        obj.addProperty("confidence", confidence);
        return obj;
    }

    /** 生成 Markdown 格式的 PoC 报告 */
    public String toMarkdown() {
        StringBuilder sb = new StringBuilder();
        sb.append("# PoC: ").append(title).append("\n\n");
        sb.append("**漏洞类型**: ").append(vulnType).append("  \n");
        sb.append("**严重性**: ").append(severity).append("  \n");
        sb.append("**置信度**: ").append(confidence).append("/100  \n");
        sb.append("**受影响端点**: `").append(affectedEndpoint).append("`\n\n");

        sb.append("## 描述\n\n");
        sb.append(description).append("\n\n");

        sb.append("## 影响\n\n");
        sb.append(impact).append("\n\n");

        if (steps != null && !steps.isEmpty()) {
            sb.append("## 复现步骤\n\n");
            for (int i = 0; i < steps.size(); i++) {
                sb.append(i + 1).append(". ").append(steps.get(i)).append("\n");
            }
            sb.append("\n");
        }

        if (curlCommand != null && !curlCommand.isEmpty()) {
            sb.append("## cURL 命令\n\n```bash\n");
            sb.append(curlCommand).append("\n```\n\n");
        }

        if (pythonScript != null && !pythonScript.isEmpty()) {
            sb.append("## Python 脚本\n\n```python\n");
            sb.append(pythonScript).append("\n```\n\n");
        }

        if (payload != null && !payload.isEmpty()) {
            sb.append("## Payload\n\n```\n");
            sb.append(payload).append("\n```\n\n");
        }

        if (evidence != null && !evidence.isEmpty()) {
            sb.append("## 证据\n\n```\n");
            sb.append(evidence.length() > 500 ? evidence.substring(0, 500) + "..." : evidence);
            sb.append("\n```\n\n");
        }

        if (remediation != null && !remediation.isEmpty()) {
            sb.append("## 修复建议\n\n");
            sb.append(remediation).append("\n");
        }

        return sb.toString();
    }
}
