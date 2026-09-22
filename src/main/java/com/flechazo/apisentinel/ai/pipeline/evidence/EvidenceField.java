package com.flechazo.apisentinel.ai.pipeline.evidence;

import java.util.Locale;

/**
 * A well-known evidence slot a vulnerability finding can carry. Slots are
 * defined by the program (not by prompt text) so completeness can be checked
 * mechanically: {@link EvidenceSchema} declares which slots each vuln type
 * <i>requires</i>, and {@code validate_findings} / the submit gate refuse a
 * finding whose required slots are missing.
 *
 * <p>The {@link #key()} is the lowercase enum name (e.g. {@code baseline_response})
 * and is the wire form external MCP clients use in the {@code evidence} object.
 */
public enum EvidenceField {
    BASELINE_RESPONSE("正常请求的响应"),
    INJECTED_RESPONSE("注入 payload 后的响应"),
    RESPONSE_DIFF("baseline 与注入响应的差异"),
    PAYLOAD_USED("实际发送的 payload"),
    ERROR_MESSAGE("数据库/服务端报错文本"),
    TIMING_EVIDENCE("时间差证据（盲注）"),
    SESSION_A_RESPONSE("会话 A 的请求+响应"),
    SESSION_B_RESPONSE("会话 B 的请求+响应"),
    ANONYMOUS_RESPONSE("匿名（去认证）请求的响应"),
    IDENTITY_PROOF("越权身份三问证据"),
    INTERNAL_INDICATOR("内网/服务端侧响应特征"),
    REFLECTED_PAYLOAD("payload 被反射的响应"),
    ENCODING_TEST("编码/转义测试响应"),
    CANARY_RESPONSE("含 canary 标记的响应");

    private final String displayName;

    EvidenceField(String displayName) { this.displayName = displayName; }

    public String displayName() { return displayName; }

    /** Wire/JSON key: the lowercase enum name, e.g. {@code baseline_response}. */
    public String key() { return name().toLowerCase(Locale.ROOT); }

    /** Resolve a wire key back to a field; {@code null} for unknown keys
     *  (unknown keys are simply ignored, never an error). */
    public static EvidenceField fromKey(String key) {
        if (key == null) return null;
        String norm = key.trim().toLowerCase(Locale.ROOT);
        for (EvidenceField f : values()) {
            if (f.key().equals(norm)) return f;
        }
        return null;
    }
}
