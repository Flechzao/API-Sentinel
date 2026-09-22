package com.flechazo.apisentinel.ai.agent;

/**
 * Agent 角色定义（参考 PentAGI 的角色分工模式）
 *
 * 不同角色的 Agent 具有不同的工具集和职责：
 * - PLANNER: 规划测试策略，不执行实际测试
 * - EXPLORER: 只读探索，收集情报
 * - EXECUTOR: 执行实际测试（发送请求、验证漏洞）
 * - VERIFIER: 验证发现的真实性，减少误报
 *
 * @since 1.2.0
 */
public enum AgentRole {

    /**
     * Planner — 规划测试策略
     *
     * 职责：
     * - 分析目标 API 的特征
     * - 识别潜在攻击面
     * - 生成测试优先级列表
     * - 不执行任何实际测试
     *
     * 工具集：只读工具（search_source_code, read_file, fingerprint_components）
     */
    PLANNER("规划测试策略，分析攻击面，生成优先级", true, false),

    /**
     * Explorer — 只读探索
     *
     * 职责：
     * - 深度探索代码仓库
     * - 发现潜在漏洞点
     * - 收集情报
     * - 不发送 HTTP 请求
     *
     * 工具集：只读工具（现有的 ExplorationSubAgent）
     */
    EXPLORER("只读探索代码和流量，收集情报", true, false),

    /**
     * Executor — 执行测试
     *
     * 职责：
     * - 发送 HTTP 请求
     * - 执行 payload
     * - 验证漏洞
     * - 生成 PoC
     *
     * 工具集：完整工具集（send_request, generate_payloads, test_auth_bypass 等）
     */
    EXECUTOR("执行实际测试，发送请求，验证漏洞", false, true),

    /**
     * Verifier — 验证发现
     *
     * 职责：
     * - 独立验证其他 Agent 的发现
     * - 减少误报
     * - 提供第二意见
     * - 交叉验证证据
     *
     * 工具集：验证工具（send_request, diff_responses, verify_*）
     */
    VERIFIER("独立验证发现，减少误报", false, true);

    private final String description;
    private final boolean readOnly;
    private final boolean canSendRequests;

    AgentRole(String description, boolean readOnly, boolean canSendRequests) {
        this.description = description;
        this.readOnly = readOnly;
        this.canSendRequests = canSendRequests;
    }

    public String description() { return description; }
    public boolean isReadOnly() { return readOnly; }
    public boolean canSendRequests() { return canSendRequests; }
}
