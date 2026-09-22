/**
 * Agent 可调用的工具集——一工具一类，由 {@link StandardToolRegistry} 统一注册。
 * 基础工具 32 个 + 元工具 2 个（request_tools, update_analysis_notes）
 * + 浏览器工具 6 个（条件启用）+ submit_report（条件注册），全量约 41 个。
 * 工具分四组：侦察/代码理解（免费）、AI 推理（消耗 LLM）、实测验证（发请求）、子 Agent 委派/特殊。
 */
package com.flechazo.apisentinel.ai.agent.tool;
