# docs/diagrams — 架构 / 逻辑图

本目录存放 README / 技术文档使用的**专业逻辑图**（架构、Agent 逻辑等），
与 `docs/images/`（插件使用截图）分离，互不干扰。

## 产物约定

每张图两份文件：

| 文件 | 用途 |
|------|------|
| `<name>_mermaid.md` | Mermaid 源码。可直接复制进 README 的 ` ```mermaid ` 代码块，GitHub 原生渲染，改文本即可维护 |
| `<name>.html` | 纯 HTML/CSS 渲染版（零 JS）。浏览器打开预览，或截图用于不支持 Mermaid 的场景 |

## Archify 交互式图 (2026-09-13 新增)

使用 [Archify](https://github.com/tt-a1i/archify) 生成的可交互技术架构图。
每张图由 `*.json` (Typed JSON IR) 源文件 + `*.html` (独立可交互成品) 配对。

| 图 | JSON 源 | HTML 成品 | 内容 |
|----|---------|-----------|------|
| 系统架构 | `api-sentinel-architecture.json` | `api-sentinel-architecture.html` | 12 个核心组件、安全边界、3 个引导视图 |
| 安全分析时序 | `api-analysis-sequence.json` | `api-analysis-sequence.html` | 被动检测 → AI 分析 → 主动验证完整流程 |
| MCP 会话化工具调用 | `mcp-session-workflow.json` | `mcp-session-workflow.html` | 外部 AI 大脑接入全量工具的泳道流程 |
| 发现流转 | `findings-dataflow.json` | `findings-dataflow.html` | traffic → findings → evidence → verdict |

### 交互功能

- `/` 搜索节点 · `F` 聚焦 · `L` 角色对比 · `R` 路径探查 · `P` 故事播放
- `S` 切换视觉风格 (Classic/Signal Flow/Blueprint)
- `T` 切换深浅主题
- `E` 导出 PNG / SVG / Share Card

### 生成/更新命令

```bash
cd ~/.claude/skills/archify
node bin/archify.mjs deliver architecture /path/to/source.json /path/to/output.html --open --json
node bin/archify.mjs deliver sequence /path/to/source.json /path/to/output.html --open --json
node bin/archify.mjs deliver workflow /path/to/source.json /path/to/output.html --open --json
node bin/archify.mjs deliver dataflow /path/to/source.json /path/to/output.html --open --json
```

---

## 早期 Mermaid 图 (历史)

| 图 | 文件 | 对应文档位置 |
|----|------|-------------|
| 整体架构图 | `overall-architecture_mermaid.md` / `.html` | README「架构图」章节 |
| Agent ReAct 工具循环 | `agent-react-loop_mermaid.md` / `.html` | README「Agent 模式」章节 |
| Agent 主循环内部机制 | `agent-loop-internals.html` | README「深入机制图 ①」 |
| 反幻觉防御机制 | `anti-hallucination-defense.html` | README「深入机制图 ②」 |
| 代码关联与污点分析 | `code-correlation-taint.html` | README「深入机制图 ③」 |

## 生成 / 重生成方式

用 `system-diagram` skill（Text → Mermaid → HTML/CSS，零依赖）：
向 Claude 描述系统结构即可生成，产物为 Mermaid 源 + HTML 渲染版。
修改时优先直接改 Mermaid 源码；结构大改再重新生成。

## 本地预览 HTML

```bash
open docs/diagrams/overall-architecture.html      # macOS
```
