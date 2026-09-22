# API Sentinel 架构手册

> 架构手册（规格+代码架构+ADR+开发工具链四合一）。根 [README.md](../README.md) 提供快速开始与概览。

## 目录

- [第一部分：完整规格（数据流、MCP 协议、错误降级、安全模型、配置）](#第一部分完整规格)
- [第二部分：代码架构（模块依赖、核心类、扩展点）](#第二部分代码架构)
- [第三部分：架构决策记录（ADR）](#第三部分架构决策记录)
- [第四部分：开发工具链指南](#第四部分开发工具链指南)

---

# 第一部分：完整规格


> 根 [README.md](../README.md) 提供概览；功能参考见 [FEATURES.md](FEATURES.md)。

本文档描述系统边界、数据流、MCP 协议、错误处理与降级、安全模型、配置默认值。内容基于当前代码实现。

---

## 系统边界与数据流

API Sentinel 以 **Burp Suite Montoya 扩展** 形式运行，入口 `ApiSentinelExtension.initialize(MontoyaApi)`。两条分析路径共用同一套工具与证据存储：

### 数据流总览

```
Burp 代理流量 ──► HttpHandler(被动) ──► MatchEngine(精准+模糊) ──► ApiEntry 入库
                                                                        │
                              ┌─────────────────────────────────────────┤
                              ▼                                         ▼
                   AnalysisPipeline(6 阶段固定)              AgentLoop(ReAct 自主)
                              │                                         │
                              ▼                                         ▼
                     VerdictValidator(交叉校验) ──► FinalVerdict ──► 写回 ApiEntry
                              │                                         │
                              └─────────► EventBus ──► UI 刷新 / 报告导出
```

### 6 阶段固定管线（`AnalysisPipeline`）

按固定顺序执行，每阶段输出喂入下一阶段，最后经 `VerdictValidator` 交叉验证产出 `FinalVerdict`：

| 阶段 | 职责 | 关键类 |
|------|------|--------|
| Stage 1 | 流量分析（纯 HTTP，不含源码） | `VulnerabilityAnalyzer` |
| Stage 2 | 代码关联（报告匹配的源码文件/路由） | `CodeIndexService` |
| Stage 3 | 测试载荷生成（由 Stage 1 findings + 源码引导） | `TestCaseService` |
| Stage 4 | 自动执行 payload（携带原始认证） | Montoya HTTP |
| Stage 5 | 鉴权绕过测试（自动发现 session、交换 auth、比对响应） | `AuthTestExecutor` |
| Stage 6 | 综合研判（baseline + 源码 + 鉴权结果） | `FinalVerdictPrompt` |

- 适合**批量系统化分析**，每阶段有独立 LLM 超时（Stage 1 最短，Stage 6 最长）。
- 阶段边界检查取消（`checkCancelled()` 抛 `CancellationException`，`execute()` 统一捕获）。

### Agent 自主模式（`AgentLoop`）

ReAct 循环：LLM 自主选择工具 → 工具执行 → 结果回喂 → 迭代，直到 `submit_report` 或预算/轮次耗尽。与 Pipeline 的区别：不固定阶段，由 LLM 决策；具备 `send_request`/`submit_report` 主动验证能力。

- **Progressive Tool Disclosure**：阶段感知，每轮只暴露 ~15 个相关工具（节省 ~68% schema tokens）。
- **Reuse-Window 软折叠**：端点在 `reuseWindowMinutes` 内被分析过时，注入上次 verdict 到 `buildInitialUserMessage`（可变尾部，保 prefix cache），措辞"请确认/修正而非重新推导"。仅软折叠不硬跳过。
- **Fallback 重建**：未调 `submit_report` 时从思考文本重建 verdict，统一过 `VerdictValidator`（标注"未完成验证"）。

---

## MCP 协议与外脑模式

### 本地 MCP Server（`McpServer`）

- **传输**：`java.net.ServerSocket` 自实现极简 HTTP/1.1（**不依赖 `jdk.httpserver`**，兼容 Burp 精简 JRE）。
- **协议**：JSON-RPC 2.0，公开工具由 `McpTools` 注册。
- **安全门**：每个请求校验 `Origin` / `Host` / `Bearer Token`（启动时 mint 256-bit token）/ `Content-Type`。
- **启停**：即时启停，无需重载扩展；运行状态写入 `~/.api-sentinel/mcp-diagnostic.log`。

### `validate_findings` 外脑证据门禁

面向"外部 harness（Claude Code / Codex）当大脑、插件当证据基础设施"。外部提交 findings + 请求记录 → **两层校验**：

1. **EvidenceSchema 结构校验**（`ai/pipeline/evidence/`）：每种漏洞类型必须携带的证据槽——SQLi 需 baseline/injected/diff/payload，IDOR 需 session_a/session_b/anonymous + 身份三问等。**未登记类型 fail-open 不拦**。
2. **VerdictValidator 真伪校验**：payload 是否真发过、响应是否匹配真实响应、越权双会话、信息级/HIGH-无-confirmed 降级。

返回带 `rejectionReasons` 的结构化 verdict；可选 `persist` 写回端点状态（默认 `false`）。

---

## 错误处理与降级

| 场景 | 策略 |
|------|------|
| LLM 调用失败 | Provider 重试（`HttpRetryHelper` 共享退避/可重试判定）；最终失败→Agent `buildFallbackResult` 从思考文本重建并过校验 |
| Stage 超时 | 每阶段独立超时，超时后该阶段降级、不阻断后续 |
| 预算耗尽 | `budgetMode=ENFORCE` 拦截 LLM；`MONITOR_ONLY` 仅记录不拦截（适用内部无限额度模型） |
| 重复端点分析 | Reuse-Window 软折叠注入上次结论（`<=0` 禁用） |
| 工具结果不可信 | `UntrustedContent` nonce 围栏包裹 HTTP 响应/DOM/源码，防 prompt injection |
| OOB 不可用 | `oobProvider` 可选 `collaborator` 或 `internal`（dnslog） |
| Provider 不可用 | `OllamaProvider.isAvailable()` 10s TTL 缓存，避免每次 3s 探测阻塞选择 |

---

## 安全模型

### 不可信内容隔离（Anti-Hallucination）

`UntrustedContent`：每次分析/循环 mint 128-bit nonce，所有攻击者可控字节（HTTP 响应、工具结果、findings.evidence）用 nonce fence 包裹。`sanitise` 检测并 defang 行内伪造关闭标记。覆盖 Stage 1（`VulnAnalysisPrompt`）、Stage 3（`TestGenPrompt`）、Stage 6（`FinalVerdictPrompt`）、Agent 工具结果（`AgentLoop`）。

### 交叉验证（`VerdictValidator`）

程序化门禁，无法用话术绕过：
- payload 是否真发过、响应是否匹配真实响应
- 越权双会话（K2：attacker==victim 由 `identity_proof` 三问负责）
- 信息级/HIGH-无-confirmed 降级
- 内网 IP carve-out（SSRF 链路返回内网数据时豁免信息级降级）

### 主动工具分级授权

主动/危险工具（`send_request`、`active_probe`、`browser_interact`、代码执行等）执行前经 UI 确认（`CodeExecutionConfirmDialog` / `BrowserInteractConfirmDialog`），支持"本次会话不再询问"。`submit_report` 前置门禁：必须 `heuristic_scan` 过；生成过 payload 须验证 `min(N, 5)` 个。

### 凭据保护

`AppConfig.includeRawCredentialsInLlm` 默认 `false`——Cookie/Authorization 发给外部 LLM 前先经 `RequestRedactor`，需用户显式 opt-in 才透传。

### MCP 扫描 SSRF 防护

`McpSecurityScanner` 扫描前解析主机，拒绝指向云元数据/链路本地地址（169.254/16、0.0.0.0、阿里云 100.100.100.200）的目标；7 端点并发探测，总时长上限 30s。

---

## 配置参数与默认值（`AppConfig`）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `matchMode` | — | 匹配模式（精确/模糊，详见 [FEATURES.md](FEATURES.md)） |
| `sensitiveDetectionEnabled` | true | 敏感信息检测 |
| `unauthorizedDetectionEnabled` | true | 越权检测 |
| `rateLimitPerSecond` | — | 主动请求速率限制 |
| `codeRepos` | — | 代码仓库列表（白盒关联） |
| `aiConfidenceThreshold` | — | AI 置信度阈值 |
| `authSessionACookie/B` | — | 越权测试双会话 Cookie |
| `oobEnabled` / `oobProvider` | — / `collaborator`\|`internal` | OOB SSRF 验证 |
| `highlightEnabled` | — | Burp 请求高亮 |
| `contextWindowTokens` | — | LLM 上下文窗口 |
| `dailyBudgetTokens` | 500,000 | 日 token 预算 |
| `perRequestMaxTokens` | 50,000 | 单次请求上限 |
| `budgetMode` | ENFORCE | `ENFORCE` 拦截 / `MONITOR_ONLY` 仅监控 |
| `includeRawCredentialsInLlm` | false | 凭据是否透传给 LLM |
| `browserFrontendUrl` | — | 前端 Base URL（browser_find_page 反向定位） |

> 配置经 `ConfigManager` 持久化，UI 在 AiSettingsPanel / AuthConfigPanel 编辑。完整字段见 `AppConfig.java`。


---

# 第二部分：代码架构


> 根 [README.md](../README.md) 提供概览；交互式架构图见 [diagrams/](diagrams/README.md)。

本文档描述模块依赖、核心类职责、Repository/事件机制、UI 与数据层交互、扩展点。内容基于当前代码实现。

---

## 顶层包职责

| 包 | 职责 |
|----|------|
| `ai` | LLM Provider 抽象、Agent 循环、6 阶段分析管线、提示构建、预算 |
| `ai/agent` | `AgentLoop`、`AgentController`、多 Agent 协调、子 Agent、反思记忆 |
| `ai/agent/tool` | 50+ Agent 工具、`ToolContext`、`StandardToolRegistry`、渐进式暴露 |
| `ai/pipeline` | `AnalysisPipeline` 6 阶段、`VerdictValidator`、`FinalVerdict`、报告写入 |
| `ai/pipeline/evidence` | `EvidenceSchema` 证据结构约束（外脑门禁） |
| `ai/provider` | `LlmProvider` 接口 + Claude/OpenAI/Ollama/DeepSeek 实现 |
| `active` | 主动探测执行器（CORS/JWT/CRLF/NoSQL/命令注入） |
| `auth` | 越权测试执行器、响应比对 |
| `benchmark` | EasyShop 基准靶场评测 |
| `browser` | Playwright 集成、agent-browser CLI、页面定位/交互/探索 |
| `codeindex` | 源码索引与关联（路由匹配、grep、read_file） |
| `config` | `AppConfig`、`ConfigManager`、`CodeRepo`、登录配置 |
| `detection` | 被动检测器（SQL/堆栈/CORS/JWT/CSRF/…）、Payload 库、攻击类型分类、自定义模板 |
| `detection/template` | `DetectionTemplate`/`TemplateParser`/`TemplateLoader`（类 Nuclei YAML DSL） |
| `event` | `EventBus`、`UiEventBus`、事件类型 |
| `export` | CSV / Markdown / 完整报告导出 |
| `handler` | Burp `HttpHandler`（被动流量入口） |
| `importer` | 流量/扫描结果导入 |
| `intruder` | Burp Intruder 集成 |
| `logging` | `LeveledLogger`（DEBUG/INFO/WARN/ERROR 四级） |
| `matching` | `CompositeMatchEngine`（Trie 精准 + Fuzzy 模糊） |
| `mcp` | `McpServer`（ServerSocket HTTP）、`McpTools`、`McpSecurityScanner`、协议 |
| `model` | `ApiEntry`、`Finding` 等数据模型 |
| `poc` | `PoCGeneratorService`、`ProofOfConcept`（PoC 自动生成） |
| `repository` | `ApiRepository` 接口 + InMemory/Persistent 装饰器 |
| `standalone` | CLI 独立运行模式 |
| `testgen` | `TestCaseService`（Stage 3 载荷生成） |
| `ui` | Swing 界面、Presenter、面板、对话框 |
| `util` | 工具类（HTTP 消息、token 估算等） |

---

## 双分析路径

两条路径共用工具与证据存储，按场景切换：

### 1. 固定管线（`AnalysisPipeline`）
6 阶段顺序执行（流量分析→代码关联→载荷生成→执行→越权→综合研判），`VerdictValidator` 交叉验证产出 `FinalVerdict`。适合**批量系统化分析**。

### 2. 自主 Agent（`AgentLoop` + `AgentController`）
ReAct 循环，LLM 自主选工具迭代，直到 `submit_report` 或预算耗尽。具备主动验证能力。带反思记忆、错误压缩、Plan-then-Execute、PoC 校验等优化。适合**复杂单端点深挖**。

> 多 Agent 协作（`MultiAgentCoordinator`）编排 Planner/Explorer/Executor/Verifier 四角色，每角色独立 `ToolContext`，由 `OrchestrateAgentsTool` 暴露。

---

## 核心类职责

| 类 | 职责 |
|----|------|
| `ApiSentinelExtension` | Burp 入口，装配 Repository/MatchEngine/EventBus/MCP/UI |
| `AnalysisPipeline` | 6 阶段编排，`execute(entry, callback)` 返回 `CompletableFuture<PipelineResult>` |
| `AgentLoop` / `AgentController` | Agent ReAct 循环与门面 |
| `VerdictValidator` | 程序化交叉校验（防话术绕过） |
| `UntrustedContent` | nonce 围栏隔离攻击者可控字节 |
| `McpServer` | ServerSocket HTTP/1.1 + JSON-RPC + 安全门 |
| `McpSecurityScanner` | MCP 端点探测 + SSRF 防护 + 风险评估 |
| `TestCaseService` | Stage 3 载荷生成 |
| `PoCGeneratorService` | 15+ 漏洞类型 PoC 模板生成（转义防注入） |
| `CompositeMatchEngine` | Trie 精准 + Fuzzy 模糊流量匹配 |
| `HeuristicDetector` | 被动检测规则集 |
| `PayloadLibrary` / `AttackType` | 150+ payload、27 攻击类型分类 |
| `LlmProvider`（接口） | 统一 LLM 接口，4 实现 |

---

## Repository 模式与事件驱动

### Repository 装饰器

```
ApiRepository（接口）  ◄── PersistentApiRepository（持久化装饰器，JSON 落盘）
                        ◄── InMemoryApiRepository（内存实现）
```

`ApiEntry` 的 CRUD 与状态写回（VULNERABLE/待评估/安全）经此层。`AgentFacade.executeAgentForEntry` 与 `AnalysisPipeline` 都通过 Repository 读历史、写结论。

### 事件总线

`EventBus`（后台线程）发布领域事件，`UiEventBus` 把 UI 相关事件投递到 EDT：

| 事件 | 触发点 |
|------|--------|
| `ApiMatchedEvent` | 流量匹配到已登记 API |
| `AiAnalysisCompleteEvent` | 分析完成 |
| `ClusterHuntTriggerEvent` | 触发 chain_hunter 子代理 |

Handler 异常以 `e.toString()` + 完整堆栈输出（`System.err`），便于诊断。

---

## UI 层与数据层交互

- **入口**：`ApiSentinelTab`（Burp 自定义 tab）装配各面板。
- **MVP 分层**：`ApiSentinelPresenter` / `AiPresenter` 协调 `ApiTablePanel`（API 表格）、`AiAnalysisPanel`（分析进度与 verdict 卡片）、`AiChatPanel`（对话）。
- **对话桥**：`ChatController` / `ChatInteractionBridge` 连接 Agent 与用户（`askChoice` 弹窗含自由文本输入）。
- **确认对话框**：`CodeExecutionConfirmDialog` / `BrowserInteractConfirmDialog` 守护主动/危险工具。
- **批量**：`BatchOrchestrator` 编排多端点批量分析。

UI 通过 `UiEventBus` 订阅领域事件刷新；工具原文与 LLM 见到的 fenced 文本分离（UI 收原文不影响展示）。

---

## 扩展点

| 扩展点 | 方式 |
|--------|------|
| 新增 Agent 工具 | 实现 `AgentTool` 接口，在 `StandardToolRegistry` 注册；按只读/有状态决定是否进并行集 |
| 渐进式暴露 | `ProgressiveToolDisclosure.PHASE_TOOLS` 配置阶段→工具集 |
| 自定义检测模板 | `custom-templates/*.yaml`，零代码加载（详见 [FEATURES.md](FEATURES.md#自定义检测模板格式)） |
| 自定义敏感规则 | 设置面板 HaE 风格三层格式，保存即生效 |
| MCP 工具 | `McpTools` 注册 JSON-RPC 工具 |
| LLM Provider | 实现 `LlmProvider` 接口 |
| 登录配置 | `~/.api-sentinel/login-profiles.json` 多环境 |

> 完整设计理由见本手册第三部分 ADR，交互式架构图见 [diagrams/](diagrams/README.md)。


---

# 第三部分：架构决策记录


> 记录 API Sentinel 的重要架构决策，避免重复讨论。
> 格式参考 [Michael Nygard's ADR template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)

---

## ADR-001: MCP 化优先于内置 Agent

**状态**: Accepted (2026-09-10)

**背景**: API Sentinel 同时提供内置 AI Agent 对话和 MCP Server 两种接入方式。

**决策**: MCP 化比内置 Agent 更有未来。

**理由**:
- 内置 Agent 天花板受限于所接裸模型，且需自维护整套 ReAct/缓存/上下文
- MCP 化把稀缺能力（白盒审计、浏览器 DOM、证据校验秤、流量资产语义）骑在持续变强的前沿大脑上
- 两者消费同一个工具层；真正的长期投资是工具层 + `validate_findings` 证据校验本身

**后果**:
- 内置 Agent 降级为离线/气隙兜底与自家工具的参考驱动
- MCP 会话化改造已完成 (P0+P1)，解锁全量 50+ 工具

---

## ADR-002: 模型分层策略

**状态**: Accepted (2026-09-10)

**背景**: LLM 调用成本高，需要优化 token 消耗。

**决策**: 
- **降到轻量模型**（结构化/机械/广度，下游有验证 + 防幻觉门兜底）：payload 生成、探索/集群狩猎子 agent
- **始终主模型**（强推理/对抗/判错代价高）：AgentLoop 主循环、最终 verdict、越权仲裁、盲注/SSTI 确认判定

**理由**: 
- payload 生成是机械工作，下游有 send_request + 响应验证兜底
- 判定类节点错误代价极高（误报/漏报），必须用最强模型

**后果**: 
- `modelTieringEnabled` 开关默认关，零风险上线
- 复用现有 `fastModel` 配置，不新增字段

---

## ADR-003: 统一写回主干

**状态**: Accepted (2026-09-10)

**背景**: MCP 接入的外部大脑分析结果不同步到 UI 表格。

**决策**: 所有写操作经 repository → `fireChange()` → UI 自动刷新，杜绝旁路写入。

**理由**:
- 旁路 mutate + 手动刷新导致数据不一致
- `fireChange()` 是已验证的可靠机制

**后果**:
- MCP 会话的 ToolContext 必须 `setApiRepository`
- `validate_findings` 的 `persist` 默认改为 `true`
- `findByPath` 为空时自动创建 entry

---

## ADR-004: 证据校验强制落库

**状态**: Accepted (2026-09-10)

**背景**: `validate_findings` 的 `persist` 参数默认 `false`，导致外部大脑的校验结果不落库。

**决策**: `persist` 默认 `true`；关联到 path 时自动落库。

**理由**:
- 不落库 = 证据链断裂
- 外部大脑自己发出的流量可能不在 repository 中，需要自动创建 entry

**后果**:
- `persistVerdict` 在 `findByPath` 为空时自动创建 entry 再挂 verdict

---

## ADR-005: 主动工具分级授权

**状态**: Accepted (2026-09-10)

**背景**: MCP 暴露 `send_request`、`active_probe` 等危险工具给外部进程。

**决策**: 
- `mcpAllowActiveTools` 开关默认**关**
- 危险工具需显式开启
- 只读白盒 + `browser_render/discover/dom_xss` 常开

**理由**:
- 外部大脑可借 Burp 发任意攻击流量
- loopback + token 已有基础防护，但需额外授权层

**后果**:
- 配置面板新增勾选框
- 已连接客户端需重新 `tools/list` 才能看到新工具

---

## ADR-006: 不做 SSE 实时推送

**状态**: Rejected (2026-09-10)

**提议**: MCP Server 支持 SSE 推送分析进度。

**拒绝理由**:
- `analyze_api` 阻塞等结果，后台事件已由 `get_latest_events` 轮询覆盖
- 裸 socket HTTP server 上加 SSE 流复杂度高、价值低
- 保留 poll 模型；如需 push 语义再做

---

## ADR-007: 浏览器引擎复用 Chromium

**状态**: Accepted (历史决策)

**背景**: 需要浏览器能力进行 DOM XSS 检测、自动登录、前端探索。

**决策**: 复用 Playwright + Chromium，不自研浏览器引擎。

**理由**:
- 自研浏览器维护成本极高且无差异化
- Playwright 已提供稳定的 API
- 浏览器引擎隔离在安全信任边界内

---

## ADR-008: 国际化覆盖策略

**状态**: Accepted

**决策**: 
- 全量国际化所有 UI 硬编码中文
- 支持中英文切换
- 优先完成用户日常看到的主面板

> 国际化为持续进行的工作，进度追踪见内部 `docs/plan/i18n-progress.md`（不随发布公开）。


---

# 第四部分：开发工具链指南


> 本文档介绍开发环境配置、IDE 设置、Git hooks、常用脚本等开发者工具链内容。

---

## 🔧 IDE 配置

### IntelliJ IDEA（推荐）

#### 必装插件

- **Lombok**（如果项目使用 Lombok）
- **EditorConfig**（自动应用 .editorconfig 配置）
- **SonarLint**（实时代码质量检查）
- **GitToolBox**（Git 增强）

#### 代码风格设置

1. **File → Settings → Editor → Code Style → Java**
   - Tab size: 4
   - Indent: 4
   - Continuation indent: 8
   - Right margin (columns): 120

2. **Wrapping and Braces**
   - Hard wrap at: 120
   - Wrap on typing: Yes

3. **Imports**
   - Class count to use import with '*': 999（不使用通配符导入）
   - Names count to use static import with '*': 999

#### 编码设置

1. **File → Settings → Editor → File Encodings**
   - Global Encoding: UTF-8
   - Project Encoding: UTF-8
   - Default encoding for properties files: UTF-8
   - Transparent native-to-ascii conversion: ✓

#### 检查配置

1. **File → Settings → Editor → Inspections**
   - 启用 Java → Code style issues → "Unused import"
   - 启用 Java → Code style issues → "Missing @Override"
   - 启用 Java → Probable bugs → "Nullability problems"

### VS Code（轻量替代）

#### 推荐扩展

```json
{
  "recommendations": [
    "vscjava.vscode-java-pack",
    "redhat.java",
    "vscjava.vscode-gradle",
    "editorconfig.editorconfig",
    "sonarsource.sonarlint-vscode",
    "gabrielbb.vscode-lombok"
  ]
}
```

#### settings.json

```json
{
  "java.format.settings.url": ".vscode/java-formatter.xml",
  "editor.formatOnSave": true,
  "editor.tabSize": 4,
  "editor.insertSpaces": true,
  "files.trimTrailingWhitespace": true,
  "files.insertFinalNewline": true,
  "files.trimFinalNewlines": true,
  "[java]": {
    "editor.tabSize": 4,
    "editor.insertSpaces": true
  },
  "[json]": {
    "editor.tabSize": 2
  },
  "[markdown]": {
    "editor.wordWrap": "on",
    "editor.trimTrailingWhitespace": false
  }
}
```

---

## 🪝 Git Hooks

### 方案 1：手动安装（推荐开发阶段）

创建 `.git/hooks/pre-commit`：

```bash
#!/bin/bash
set -e

echo "🔍 Running pre-commit checks..."

# 1. 编译检查
echo "📦 Compiling..."
./gradlew compileJava compileTestJava --quiet || {
  echo "❌ Compilation failed"
  exit 1
}

# 2. 单元测试
echo "🧪 Running tests..."
./gradlew test --quiet || {
  echo "❌ Tests failed"
  exit 1
}

# 3. 代码风格（如果有 Checkstyle/SpotBugs）
# echo "🎨 Checking code style..."
# ./gradlew checkstyleMain --quiet || exit 1

# 4. 禁止提交敏感文件
echo "🔒 Checking for secrets..."
if git diff --cached --name-only | grep -qE '(ai-config\.json|credentials\.json|secrets\.json|\.pem|\.key)$'; then
  echo "❌ Attempting to commit sensitive files!"
  echo "   Blocked files:"
  git diff --cached --name-only | grep -E '(ai-config\.json|credentials\.json|secrets\.json|\.pem|\.key)$'
  exit 1
fi

# 5. 禁止提交大文件（>1MB）
echo "📏 Checking file sizes..."
MAX_SIZE=1048576  # 1MB
for file in $(git diff --cached --name-only); do
  if [ -f "$file" ]; then
    size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
    if [ "$size" -gt "$MAX_SIZE" ]; then
      echo "❌ File too large: $file ($size bytes)"
      exit 1
    fi
  fi
done

echo "✅ All checks passed!"
```

**安装**：
```bash
chmod +x .git/hooks/pre-commit
```

### 方案 2：使用 pre-commit 框架（推荐团队协作）

安装 [pre-commit](https://pre-commit.com/)：

```bash
pip install pre-commit
```

创建 `.pre-commit-config.yaml`：

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
        args: ['--maxkb=1024']
      - id: check-merge-conflict
      - id: detect-private-key

  - repo: https://github.com/macisamuele/language-formatters-pre-commit-hooks
    rev: v2.12.0
    hooks:
      - id: pretty-format-java
        args: [--autofix]

  - repo: local
    hooks:
      - id: gradle-test
        name: Gradle Test
        entry: ./gradlew test --quiet
        language: system
        types: [java]
        pass_filenames: false
```

**安装**：
```bash
pre-commit install
pre-commit run --all-files  # 首次运行
```

---

## 📜 常用脚本

### 构建脚本

```bash
# 完整构建（编译 + 测试 + 打包）
./gradlew clean build shadowJar

# 仅编译（快速检查语法）
./gradlew compileJava

# 仅测试
./gradlew test

# 仅打包（跳过测试）
./gradlew shadowJar -x test

# 生成测试报告
./gradlew test jacocoTestReport
open build/reports/tests/test/index.html
```

### 运行脚本

```bash
# 启动演示靶场
cd easyshop-app
mvn spring-boot:run

# 在另一个终端运行基准测试
BENCHMARK_ENABLED=true ./gradlew test --tests BenchmarkIntegrationTest

# 查看基准测试结果
cat build/benchmark-report.txt
```

### 代码质量脚本

```bash
# 运行所有检查（编译 + 测试 + 静态分析）
./gradlew check

# 生成代码覆盖率报告（如果配置了 JaCoCo）
./gradlew jacocoTestReport
open build/reports/jacoco/test/html/index.html

# 查找未使用的导入
grep -r "^import " src/main/java --include="*.java" | awk '{print $2}' | sort | uniq -c | sort -rn

# 统计代码行数
find src/main/java -name "*.java" -exec wc -l {} + | tail -1

# 查找 TODO/FIXME
grep -rn "TODO\|FIXME\|XXX" src/main/java
```

### Git 脚本

```bash
# 查看提交历史（带图形）
git log --graph --oneline --all

# 查看未提交的文件
git status

# 查看差异
git diff
git diff --cached  # 已暂存的更改

# 清理未跟踪文件
git clean -fd

# 重置到最近一次提交
git reset --hard HEAD
```

---

## 🔍 调试技巧

### 远程调试（调试 Burp 插件）

1. 启动 Burp 时附加调试参数：
```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar burpsuite_pro.jar
```

2. 在 IDE 中创建 Remote Debug 配置：
   - Host: localhost
   - Port: 5005

3. 设置断点，开始调试

### 日志调试

API Sentinel 日志位置：
```
~/.api-sentinel/logs/api-sentinel.log
```

查看实时日志：
```bash
tail -f ~/.api-sentinel/logs/api-sentinel.log
```

调整日志级别（在代码中）：
```java
import java.util.logging.*;

Logger logger = Logger.getLogger(MyClass.class.getName());
logger.setLevel(Level.FINE);  // DEBUG 级别
logger.fine("Debug message");
```

### MCP Server 调试

测试 MCP 连接：
```bash
# 列出工具
curl -X POST http://127.0.0.1:9877/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# 调用工具
curl -X POST http://127.0.0.1:9877/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_apis","arguments":{}}}'
```

查看 MCP 诊断日志：
```bash
cat ~/.api-sentinel/mcp-diagnostic.log
```

---

## 📊 性能分析

### 使用 VisualVM

1. 下载 [VisualVM](https://visualvm.github.io/)
2. 启动 Burp（带 API Sentinel）
3. 在 VisualVM 中连接到 Burp 进程
4. 查看 CPU / 内存 / 线程

### 使用 JProfiler（商业）

1. 启动 JProfiler
2. Attach 到 Burp 进程
3. 录制性能数据
4. 分析热点方法

### 使用 Async Profiler（开源）

```bash
# 下载 async-profiler
wget https://github.com/async-profiler/async-profiler/releases/download/v3.0/async-profiler-3.0-linux-x64.tar.gz
tar xzf async-profiler-3.0-linux-x64.tar.gz
cd async-profiler-3.0-linux-x64

# 找到 Burp 的 PID
jps -l | grep burp

# 录制 30 秒 CPU 火焰图
./profiler.sh -d 30 -f flamegraph.html <PID>

# 打开火焰图
open flamegraph.html
```

---

## 🧪 测试最佳实践

### 测试命名

```java
@Test
void testMyFeature_withValidInput_shouldSucceed() { }

@Test
void testMyFeature_withInvalidInput_shouldThrowException() { }

@Test
void testMyFeature_whenConditionMet_shouldReturnExpected() { }
```

### 测试结构（Arrange-Act-Assert）

```java
@Test
void testCalculator_add() {
    // Arrange
    Calculator calc = new Calculator();
    
    // Act
    int result = calc.add(2, 3);
    
    // Assert
    assertEquals(5, result);
}
```

### Mock 外部依赖

```java
@Test
void testLlmProvider_withMockedHttpClient() {
    // Mock HTTP client
    HttpClient mockClient = mock(HttpClient.class);
    when(mockClient.send(any(), any())).thenReturn(mockResponse);
    
    // Create provider with mocked client
    LLMProvider provider = new ClaudeProvider(mockClient);
    
    // Test
    String result = provider.chat("Hello");
    
    // Verify
    assertNotNull(result);
    verify(mockClient).send(any(), any());
}
```

---

## 📚 相关文档

- [CONTRIBUTING.md](../CONTRIBUTING.md) — 贡献指南
- [ARCHITECTURE.md](ARCHITECTURE.md) — 本手册（含规格/代码架构/ADR/开发）
- [examples/](../examples/README.md) — 配置示例

---

## ❓ 常见问题

**Q: 为什么我的代码风格和别人不一样？**  
A: 确保安装了 EditorConfig 插件，它会自动应用 `.editorconfig` 配置。

**Q: Git hooks 不生效？**  
A: 检查 `.git/hooks/pre-commit` 是否有执行权限：`chmod +x .git/hooks/pre-commit`

**Q: 测试运行太慢？**  
A: 使用 `./gradlew test --tests SpecificTestClass` 只运行特定测试类。

**Q: 如何跳过 Git hooks？**  
A: `git commit --no-verify`（不推荐常规使用）。
