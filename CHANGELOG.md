# Changelog

API Sentinel 的所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/)，遵循[语义化版本](https://semver.org/)。

---

## [1.1]

> 当前版本。全量 1231 测试通过（1233 用例，2 跳过，0 失败）。

### 新功能

**浏览器能力集成**（集成 Playwright-Java 1.49.0）
- 客户端安全测试：`browser_discover`（XHR/Fetch 捕获 + JS Bundle 分析 + 路由提取）、`browser_render`（DOM/console/CSP）、`browser_dom_xss`（DOM XSS 检测）、`register_discovered_apis`
- 反向定位与交互：`browser_find_page`（三级定位）、`browser_interact`（UI 操作序列 + 确认弹窗）
- 自动化流程：`browser_login`（自动登录 + Cookie 注入 + 多环境登录配置）、`browser_explore`（LLM 多层导航 + 7 天缓存）、`browser_auto_crawl`（无人值守全站）
- DeepSeek 视觉模型（多模态 + 探索引擎视觉模式）
- 浏览器工具优化：DomSimplifier Vue/React 检测（13 CSS 模式 + `cursor:pointer` 后扫）、新动作类型（hover/scroll/upload/press_key）、DOM 差异分析、智能回溯、智能等待

**agent-browser CLI 集成**（后续触发 12x 性能）
- `extract_auth` / `capture_requests` / `trigger_apis`，策略优先级：直接 HTTP > UI 重放 > 浏览器探索
- 新增 API 模板提取、认证上下文、捕获请求、Cookie 信息、CLI 封装等服务类
- 探索缓存同时缓存 UI 路径与 API 模板，100 个 API 后续触发 25 分钟 → 2 分钟

**8 项能力增强**
- 攻击类型分类（27 种，OWASP API Top 10 全覆盖）+ Payload 库（150+，模板渲染）
- IDOR/BOLA 检测增强（6 种 ID 格式 + 16 种 owner 字段 + 置信度评分）
- PoC 自动生成（15+ 漏洞类型，cURL + Python + 复现步骤 + Markdown 报告）
- 多 Agent 协作（规划/侦察/执行/验证四角色工作流）
- 自定义检测模板（类 Nuclei YAML DSL，regex/word/status 匹配器 + 3 示例）
- MCP 安全扫描（7 端点探测 + 风险评估）
- Mass Assignment / 过度数据暴露检测（两种新模式）

**工具与检测优化**
- 白盒审计 SinkMap 扩展 5 类：XXE、SSTI、CRLF、开放重定向、NoSQL；SQL 补 MyBatis `${}` 插值与 `Statement.execute()`
- `send_request` 支持 multipart（自动 boundary + `file:@` 上传）与 `timeout_ms`（1s–120s），批量模式防无限挂起
- `active_probe` 命令注入检测：响应型 5 种 shell 标记 + 时序型 `;sleep` 基线比对
- 业务逻辑精度：`CountDownLatch` 并发竞态 + 篡改值响应校验
- `heuristic_scan` 4 类新模式：NoSQL 操作符、URL 敏感参数、GraphQL/introspection、开放重定向
- `chain_hunter` 成本控制：`max_iterations` 参数 + 兄弟去重 + 结果上限 8K→16K
- 越权检测 IDOR 扫描从仅 URL path 扩展到 query 参数和 JSON body，覆盖 18 种常见 ID 参数名
- 越权检测 `findAlternateId()` 改为 path-pattern 优先匹配，`pickTemplates()` 按 method+path 去重
- 越权检测新增 `verifySessionAlive()` 前置检查 session token 过期，避免 false SAFE；请求限速 150ms 降低 WAF 触发

**MCP 外脑模式**
- MCP Server（ServerSocket HTTP/1.1 + JSON-RPC + 安全门 + 即时启停）
- `validate_findings` 证据门禁：证据结构校验 + 真伪校验，可选写回端点状态

**Agent 引擎优化**（参考 LangGraph/AutoGen/CrewAI/Reflexion/MemGPT）
- 渐进式工具暴露（43→~15 工具/轮，省 68% schema token）、反思记忆、错误压缩、发现存储、状态追踪、分析 Profile、先规划后执行、PoC 校验、按需加载工具组

**越权检测凭证模型升级**
- 新增 `SessionCredentials` record：统一承载 Cookie + Auth Headers（Authorization / X-Token / X-Access-Token / Token / API-Key / X-API-Key），Bearer-only 用户可完整配置手动会话
- 新增 `SessionConfig` record：bundling slot / label / credentials / domain / level / group，支持多会话两两配对测试
- `AppConfig` / `AnalysisConfig` 新增会话 C 字段 + 每个会话的 domain（域名作用域）、level（权限等级 HIGH/MEDIUM/LOW）、group（租户/组标识）字段
- `hasManualAuthSessions()` 改为 Cookie 或 Auth Headers 任一非空即有效；`countConfiguredSessions()` 返回 1-3
- `AnalysisConfig.forPipeline(AppConfig, boolean)` 静态工厂统一 5 个调用点的凭证映射，杜绝字段漂移
- 越权配置面板改为 3 列布局（A/B/C），每列含标签 + 域名 + 权限等级下拉框 + 组/租户文本框 + Cookie 区 + Auth Headers 区
- 面板首次显示时自动检测 Proxy History 填充会话（无需手动点按钮），域名自动从请求 Host 提取
- `AuthTestExecutor.executePairwise(List<SessionConfig>, targetDomain)` 新方法：N 个会话两两配对（C(N,2)），按域名过滤，聚合最严判定。每对自动标注测试类型（水平越权/垂直越权/跨租户越权）基于权限等级+组字段推断
- HTTP History 右键菜单新增"提取为会话 A/B/C"，一键写入越权配置

- 越权配置面板新增会话验证功能：每个会话列标题旁有 LED 指示灯（绿=有效 / 红=过期 / 黄=不可达 / 灰=未验证），保存后自动验证，"验证会话"按钮手动触发。向各会话域名发送带凭证的 GET 请求，根据响应码判断 token 是否仍然有效

**导入与批量操作**
- 导入 API 支持域名信息：`METHOD /path domain` 三段格式（域名可选，第三段自动识别）
- API 表格多选右键"批量设置域名"：一次为多个接口统一设置域名
- 批量设置域名快捷键：`Ctrl/Cmd+Shift+D`（选中 2+ 行后可用）。修复三个叠加 bug：① `fireTableDataChanged` 后 view-model 索引映射失效（改用 ApiEntry 引用快照）② `refreshFromRepository` 重建 displayList 时重新应用域名过滤器，设好域名的行被过滤掉（改回 `fireTableDataChanged`）③ `updateDomain(path)` 按 path 查找只返回第一个匹配，同 path 不同 method（如 GET+POST 同路径）只有第一个被更新（新增 `updateDomain(ApiEntry, domain)` 按引用更新，单元格编辑也同步修复）
- Burp HTTP History 右键菜单精简：移除"标记漏洞"子菜单、"标记状态"子菜单和"生成 Bambda 代码"，新增"提取为会话 C"。"Pipeline 分析"更名为"AI 分析"（跟随工具栏 Agent/Pipeline 模式切换）。多选提取会话时合并所有请求的凭证（cookie + auth headers 去重合并）并显示 toast 预览。最终菜单 5 项：AI 分析 / 添加到监控列表 / 提取为会话 A·B·C

### 安全加固

**防幻觉 nonce 围栏**（128-bit）
- 分析各阶段 prompt 与 Agent 工具结果均用 nonce 围栏包裹攻击者可控字节（HTTP 响应/DOM/源码/工具结果），检测并中和行内伪造关闭标记

**交叉校验**（程序化门禁，无法话术绕过）
- payload 是否真发过 / 响应是否匹配 / 越权双会话 / 信息级·HIGH-无-confirmed 降级 / 内网 IP 豁免（SSRF 链路）
- `submit_report` 行为语义门禁（按 finding 计数，封顶 5）
- 主动工具分级授权（代码执行 / 浏览器交互确认弹窗）

**新功能风险面加固**
- MCP 扫描 SSRF 防护（拒绝云元数据/链路本地地址）+ 总超时
- PoC 生成命令/代码注入防护（shell 与 Python 字符串转义 + JSON 解析）
- 自定义正则 ReDoS 防护（长度与目标截断 + 灾难性回溯拒绝）

**凭据保护**：Cookie/Authorization 发给外部 LLM 前先过滤，默认不透传

### 问题修复

- MCP Server 在 Burp 内启动失败：精简 JRE 不含 httpserver 模块 → 改用 ServerSocket 自实现 HTTP/1.1，保留全部安全门
- Bearer-token / X-Token 用户越权测试完全失效：`AuthBypassTool` 和 `AnalysisPipeline` fallback 路径写死 `Map.of()` 丢弃 auth headers（根因修复）
- 历史流量对话框"提取为会话 A/B"对 Bearer 请求报"该请求没有 Cookie"：改为同时提取 Cookie + Auth 头
- 越权配置面板自动检测成功但面板空白：Bearer-only 会话的 `toCookieHeaderValue()` 返回空字符串（改为双通道填充）
- `hasManualAuthSessions()` 仅检查 Cookie 导致 Bearer-only 配置被忽略（改为 Cookie 或 Auth Headers 任一非空）
- 越权测试 IDOR 轮次仅扫描 URL path 中的资源 ID（扩展到 query 参数和 JSON body）
- `findAlternateId()` 取 session B 任意请求的第一个不同 ID（改为 path-pattern 优先匹配）
- `pickTemplates()` 仅按 path 去重漏掉 method 维度（改为 method+path 去重）
- 自定义模板正则不反转义 YAML 双引号字符串 → 内置模板正则恢复匹配
- Agent 兜底重建路径强制过交叉校验
- 内网 IP 程序化兜底
- 响应相似度阈值长度自适应（短响应提高阈值，防误判）
- UI 进度条完成态隐藏
- 引用已移除匹配模式阻塞编译
- 报告风险统计不汇总 / 降级审计轨迹丢失 / 级联污染 / 探针污染清单 / 概览口径不一致
- ReplayDialog 无原始请求时用 ApiEntry 构建模板（修 "HTTP service cannot be null"）
- RepeaterPanel 用 `showsAsVerified` 替代 `anomalyDetected` 显示已确认 payload
- 对话桥 `askChoice` 增加自由文本输入
- 多 payload 匹配 + 确认兜底

### 代码质量

- 发现存储线程安全（并发集合 + 原子计数）
- 重试逻辑与上下文构建去重（三 Provider / Agent+Pipeline 共享）
- 事件总线异常完整堆栈
- Agent 跨 run 复用上次结论（软折叠，保前缀缓存命中）

### 性能

- 检测正则预编译缓存（复用编译结果）
- MCP 扫描并发化（7 端点 4 线程，最坏 70s→~10s）
- Ollama 可用性缓存（10s TTL）
- Payload 库已是静态查表，无需额外缓存

### 测试

| 轮次 | 内容 | 用例 |
|------|------|------:|
| P0 | 5 工具 + 协调器单测补齐 | +93 |
| P1 | SSRF / 注入 / ReDoS 防护测试 | +24 |
| P2 | 3 端到端集成测试 | +14 |
| P3 | 正则缓存 + MCP 并发 | +1 |
| P4 | i18n / 浏览器 / bug 修复补充测试 | +90 |

全量 1009 → 1231 通过、0 失败（+222）。

### 构建与文档

- 版本号 1.0→1.1，Playwright 重定位打包，shadowJar 构建
- EasyShop 靶场：重命名 demo-vuln-app → easyshop-app，扩充种子数据；新漏洞类型（命令注入/NoSQL/CRLF/优惠券重放/影子 API）；新工具接口与状态重置；SPA 7 页 100% 覆盖；ground-truth 53 端点（CWE/CVSS/OWASP），Quick 35 + Full 53 模式
- 文档聚合为 4 份主文档（功能参考 / 架构手册 / 浏览器手册 / 第三方致谢），开发过程文档完成后即删

### 参考项目

- API 安全：OWASP API Security Top 10、idor-detector、BOLA-Lens
- AI 驱动：clairvoyance、pentestgpt、zap-ai-extensions
- Burp 扩展：burp-ai-assistant、burp-vuln-scanner
- 浏览器：agent-browser、Playwright-Java
- MCP：mcp-scanner、mcp-security-notifications
- PoC / 多 Agent / 模板：Strix、PentAGI、Nuclei
- 完整借鉴清单与许可证见 [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md)

---

## [1.0.0]

首版发布，奠定核心基线：

- **流量捕获与接口归一化**：Burp 代理被动监听，Trie 精准 + 模糊匹配、`{id}` 参数化、同模式聚合
- **Pipeline 6 阶段固定流水线**：流量分析 → 代码关联 → 载荷生成 → 执行 → 越权 → 综合研判
- **Agent ReAct 自主循环**：LLM 自主调度工具迭代分析，推理过程可见
- **三种分析模式**：Pipeline 固定流水线 / Agent 自主 / AI 对话协同
- **越权测试**：多 session 比对 + IDOR 资源 ID 替换 + 未授权访问 + 响应相似度判定 + 灰色区间 AI 仲裁
- **OOB SSRF 带外验证**：Collaborator 或内部 dnslog 探测
- **代码仓库白盒关联**：路由匹配、源码 grep、read_file
- **本地零成本被动检测**：SQL 错误、堆栈、安全头、CORS、JWT、CSRF、敏感信息等正则规则实时扫描
- **敏感信息检测**：HaE 风格三层格式（主正则 + 排除过滤 + 作用域）
- **WAF 识别与编码绕过**：厂商签名被动识别 + 被拦 payload 编码变体重试
- **内嵌 Repeater 与测试用例管理**：一键复现、payload 验证状态追踪
- **报告导出**：CSV / Markdown / 完整 HTML 报告


