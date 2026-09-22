# API Sentinel 功能参考

> 本文档是 [README.md](../README.md) 的补充，包含被动检测规则详情、敏感信息规则格式、Agent 工具参数说明等查阅型参考内容。
>
> 📐 **架构与设计文档索引**：
> - [ARCHITECTURE.md](ARCHITECTURE.md) — 规格与代码架构、ADR 决策、开发工具链（四合一）
> - [diagrams/](diagrams/README.md) — 交互式架构图（组件总览、时序、MCP 会话、数据流）

## 目录

- [被动检测规则详情](#被动检测规则详情)
- [敏感信息规则格式](#敏感信息规则格式)
- [Agent 工具参数说明](#agent-工具参数说明)
- [WAF 识别厂商列表](#waf-识别厂商列表)
- [组件指纹列表](#组件指纹列表)
- [报告导出格式](#报告导出格式)

---

## 被动检测规则详情

### SQL 错误信息检测

| 数据库 | 签名示例 | 检测方式 |
|--------|----------|----------|
| MySQL | `SQL syntax.*MySQL` / `mysql_fetch` / `MySQLSyntaxErrorException` | 精确引擎签名，避免"mysql"纯文本提及误报 |
| PostgreSQL | `org.postgresql` / `PSQLException` / `ERROR:.*syntax error` | 异常类名 + 错误消息模式 |
| Oracle | `ORA-[0-9]{4,5}` / `OracleDatabaseException` / `PLS-` | ORA 错误码 + PLS 异常 |
| SQL Server | `SQLServerException` / `com.microsoft.sqlserver` / `Incorrect syntax near` | 异常类名 + T-SQL 错误消息 |
| SQLite | `SQLiteException` / `SQLite\.Exception` / `near ".*": syntax error` | 异常类名 + 语法错误模式 |
| JDBC Generic | `java\.sql\.SQLException` / `org\.hibernate\.exception` / `JDBCConnectionException` | 通用 JDBC 异常类名 |

### 堆栈跟踪

| 语言 | 签名 | 说明 |
|------|------|------|
| Java | `at com\.\w+\.` / `Caused by:` / `\tat java\.` | 标准 Java 堆栈格式 |
| Python | `File ".*", line \d+` / `Traceback \(most recent call last\):` | Python traceback 格式 |
| C# | `at System\.` / `at Microsoft\.` / `Server Error in '\/' Application` | .NET 堆栈格式 |

### 服务器版本信息

| 检测项 | 检测位置 | 示例 |
|--------|----------|------|
| Server 头 | 响应头 `Server` | `Apache/2.4.41 (Ubuntu)` |
| X-Powered-By | 响应头 `X-Powered-By` | `PHP/7.4.3` / `ASP.NET` |
| X-AspNet-Version | 响应头 `X-AspNet-Version` | `4.0.30319` |
| X-AspNetMvc-Version | 响应头 `X-AspNetMvc-Version` | `5.2` |

### 调试模式

| 框架 | 检测内容 | 说明 |
|------|----------|------|
| Spring Boot | `Whitelabel Error Page` | Spring Boot 默认错误页 |
| Django | `DEBUG.*=.*true` / `Django settings exposed` | Django debug 模式 |
| Laravel | `Whoops! There was an error` / `Environment &amp; details` | Laravel debug 页 |
| Generic | `debug=true` / `trace=true` / `dump=true` | URL 参数调试模式 |

### 内网 IP 泄露

| 类型 | 正则 | 说明 |
|------|------|------|
| A 类 | `(^|[^\d.])10\.\d{1,3}\.\d{1,3}\.\d{1,3}($|[^\d.])` | 带边界锚点防版本号误报 |
| B 类 | `(^|[^\d.])172\.(1[6-9]\|2[0-9]\|3[01])\.\d{1,3}\.\d{1,3}($|[^\d.])` | 172.16-31.x |
| C 类 | `(^|[^\d.])192\.168\.\d{1,3}\.\d{1,3}($|[^\d.])` | 192.168.x.x |

### CORS 配置

| 检测项 | 风险 | 说明 |
|--------|------|------|
| `*` + credentials | MEDIUM | `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`（浏览器会忽略，降级） |
| Origin 反射 | HIGH | `Origin` 请求头值被精确反射到 `Access-Control-Allow-Origin` |
| null Origin | MEDIUM | `Access-Control-Allow-Origin: null` |

### JWT 安全

| 检测项 | 说明 |
|--------|------|
| alg:none | 无签名算法 |
| 缺过期时间 | 无 `exp` 声明 |
| 内嵌 jwk | 内嵌公钥 |
| jku/x5u 注入 | 外部密钥引用 |
| kid 注入 | 密钥 ID 注入 |
| 多 token 全检 | 同时检查 Cookie 和 Authorization 头中的 token |
| HS256 标注 | 对称签名算法标注 |

### CSRF

检测条件：状态变更方法（POST/PUT/DELETE/PATCH）+ Cookie 认证（`Authorization: Bearer` 不算）+ 无 CSRF Token（`X-CSRF-Token` / `X-XSRF-TOKEN` / `_csrf` / `csrftoken` / `__RequestVerificationToken`）

### 请求走私

| 检测项 | 说明 |
|--------|------|
| CL + TE 共存 | 同时存在 `Content-Length` 和 `Transfer-Encoding` |
| 重复 CL | 多个 `Content-Length` 头 |

### 危险文件上传

检测可执行扩展名上传成功：`jsp` / `jspx` / `php` / `phtml` / `asp` / `aspx` / `ashx` / `asa` / `cer` / `cdx` / `exe` / `dll` / `so` / `sh` / `pl` / `py` / `cgi` / `war` / `jar`

### 反序列化

| 类型 | 签名 |
|------|------|
| Java 序列化 | 魔术字节 `aced0005`（hex） |
| .NET ViewState | `__VIEWSTATE` 参数含 base64 编码数据 |

### 安全头缺失

仅在 HTML 2xx 响应中检测。检测以下头部缺失：

| 头 | 说明 |
|----|------|
| `Strict-Transport-Security` | HSTS |
| `Content-Security-Policy` | CSP |
| `X-Frame-Options` | 点击劫持防护 |
| `X-Content-Type-Options` | MIME 嗅探防护 |
| `Referrer-Policy` | 引用来源策略 |

---

## 敏感信息规则格式

API Sentinel 采用 **HaE 风格三层格式**（主正则 + 排除过滤 + 作用域），内置 38 条规则。用户自定义规则在设置面板中添加，保存后立即生效。

### 规则结构

```json
{
  "name": "规则名称",
  "regex": "主正则表达式",
  "exclude": "排除过滤正则（可选）",
  "scope": "response | request | any"
}
```

### 内置规则覆盖

| 类别 | 规则示例 | 数量 |
|------|----------|------|
| 组件指纹 | Swagger UI、Shiro RememberMe、Druid、Actuator、Vite、Ueditor、上传表单、自定义 URL Scheme | 8 |
| 漏洞线索 | ViewState 反序列化、passwd/win.ini 泄露、Source Map 泄露、调试逻辑参数、URL 作为参数值 | 6 |
| 云服务密钥 | AWS/GCP/Azure/Heroku Key、GitHub/GitLab/Slack/Stripe Token、企业微信、SSH 私钥 | 13 |
| 认证凭证 | JWT、密码字段、Authorization 头、敏感字段 | 4 |
| 数据库连接 | JDBC 连接串 | 1 |
| 个人信息 | 身份证号、手机号、邮箱 | 3 |
| 网络/系统信息 | 内网 IP、MAC 地址、Windows 路径 | 3 |

### 自定义规则示例

```json
{
  "name": "自定义 Secret Key",
  "regex": "(secret[_-]?key|api[_-]?secret)\\s*[:=]\\s*['\"]([a-zA-Z0-9+/=]{20,})['\"]",
  "exclude": "",
  "scope": "response"
}
```

---

## Agent 工具参数说明

### heuristic_scan

无参数。直接调用，返回所有被动检测结果的 JSON 数组。检测范围：SQL 错误、堆栈跟踪、信息泄露、CORS 误配、安全头缺失、CSRF、请求走私、危险上传、反序列化、NoSQL 操作符（$ne/$gt 等）、GraphQL/introspection、URL 敏感参数泄露、开放重定向。

### analyze_traffic

无参数（使用当前绑定的 API 入口的请求/响应）。返回 `AnalysisResult` JSON。

### search_source_code

无参数（使用当前 API 路径自动匹配路由）。返回匹配到的源码片段。

### read_file

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 相对于已索引仓库根目录的文件路径 |
| `start_line` | number | 否 | 起始行号（1-based） |
| `end_line` | number | 否 | 结束行号（1-based） |

### grep_repo

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `pattern` | string | 是 | 正则表达式 |

### generate_payloads

无参数。基于当前已收集的 findings 生成测试用例。必须先调用 `analyze_traffic` 或 `heuristic_scan` 获得发现。

### send_request

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | string | 是 | HTTP 方法 |
| `path` | string | 是 | 请求路径 |
| `headers` | string | 否 | 自定义请求头（`Key: Value` 每行一个） |
| `body` | string | 否 | 请求体 |
| `multipart` | boolean | 否 | 为 true 时 body 按 multipart 字段格式解析（`field1=value1\nfield2=value2`），自动生成 boundary。用 `file:@/path/to/file` 上传文件 |
| `timeout_ms` | integer | 否 | 请求超时毫秒数（默认 30000，最大 120000） |
| `use_original_auth` | boolean | 否 | 是否携带原始认证头（默认 true） |
| `payloads` | array | 否 | 批量并发变体数组 |
| `host` | string | 否 | 目标 host:port（无流量时指定） |

### test_auth_bypass

无参数。自动从代理历史发现 session 并执行越权测试。

### active_probe

无参数。按触发条件自动执行：CORS（Origin 头存在）、JWT（检测到 JWT token）、CRLF（请求含换行字符）、NoSQL（请求体含 JSON 操作符）、命令注入（shell 元字符 canary + `;sleep` 时序检测）。

### fingerprint_components

无参数。从已捕获的响应被动识别，零请求。

### verify_boolean_blind

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `param_name` | string | 是 | 参数名 |
| `param_value` | string | 是 | 当前参数值 |
| `param_location` | string | 否 | 参数位置：`query` / `body` / `header`（默认 `query`） |
| `db_type` | string | 否 | 数据库类型：`mysql` / `postgres` / `mssql` / `oracle` / `sqlite` / `auto`（默认 `auto`） |

### verify_timing_blind

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `param_name` | string | 是 | 参数名 |
| `param_value` | string | 是 | 当前参数值 |
| `param_location` | string | 否 | 参数位置（默认 `query`） |
| `db_type` | string | 否 | 数据库类型，`auto` 模式逐 DB 尝试（最多 6 个请求） |

### waf_bypass_retry

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `vuln_type` | string | 是 | 漏洞类型：`sql_injection` / `xss` / `command_injection` / `path_traversal` / `ssti` |
| `blocked_payload` | string | 是 | 被 WAF 拦截的原始 payload |

返回成功绕过的变体 payload，或"所有策略均被拦截"。

### verify_business_logic

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `attack_type` | string | 是 | 攻击类型：`price_tampering` / `coupon_replay` / `negative_value` / `step_skip` / `race_condition` / `enumeration` |
| `target_field` | string | 否 | 目标字段名 |

价格篡改和负值测试会校验响应体是否真正接受了篡改值。竞态测试使用 CountDownLatch 同步并发请求。

### chain_hunter

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `task` | string | 是 | 已确认漏洞 A 的描述（类型+触发方式+payload+证据） |
| `max_iterations` | integer | 否 | 子代理最大 LLM 轮次（默认 10，范围 3-20） |

子代理自动发现兄弟端点、去重已测端点、按攻击模式扩散测试。

### extract_auth

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `inject_to_config` | boolean | 否 | 是否注入到 AppConfig（默认 true） |

从浏览器提取认证凭证（Cookie/JWT），注入到 send_request。使用 agent-browser CLI。

**输出**：`success` / `cookie_count` / `bearer_token_present` / `cookie_names`（不返回值）/ `cookie_injected` / `bearer_token_injected`

**依赖**：`npm install -g agent-browser && agent-browser install`

### capture_requests

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `filter` | string | 否 | 过滤器：`xhr,fetch` / `POST` / `2xx`（默认 `xhr,fetch`） |
| `save_to_file` | string | 否 | 保存路径（JSON 格式） |

捕获浏览器网络请求模板（HAR），保存供 trigger_apis 复用。

**输出**：`success` / `count` / `requests`（method/url/status）/ `saved_to`

### trigger_apis

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `api_paths` | array | 否 | API 路径列表（默认使用表格选中项） |
| `params` | object | 否 | 参数映射（用于 API 模板） |
| `use_browser_explore` | boolean | 否 | 是否对无缓存的 API 使用 browser_explore（默认 true） |

批量触发 API 表格中的接口。策略优先级：直接 HTTP（0.5s）> UI 重放（5-10s）> browser_explore（30-60s）。

**输出**：`success` / `total` / `direct_triggered` / `ui_replayed` / `explored` / `failed` / `cache_stats`

**性能提升**：后续触发速度 12x（25 分钟 → 2 分钟，100 个 API 场景）

### ssrf_oob

无参数。返回生成的 OOB 探针域名（如 `abc123.internal.dnslog.cn`）。

### submit_report

无参数。提交最终评估报告。**前置条件**：至少调用过 `heuristic_scan`；如果生成过 payload，必须通过 `send_request` 验证过至少 `min(N, 5)` 个。

### list_attack_types

查询内置攻击类型分类与 Payload 库（27 种类型、150+ payload）。零 LLM 成本，纯本地查表。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `attack_type` | string | 否 | 指定攻击类型 ID 查详情（如 `BOLA`、`SQL_INJECTION`）。省略则列出全部 |
| `severity` | string | 否 | 按严重性过滤：`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `owasp_top10_only` | boolean | 否 | 仅返回 OWASP API Security Top 10 类型 |
| `search` | string | 否 | 关键词搜索 payload（在 value/name/description 中匹配） |
| `payload_limit` | integer | 否 | 每类型返回 payload 上限（默认 10） |

**输出**：列表模式返回 `total` / `total_payloads` / `attack_types[]`（每个含 id/name/severity/owasp_mapping/payload_count）；详情模式返回单类型详情 + payloads[]；搜索模式返回 results[]。

### generate_poc

对已确认漏洞生成可执行的 Proof of Concept（cURL 命令 + Python 脚本 + 复现步骤 + 影响评估）。零 LLM 成本，纯模板生成。支持 15+ 漏洞类型。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `vuln_type` | string | 是 | 漏洞类型：SQL Injection / XSS / BOLA/IDOR / SSRF / Path Traversal / SSTI / XXE / Command Injection / Mass Assignment / Auth Bypass / CSRF / Open Redirect / NoSQL Injection 等 |
| `endpoint` | string | 是 | 受影响端点描述（如 `GET /api/users/{id}`） |
| `url` | string | 是 | 完整 URL |
| `severity` | string | 否 | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`（默认 `HIGH`） |
| `method` | string | 否 | HTTP 方法（默认 `GET`） |
| `payload` | string | 否 | 触发漏洞的 payload |
| `evidence` | string | 否 | 响应证据片段 |
| `description` | string | 否 | 漏洞描述 |
| `remediation` | string | 否 | 修复建议 |
| `cookies` | string | 否 | 复现所需 Cookie |
| `headers` | string | 否 | 额外请求头（每行一个） |
| `confidence` | integer | 否 | 置信度 0-100（默认 80） |
| `save_to_file` | string | 否 | 保存为 Markdown 文件的路径 |

**输出**：`curl_command` / `python_script` / `steps[]` / `impact` / `remediation` / `total_generated`（累计生成数）。可选 `saved_to` / `format`。

**安全**：所有用户输入（url/cookies/headers/payload）在拼入 curl 单引号串与 Python 双引号串前均做转义（`escapeSingle`/`escapePy`），防命令/代码注入；`{` 开头 payload 走 `json.loads` 而非裸拼 Python 代码。

### orchestrate_agents

编排多 Agent 协作工作流，协调 4 个角色：Planner（规划）、Explorer（侦察）、Executor（执行）、Verifier（验证）。每阶段输出作为下阶段输入。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `target_api` | string | 是 | 目标 API（如 `POST /api/orders`） |
| `workflow` | string | 否 | 工作流类型：`full`（默认，4 阶段全跑）/ `plan`（仅规划）/ `execute`（仅执行，不调 LLM）/ `verify`（仅验证） |
| `focus_areas` | string | 否 | 逗号分隔的关注领域（如 `authentication,authorization,injection`） |

**输出**：`agent_outputs[]`（每阶段含 role/success/summary/iterations_used/tools_called）/ `phases_completed` / `phases_failed` / `next_step`。Planner/Explorer/Verifier 走 LLM，Executor 当前为占位阶段（提示用 send_request 等验证工具执行计划）。

### custom_detection

用 YAML 模板执行自定义检测规则（类 Nuclei）。模板从 `custom-templates/` 目录加载。零 LLM 成本。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `action` | string | 否 | `list`（列模板，默认）/ `run`（执行模板）/ `reload`（重载目录） |
| `template_id` | string | run 时必填 | 要执行的模板 ID |
| `tag` | string | 否 | list 时按 tag 过滤 |
| `severity` | string | 否 | list 时按 severity 过滤 |

**run 输出**：`matched`（是否命中）/ `matchers_matched` / `severity` / `finding` / `remediation` / `matched_matchers[]`。模板对当前 API 入口的 `lastRawResponse` 求值。

**安全**：用户正则受 ReDoS 防护——pattern 长度上限 2000、目标截断 100k、灾难性回溯形态（如 `(a+)+`）直接拒绝；编译后的 Pattern 缓存复用。

#### 自定义检测模板格式

模板为 YAML，放在 `custom-templates/` 目录（`.yaml`/`.yml`），结构：

```yaml
id: custom-sqli-detection        # 必填，唯一标识
name: Custom SQL Injection Detection   # 必填
severity: critical               # 必填: critical/high/medium/low/info
type: response-pattern           # 可选，默认 response-pattern

description: 检测说明            # 可选
remediation: 修复建议            # 可选
tags: sqli, injection, owasp-a03 # 可选，逗号分隔

matchers:                        # 必填，至少 1 个
  - type: regex                  # regex / word / status / dsl
    pattern: "(?i)(SQL syntax|mysql_fetch|ORA-\\d{5})"  # regex 用
    words: ["syntax error", "mysql error"]              # word 用，内联数组
    status: 500                                         # status 用
    condition: or                # 可选，and/or（默认 or）
    part: body                   # 可选，body/headers/all（默认 body）
    negative: false              # 可选，true 时取反
```

> 注意：`words` 必须用内联数组格式 `["a", "b"]`；正则中的引号/反斜杠需按 YAML 双引号转义（`\"`、`\\d`、`\\s`），解析器会自动反转义。内置 3 个示例：`sqli-detection.yaml`、`ssrf-detection.yaml`、`sensitive-data.yaml`。

### scan_mcp_servers

扫描暴露的 MCP（Model Context Protocol）服务器端点并评估安全风险。并发探测 7 个常见路径，检测认证缺失、枚举工具、评风险等级。零 LLM 成本。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `target_url` | string | 否 | 目标 base URL（如 `https://example.com`）。省略则需 `scan_current_host=true` |
| `scan_current_host` | boolean | 否 | 为 true 时扫描当前 API 入口的主机 |

**输出**：`base_url` / `endpoints_found` / `critical_risk` / `endpoints[]`（每个含 url/status_code/auth_required/tool_count/risk_level/recommendation）。CRITICAL（无认证 + 有工具）时返回 warning + 处置建议。

**安全**：SSRF 防护——扫描前解析主机，拒绝指向云元数据/链路本地地址（169.254/16、0.0.0.0、阿里云 100.100.100.200）的目标；放行 loopback 与站点本地段。总扫描时长上限 30s（7 端点并发探测，最坏约 10s）。

---

## WAF 识别厂商列表

| 厂商 | 典型签名 | 分数阈值 |
|------|----------|----------|
| Cloudflare | `cf-ray` / `__cfduid` / `Just a moment` 挑战页 | ≥60 拦截 |
| AWS WAF | `x-amzn-requestid` / CloudFront `AccessDenied` 页 | ≥60 拦截 |
| Imperva | `_Incapsula_Resource` / `incap_ses` cookie | ≥60 拦截 |
| Akamai | `AkamaiGHost` / `x-akamai` 头 | ≥60 拦截 |
| F5 BIG-IP | `Support ID` 页 / `TS` cookie | ≥60 拦截 |
| ModSecurity | `ModSecurity` / `Not Acceptable!` 错误页 | ≥60 拦截 |
| Sucuri | `Sucuri WebSite Firewall` / `x-sucuri-id` | ≥60 拦截 |
| FortiWeb | `Powered by Fortinet` / `FortiWeb` | ≥60 拦截 |
| Barracuda | `BNI__BARRACUDA` / `barra_counter_session` cookie | ≥60 拦截 |
| Wallarm | `nginx-wallarm` / `Wallarm` | ≥60 拦截 |
| 360 WAF | `360WebSafe` / `wangzhan.360.cn` | ≥60 拦截 |
| Wordfence | `Generated by Wordfence` | ≥60 拦截 |

分数 30-59 为"待确认"，不阻断后续分析但标记为疑似 WAF。

---

## 组件指纹列表

| 组件 | 特征 | 风险 | 相关漏洞 |
|------|------|------|----------|
| Fastjson | `@type` JSON 字段 / `com.alibaba.fastjson` 异常 | HIGH | 反序列化 RCE |
| Log4j | `log4j` 相关类名 / JNDI 特征 | CRITICAL | Log4Shell |
| Shiro | `rememberMe=deleteMe` cookie | HIGH | 反序列化 RCE |
| Spring Actuator | `/actuator` 路径响应 | MEDIUM | 信息泄露 |
| Nacos | `nacos` 路径 / 响应特征 | HIGH | 认证绕过 |
| Swagger | `swagger-ui` / `api-docs` 路径 | LOW | API 文档暴露 |
| Druid | `/druid` 路径 / 响应特征 | HIGH | 未授权访问 |
| Vite | `@vite` 路径 / HMR 特征 | LOW | 信息泄露 |
| Ueditor | `ueditor` 路径 / 响应特征 | MEDIUM | SSRF/文件上传 |

> 完整列表参见 `ComponentFingerprinter.java`，共 30+ 组件。

---

## 报告导出格式

### CSV 导出

| 列名 | 说明 |
|------|------|
| 方法 | HTTP 方法 |
| 路径 | API 路径 |
| 域名 | 目标域名 |
| 风险 | HIGH/MEDIUM/LOW/SAFE |
| 发现数 | findings 总数 |
| 测试用例数 | 生成的测试用例数 |
| 确认漏洞 | confirmed_vulns 数量 |
| 疑似漏洞 | suspected_vulns 数量 |
| AI 摘要 | 总结文本 |
| AI 建议 | 修复建议 |
| 备注 | 用户备注 |

### Markdown 导出

按接口分组，每个接口包含：
- 基本信息和风险等级
- confirmed_vulns 详情（类型、证据、payload、验证命令）
- suspected_vulns 详情（类型、原因、验证命令）
- 测试用例列表
- 总结和建议

### 完整报告

在 Markdown 导出基础上增加：
- AI 研判详情（verdict 原始内容）
- 验证门禁节（confirmed/疑似/身份证据/verdict 的 rejection_reasons）
- 越权测试详情（session 信息、相似度、AI 仲裁结果）
- 被动检测发现详情
## 预算管理

| 配置项 | 说明 |
|--------|------|
| `dailyBudgetTokens` | 日 token 预算（默认 500,000） |
| `perRequestMaxTokens` | 单次请求上限（默认 50,000） |
| `budgetMode` | `ENFORCE`（拦截）或 `MONITOR_ONLY`（只监控不拦截） |

`MONITOR_ONLY` 模式下，token 消耗仍被记录和展示，但 LLM 调用永不拦截。适用于内部模型无限额度场景。

`AnalysisCostTracker` 按单端点分析记录 token 消耗明细，在报告末尾输出输入/输出/合计的表格。

## CLI 独立运行

```bash
java -jar API-Sentinel-1.1.jar --target URL --path PATH --endpoint LLM --api-key KEY --monitor-only
```

CLI 模式下所有 50+ 工具正常工作（HTTP 通过 java.net.http.HttpClient 发送，代理历史返回空）。详见 README。
