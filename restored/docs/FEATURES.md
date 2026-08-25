# API Sentinel 功能参考

> 本文档是 [README.md](README.md) 的补充，包含被动检测规则详情、敏感信息规则格式、Agent 工具参数说明等查阅型参考内容。

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

无参数。直接调用，返回所有被动检测结果的 JSON 数组。

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
| `headers` | object | 否 | 自定义请求头（key-value） |
| `body` | string | 否 | 请求体 |
| `query_params` | object | 否 | URL 查询参数（key-value） |

### test_auth_bypass

无参数。自动从代理历史发现 session 并执行越权测试。

### active_probe

无参数。按触发条件自动执行：CORS（Origin 头存在）、JWT（检测到 JWT token）、CRLF（请求含换行字符）、NoSQL（请求体含 JSON 操作符）。

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

### ssrf_oob

无参数。返回生成的 OOB 探针域名（如 `abc123.internal.dnslog.cn`）。

### submit_report

无参数。提交最终评估报告。**前置条件**：至少调用过 `heuristic_scan`；如果生成过 payload，必须通过 `send_request` 验证过至少 `min(N, 5)` 个。

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