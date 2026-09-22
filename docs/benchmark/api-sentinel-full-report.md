# API 安全渗透测试完整报告

> 由 API Sentinel 自动生成

---

## 1. 报告概览

| 项目 | 值 |
|------|----|
| 生成时间 | 2026-08-26 13:45:41 |
| API 总数 | 42 |
| 已测试 | 37 (88.1%) |
| 测试通过 | 3 |
| 存在漏洞 | 11 |
| 测试中 | 5 |
| 未测试 | 5 |

### 风险统计

| 风险等级 | 数量 |
|----------|------|
| 高危 (HIGH) | 0 |
| 中危 (MEDIUM) | 0 |
| 低危 (LOW) | 0 |
| 信息 (INFO) | 0 |
| **总计** | **0** |

## 2. 统计图表

### 测试覆盖率

```
已通过      │███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 3
有漏洞      │██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 11
测试中      │█████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 5
未测试      │█████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 5
```

### 风险分布

```
HIGH     │░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 0
MEDIUM   │░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 0
LOW      │░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 0
INFO     │░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│ 0
```

## 3. 域名分布

| 域名 | 接口数 | 漏洞数 | 已测试 |
|------|--------|--------|--------|
| localhost:8089 | 42 | 11 | 37 |

## 4. 漏洞详情

### 4.1 GET /api/users/search

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Windows File Path — t:\nSELECT id, username, email FROM users WHERE username LIKE '%test'%' [42000-224]
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 213 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-19T11:38:20.175191
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。
  - [SENSITIVE_INFO][INFO] 敏感信息 / Email — alice@example.com

#### AI 分析结果 (AGENT)

- 风险等级: **NONE**
- 模型: n/a
- 分析耗时: 0ms
- 摘要: format_only: 由 Agent 自行分析

#### AI 研判与验证门禁

- 综合风险: **HIGH**
- 已确认:
  - [路径穿越/LFI] /api/files 路径穿越读取任意文件（/etc/passwd）（CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)）
  - [越权访问/敏感信息泄露] /api/users/{id} 匿名枚举用户返回密码哈希与 SSN（IDOR）（CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)）
    - 身份证据: 匿名会话（无 Cookie/Authorization/X-Auth-Token 头）直接访问返回 200；请求 id=1 得到 alice 的 passwordHash+ssn，请求 id=2 得到 bob 的不同 passwordHash+ssn，请求 id=3 得到 admin 的不同数据——三次返回分属三个不同账号的 PII，证明是任意对象枚举型 IDOR 而非返回自身数据。
  - [越权访问/权限绕过] /api/admin/users 缺失角色校验（任意伪造会话 Cookie 即可读全库）（CVSS: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)）
    - 身份证据: 无 Cookie 时该端点返回 401（有鉴权缺省）；伪造任意 Session 值 SESSION_USER=2（无密码验证，login 接口也不校验密码）后返回 200 并泄露全部账号数据。返回数据包含 alice/bob/admin 三个不同账号的 PII，而伪造身份只是普通用户 bob(id=2)——证明缺失角色校验、任意登录态可越权读取管理数据。
  - [服务端模板注入(SSTI)] /api/render 用户输入作为模板执行（${7*7}→49）（CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)）
  - [XXE] /api/parse-xml XML 外部实体注入读取本地文件（CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)）
  - [反射型XSS] /api/greet 反射型 XSS（脚本原样回显）（CVSS: 6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)）
  - [敏感信息泄露] /api/debug/config 泄露内部主机/数据库连接等配置（CVSS: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)）
- 疑似:
  - [SQL注入] /api/users/search 未认证错误回显+布尔型 SQL 注入（可拖全库）（置信度: MEDIUM）
  - [SSRF] /api/fetch-url 服务端请求伪造访问内网端点（置信度: MEDIUM）
  - [SQL注入(布尔盲注)] /api/products/detail 布尔盲注（响应差异判定）（置信度: MEDIUM）
- 验证门禁: 全部校验通过

---

### 4.2 GET /api/products/search

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 存在漏洞

#### AI 分析结果 (AGENT)

- 风险等级: **NONE**
- 模型: n/a
- 分析耗时: 0ms
- 摘要: format_only: 由 Agent 自行分析

#### AI 研判与验证门禁

- 综合风险: **SAFE**
- 验证门禁: 全部校验通过

---

### 4.3 GET /api/orders/{id}

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 62 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-19T11:06:52.083378
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。
  - [HEURISTIC][LOW] 信息泄露 / 堆栈跟踪泄露 — 响应中包含堆栈跟踪信息: java.lang.NullPointerException

---

### 4.4 GET /api/admin/users

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 垂直越权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Password Field — "passwordHash":"5f4dcc3b5aa765d61d8327deb882cf99"
  - [SENSITIVE_INFO][INFO] 敏感信息 / Email — alice@example.com

#### AI 分析结果 (AGENT)

- 风险等级: **NONE**
- 模型: n/a
- 分析耗时: 0ms
- 摘要: format_only: 由 Agent 自行分析

#### AI 研判与验证门禁

- 综合风险: **HIGH**
- 已确认:
  - [越权访问 / 垂直越权（Broken Access Control）] GET /api/admin/users 缺少角色校验，任意客户端（含伪造会话）可拉取全部用户敏感数据（CVSS: 8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)）
    - 身份证据: ① 使用上下文：SESSION_USER=2（普通用户 bob 的会话 cookie）访问，返回 200 全量数据。② 匿名访问（去掉 Cookie）返回 401，说明存在认证门槛但其唯一逻辑是"cookie 非空"，不含角色/身份有效性校验。③ 返回数据确认属于【他人账号】而非当前用户：响应包含 id=1(alice)、id=2(bob)、id=3(admin) 三条完整记录，其中 alice 的 email/ssn/passwordHash 与 admin 的敏感信息明显不属于 bob 本人；更关键的是伪造 SESSION_USER=999（UserStore 中不存在的用户 ID）同样返回 200 全量数据，证明服务端根本不校验会话身份，任何伪造 cookie 都能拿到所有他人数据。
- 疑似:
  - [敏感信息泄露] admin 端点返回 passwordHash 与 ssn 明文，且密码哈希为可破解的弱 MD5（置信度: MEDIUM）
- 验证门禁: 全部校验通过

---

### 4.5 GET /api/users/{id}

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Password Field — "passwordHash":"5f4dcc3b5aa765d61d8327deb882cf99"
  - [SENSITIVE_INFO][INFO] 敏感信息 / Email — alice@example.com
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 125 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-19T11:40:47.205691
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。
  - [HEURISTIC][LOW] 信息泄露 / 堆栈跟踪泄露 — 响应中包含堆栈跟踪信息: at org.springframework.web.method.annotation.AbstractNamedValueMethodArgumentResolver.convertIfNeces...

---

### 4.6 GET /api/users/{id}/public

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Email — alice@example.com
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 55 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-19T22:33:58.958882
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。
  - [HEURISTIC][LOW] 信息泄露 / 堆栈跟踪泄露 — 响应中包含堆栈跟踪信息: at org.springframework.web.method.annotation.AbstractNamedValueMethodArgumentResolver.convertIfNeces...

#### AI 分析结果 (AGENT)

- 风险等级: **NONE**
- 模型: n/a
- 分析耗时: 0ms
- 摘要: format_only: 由 Agent 自行分析

#### AI 研判与验证门禁

- 综合风险: **HIGH**
- 已确认:
  - [未授权访问 / 敏感信息泄露 (IDOR)] GET /api/users/{id} 未授权枚举全部用户的 passwordHash、SSN、email，且凭据为可破解的无盐MD5（CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)）
    - 身份证据: 1) 使用哪个会话：匿名会话，未携带任何认证凭据（无 Cookie、无 Authorization、无 X-Auth-Token，send_request 显式 use_original_auth=false）。2) 匿名访问结果：/api/users/1、/api/users/2、/api/users/3 全部返回 200 完整记录，证明无需登录即可访问。3) 如何确认返回的是他人数据：通过递增路径 id 枚举到 3 个不同账号（alice/bob/admin），每个 id 返回各自不同的 passwordHash、ssn、email；UserStore 源码确认这三条是三个不同用户，其中 id=2(bob)、id=3(admin) 的凭据与 SSN 非发起请求者所属（请求者本身无任何身份），属于可枚举的全量他人敏感数据。
- 疑似:
  - [堆栈跟踪信息泄露] GET /api/users/{id}/public 及 /api/users/{id} 对非数字 id 返回完整 Java 堆栈跟踪（泄露框架内部实现）（置信度: MEDIUM）
- 验证门禁: 全部校验通过

---

### 4.7 GET /api/debug/config

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Internal IP Address — 10.0.5.23
  - [HEURISTIC][MEDIUM] 配置错误 / 调试模式开启 — 响应中检测到调试模式标记: "debug":true
  - [HEURISTIC][LOW] 信息泄露 / 内网 IP 地址泄露 — 响应中包含内网 IP: 10.0.5.23
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 139 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-19T11:06:52.350635
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。

---

### 4.8 GET /api/greet

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [HEURISTIC][LOW] 配置错误 / 缺失安全响应头: strict-transport-security — 响应未设置 strict-transport-security 头
  - [HEURISTIC][LOW] 配置错误 / 缺失安全响应头: content-security-policy — 响应未设置 content-security-policy 头
  - [HEURISTIC][LOW] 配置错误 / 缺失安全响应头: x-frame-options — 响应未设置 x-frame-options 头
  - [HEURISTIC][LOW] 配置错误 / 缺失安全响应头: x-content-type-options — 响应未设置 x-content-type-options 头
  - [HEURISTIC][LOW] 配置错误 / 缺失安全响应头: referrer-policy — 响应未设置 referrer-policy 头
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 68 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-19T11:40:18.639682
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。
  - [SENSITIVE_INFO][INFO] 敏感信息 / Custom URL Scheme — http://evil.example/?c=

---

### 4.9 POST /api/register

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Password Field — "passwordHash":"f30aa7a662c728b7407c54ae6bfd27d1"
  - [UNAUTHORIZED][MEDIUM] 越权 / 未授权访问探测（待确认） — [未授权检测-待确认] 去除认证头后仍返回 2xx (200)
  原始状态码: 200
  响应长度: 103 字节
  去除的头: Cookie, Authorization, X-Auth-Token
  检测时间: 2026-08-26T11:00:01.546168
  注意: 无法区分"该接口本来就不需要认证"和"需要认证但未强制"，请人工确认后再判定。
  - [HEURISTIC][LOW] 信息泄露 / 堆栈跟踪泄露 — 响应中包含堆栈跟踪信息: at org.springframework.web.servlet.mvc.method.annotation.AbstractMessageConverterMethodArgumentResol...

---

### 4.10 POST /api/register-safe

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 未授权
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Password Field — "passwordHash":"$2a$10$EcxtTBmZ8wq6lNIKKvq2L.FbtPDjar6u/FKQTDRd24GxH9uarJ.OC"

---

### 4.11 GET /api/redirect-safe

- **域名**: localhost:8089
- **状态**: 存在漏洞
- **漏洞类型**: 存在漏洞
- **被动检测**:
  - [SENSITIVE_INFO][INFO] 敏感信息 / Custom URL Scheme — http://example.com
  - [SENSITIVE_INFO][INFO] 敏感信息 / Email — evil.com@example.com

---

## 5. 敏感信息发现

| API | 域名 | 发现 |
|-----|------|------|
| GET /api/users/search | localhost:8089 | Windows File Path; Email |
| GET /api/admin/users | localhost:8089 | Password Field; Email |
| GET /api/profile | localhost:8089 | Email |
| GET /api/profile2 | localhost:8089 | Email; Custom URL Scheme |
| POST /api/fetch-url | localhost:8089 | Internal IP Address; Email |
| POST /api/fetch-url-safe | localhost:8089 | Custom URL Scheme |
| GET /api/users/{id} | localhost:8089 | Password Field; Email |
| GET /api/users/{id}/public | localhost:8089 | Email |
| GET /api/debug/config | localhost:8089 | Internal IP Address |
| GET /api/greet | localhost:8089 | Custom URL Scheme |
| GET /api/render | localhost:8089 | Passwd File Leak |
| GET /api/files | localhost:8089 | Passwd File Leak |
| POST /api/parse-xml | localhost:8089 | Passwd File Leak; Spring Boot Actuator; Custom URL Scheme; Email |
| POST /api/parse-xml-safe | localhost:8089 | Custom URL Scheme |
| POST /api/reset-token | localhost:8089 | Sensitive Field |
| POST /api/reset-token-safe | localhost:8089 | Sensitive Field |
| POST /api/register | localhost:8089 | Password Field |
| POST /api/register-safe | localhost:8089 | Password Field |
| GET /api/redirect | localhost:8089 | Custom URL Scheme |
| GET /api/redirect-safe | localhost:8089 | Custom URL Scheme; Email |
| POST /api/profile/update | localhost:8089 | Email |
| POST /api/profile/update-safe | localhost:8089 | Email |

## 6. 完整 API 列表

| # | Method | API | 状态 | 结果 | 域名 |
|---|--------|-----|------|------|------|
| 1 | GET | /api/users/search | 存在漏洞 | /api/users/{id} 匿名枚举用户返回密码哈希与 SSN（IDOR） | localhost:8089 |
| 2 | GET | /api/products/search | 存在漏洞 | 错误回显 SQL 注入（/api/users/search） | localhost:8089 |
| 3 | GET | /api/orders/{id} | 存在漏洞 | GET /api/orders/{id} 完全缺失认证与归属校验，可匿名/任意会话枚举读取其他用户订单 | localhost:8089 |
| 4 | GET | /api/invoices/{id} | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 5 | GET | /api/admin/users | 存在漏洞 | GET /api/admin/users 缺少角色校验，任意客户端（含伪造会话）可拉取全部用户敏感数据 | localhost:8089 |
| 6 | POST | /api/auth/token | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 7 | POST | /api/auth/token-strict | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 8 | GET | /api/profile | 接口测试中 | 接口测试中 | localhost:8089 |
| 9 | GET | /api/profile2 | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 10 | POST | /api/fetch-url | 待评估 | 未授权 | localhost:8089 |
| 11 | POST | /api/fetch-url-safe | 测试通过，安全 | AI 分析未发现漏洞 | localhost:8089 |
| 12 | POST | /api/upload | 待评估 | 未授权 | localhost:8089 |
| 13 | POST | /api/upload-safe | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 14 | POST | /api/import | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 15 | GET | /web/dashboard | 待评估 | 未授权 | localhost:8089 |
| 16 | GET | /api/users/{id} | 存在漏洞 | GET /api/users/{id} 无任何认证，可枚举并返回任意用户完整记录 | localhost:8089 |
| 17 | GET | /api/users/{id}/public | 存在漏洞 | GET /api/users/{id} 未授权枚举全部用户的 passwordHash、SSN、email，且凭据为可破解的无盐MD5 | localhost:8089 |
| 18 | GET | /api/debug/config | 存在漏洞 | 调试端点未授权暴露敏感配置信息（内网IP、数据库连接串、debug标志、构建版本） | localhost:8089 |
| 19 | POST | /api/checkout | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 20 | GET | /api/greet | 存在漏洞 | /api/greet 的 name 参数未做 HTML 编码导致反射型 XSS | localhost:8089 |
| 21 | GET | /api/greet-safe | 测试通过，安全 | AI 分析未发现漏洞 | localhost:8089 |
| 22 | GET | /api/render | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 23 | GET | /api/render-safe | 测试通过，安全 | AI 分析未发现漏洞 | localhost:8089 |
| 24 | GET | /api/files | 待评估 | 未授权 | localhost:8089 |
| 25 | GET | /api/files-safe | 接口测试中 | 接口测试中 | localhost:8089 |
| 26 | POST | /api/parse-xml | 待评估 | 未授权 | localhost:8089 |
| 27 | POST | /api/parse-xml-safe | 待评估 | 未授权 | localhost:8089 |
| 28 | GET | /api/products/detail | 待评估 | 未授权 | localhost:8089 |
| 29 | GET | /api/products/detail-safe | 待评估 | 未授权 | localhost:8089 |
| 30 | POST | /api/transfer | 接口测试中 | 接口测试中 | localhost:8089 |
| 31 | POST | /api/transfer-safe | 接口测试中 | 接口测试中 | localhost:8089 |
| 32 | POST | /api/reset-token | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 33 | POST | /api/reset-token-safe | 接口测试中 | 接口测试中 | localhost:8089 |
| 34 | POST | /api/encrypt | 待评估 | 未授权 | localhost:8089 |
| 35 | POST | /api/encrypt-safe | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 36 | POST | /api/register | 存在漏洞 | GET /api/users/{id} 匿名返回完整用户记录含 passwordHash 与 SSN | localhost:8089 |
| 37 | POST | /api/register-safe | 存在漏洞 | /api/users/{id} 匿名可读取任意用户完整记录（含 passwordHash 与 SSN） | localhost:8089 |
| 38 | GET | /api/redirect | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |
| 39 | GET | /api/redirect-safe | 存在漏洞 | /api/redirect 端点存在开放重定向（同 Controller 未加白名单的兄弟端点） | localhost:8089 |
| 40 | POST | /api/profile/update | 待评估 | 未授权 | localhost:8089 |
| 41 | POST | /api/profile/update-safe | 待评估 | 未授权 | localhost:8089 |
| 42 | GET | /etc/passwd | 待评估 | AI 分析发现疑似漏洞，待人工确认 | localhost:8089 |

---

*报告结束 - API Sentinel v1.0*
