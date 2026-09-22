# API 安全测试报告

- **生成时间**: 2026-08-26 13:44:19
- **API总数**: 42
- **已测试**: 37 (88%)
- **存在漏洞**: 11

## 统计摘要

| 状态 | 数量 |
|------|------|
| 测试通过 | 3 |
| 存在漏洞 | 11 |
| 测试中 | 5 |
| 未测试 | 5 |

## 发现的漏洞

### 垂直越权 (1)

| API | Method | Domain | Note |
|-----|--------|--------|------|
| /api/admin/users | GET | localhost:8089 |  |

### 未授权 (19)

| API | Method | Domain | Note |
|-----|--------|--------|------|
| /api/users/search | GET | localhost:8089 |  |
| /api/orders/{id} | GET | localhost:8089 |  |
| /api/fetch-url | POST | localhost:8089 |  |
| /api/upload | POST | localhost:8089 |  |
| /web/dashboard | GET | localhost:8089 |  |
| /api/users/{id} | GET | localhost:8089 |  |
| /api/users/{id}/public | GET | localhost:8089 |  |
| /api/debug/config | GET | localhost:8089 |  |
| /api/greet | GET | localhost:8089 |  |
| /api/files | GET | localhost:8089 |  |
| /api/parse-xml | POST | localhost:8089 |  |
| /api/parse-xml-safe | POST | localhost:8089 |  |
| /api/products/detail | GET | localhost:8089 |  |
| /api/products/detail-safe | GET | localhost:8089 |  |
| /api/encrypt | POST | localhost:8089 |  |
| /api/register | POST | localhost:8089 |  |
| /api/register-safe | POST | localhost:8089 |  |
| /api/profile/update | POST | localhost:8089 |  |
| /api/profile/update-safe | POST | localhost:8089 |  |

### 存在漏洞 (2)

| API | Method | Domain | Note |
|-----|--------|--------|------|
| /api/products/search | GET | localhost:8089 |  |
| /api/redirect-safe | GET | localhost:8089 |  |

## 完整API列表

| # | Method | API | Status | Result | Note | Passive | Domain |
|---|--------|-----|--------|--------|-------|---------|--------|
| 1 | GET | /api/users/search | 存在漏洞 | /api/users/{id} 匿名枚举用户返回密码哈希与 SSN（IDOR） |  | Windows File Path · 未授权访问探测（待确认） +1 | localhost:8089 |
| 2 | GET | /api/products/search | 存在漏洞 | 错误回显 SQL 注入（/api/users/search） |  | -- | localhost:8089 |
| 3 | GET | /api/orders/{id} | 存在漏洞 | GET /api/orders/{id} 完全缺失认证与归属校验，可匿名/任意会话枚举读取其他用户订单 |  | 未授权访问探测（待确认） · 堆栈跟踪泄露 | localhost:8089 |
| 4 | GET | /api/invoices/{id} | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | -- | localhost:8089 |
| 5 | GET | /api/admin/users | 存在漏洞 | GET /api/admin/users 缺少角色校验，任意客户端（含伪造会话）可拉取全部用户敏感数据 |  | Password Field · Email | localhost:8089 |
| 6 | POST | /api/auth/token | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | 堆栈跟踪泄露 | localhost:8089 |
| 7 | POST | /api/auth/token-strict | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | 堆栈跟踪泄露 | localhost:8089 |
| 8 | GET | /api/profile | 接口测试中 | 接口测试中 |  | Email · 通配符 Origin 配合凭据共享 | localhost:8089 |
| 9 | GET | /api/profile2 | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | Email · Custom URL Scheme +2 | localhost:8089 |
| 10 | POST | /api/fetch-url | 待评估 | 未授权 |  | Internal IP Address · 调试模式开启 +4 | localhost:8089 |
| 11 | POST | /api/fetch-url-safe | 测试通过，安全 | AI 分析未发现漏洞 |  | 堆栈跟踪泄露 · Custom URL Scheme +5 | localhost:8089 |
| 12 | POST | /api/upload | 待评估 | 未授权 |  | 堆栈跟踪泄露 · 危险文件扩展名上传成功 +1 | localhost:8089 |
| 13 | POST | /api/upload-safe | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | 堆栈跟踪泄露 | localhost:8089 |
| 14 | POST | /api/import | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | 堆栈跟踪泄露 | localhost:8089 |
| 15 | GET | /web/dashboard | 待评估 | 未授权 |  | 缺失安全响应头: strict-transport-security · 缺失安全响应头: content-security-policy +4 | localhost:8089 |
| 16 | GET | /api/users/{id} | 存在漏洞 | GET /api/users/{id} 无任何认证，可枚举并返回任意用户完整记录 |  | Password Field · Email +2 | localhost:8089 |
| 17 | GET | /api/users/{id}/public | 存在漏洞 | GET /api/users/{id} 未授权枚举全部用户的 passwordHash、SSN、email，且凭据为可破解的无盐MD5 |  | Email · 未授权访问探测（待确认） +1 | localhost:8089 |
| 18 | GET | /api/debug/config | 存在漏洞 | 调试端点未授权暴露敏感配置信息（内网IP、数据库连接串、debug标志、构建版本） |  | Internal IP Address · 调试模式开启 +2 | localhost:8089 |
| 19 | POST | /api/checkout | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | 状态变更接口缺少 CSRF 防护 | localhost:8089 |
| 20 | GET | /api/greet | 存在漏洞 | /api/greet 的 name 参数未做 HTML 编码导致反射型 XSS |  | 缺失安全响应头: strict-transport-security · 缺失安全响应头: content-security-policy +5 | localhost:8089 |
| 21 | GET | /api/greet-safe | 测试通过，安全 | AI 分析未发现漏洞 |  | 缺失安全响应头: strict-transport-security · 缺失安全响应头: content-security-policy +3 | localhost:8089 |
| 22 | GET | /api/render | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | Passwd File Leak | localhost:8089 |
| 23 | GET | /api/render-safe | 测试通过，安全 | AI 分析未发现漏洞 |  | -- | localhost:8089 |
| 24 | GET | /api/files | 待评估 | 未授权 |  | Passwd File Leak · 未授权访问探测（待确认） | localhost:8089 |
| 25 | GET | /api/files-safe | 接口测试中 | 接口测试中 |  | -- | localhost:8089 |
| 26 | POST | /api/parse-xml | 待评估 | 未授权 |  | Passwd File Leak · 未授权访问探测（待确认） +3 | localhost:8089 |
| 27 | POST | /api/parse-xml-safe | 待评估 | 未授权 |  | Custom URL Scheme · 未授权访问探测（待确认） | localhost:8089 |
| 28 | GET | /api/products/detail | 待评估 | 未授权 |  | 未授权访问探测（待确认） | localhost:8089 |
| 29 | GET | /api/products/detail-safe | 待评估 | 未授权 |  | 未授权访问探测（待确认） | localhost:8089 |
| 30 | POST | /api/transfer | 接口测试中 | 接口测试中 |  | 状态变更接口缺少 CSRF 防护 | localhost:8089 |
| 31 | POST | /api/transfer-safe | 接口测试中 | 接口测试中 |  | 状态变更接口缺少 CSRF 防护 | localhost:8089 |
| 32 | POST | /api/reset-token | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | Sensitive Field · 未授权访问探测（待确认） | localhost:8089 |
| 33 | POST | /api/reset-token-safe | 接口测试中 | 接口测试中 |  | Sensitive Field | localhost:8089 |
| 34 | POST | /api/encrypt | 待评估 | 未授权 |  | 未授权访问探测（待确认） | localhost:8089 |
| 35 | POST | /api/encrypt-safe | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | 堆栈跟踪泄露 | localhost:8089 |
| 36 | POST | /api/register | 存在漏洞 | GET /api/users/{id} 匿名返回完整用户记录含 passwordHash 与 SSN |  | Password Field · 未授权访问探测（待确认） +1 | localhost:8089 |
| 37 | POST | /api/register-safe | 存在漏洞 | /api/users/{id} 匿名可读取任意用户完整记录（含 passwordHash 与 SSN） |  | Password Field | localhost:8089 |
| 38 | GET | /api/redirect | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | Custom URL Scheme · 堆栈跟踪泄露 | localhost:8089 |
| 39 | GET | /api/redirect-safe | 存在漏洞 | /api/redirect 端点存在开放重定向（同 Controller 未加白名单的兄弟端点） |  | Custom URL Scheme · Email | localhost:8089 |
| 40 | POST | /api/profile/update | 待评估 | 未授权 |  | Email · 未授权访问探测（待确认） | localhost:8089 |
| 41 | POST | /api/profile/update-safe | 待评估 | 未授权 |  | Email · 未授权访问探测（待确认） | localhost:8089 |
| 42 | GET | /etc/passwd | 待评估 | AI 分析发现疑似漏洞，待人工确认 |  | -- | localhost:8089 |
