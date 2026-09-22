# API-Sentinel 基准评测记录表

> 靶场：demo-vuln-app（42 接口 = 24 个真实漏洞 + 18 个安全对照，标准答案来自 `GROUND_TRUTH.md`）
> 用途：跑完后把本文件交给 AI 助手，用于填充文章第九节的评测数据。

## 运行步骤

1. **启动靶场**：`cd demo-vuln-app && mvn spring-boot:run`（监听 8089；或用 `java -jar target/vuln-app-1.0.0.jar`）
2. **Burp 加载插件**，配置 AI（建议 Claude Sonnet 级或更高）
3. **⚠️ 关键步骤：索引源码仓库** —— 在插件设置里把 `demo-vuln-app/src` 配置为代码仓库并索引。不做这步，"需跳层"类和 #31-42 的 Agent 专属逻辑漏洞基本测不出来
4. **用两个账号打流量**（必须经过 Burp 代理，越权测试需要双会话）：
   - alice / bob 分别登录拿 Cookie（GROUND_TRUTH.md 里有现成 curl 模板）
   - 过一遍全部 42 个接口：GET 类直接访问，POST 类用 curl 带参数发
   - 越权相关接口（#4/#5/#6/#41）注意用 bob 的身份访问 alice 的资源
5. **触发分析**：
   - 建议先跑 **Agent 模式**（覆盖面最全，逻辑漏洞只有它能测）
   - 有时间再跑一轮 Pipeline 模式做对比
   - 任务队列批量分析即可，注意 token 预算
6. **记录结果**：逐个接口填写下表。重点抄录两个东西：
   - 最终结论（confirmed / suspected / safe）
   - **verdict 卡片里的降级记录**（`rejectionReasons`：模型声称 confirmed 但被程序校验打回的条目及理由）——这是文章最想要的数据

## 逐接口记录

结论填写：`confirmed` / `suspected` / `safe` / `未分析`；符合性：✅ / ❌ / ⚠️（部分命中）

| # | 接口 | 类型 | 标准答案 | 跳层 | 工具结论（模式） | 符合 | 备注（降级记录/证据质量） |
|---|---|---|---|---|---|---|---|
| 1 | `GET /api/users/search?name=` | SQL 注入（显错，H2） | 有漏洞 | 否 | | | |
| 2 | `GET /api/products/search?name=` | SQLi 安全对照 | 安全 | 否 | | | |
| 3 | `GET /api/orders/{id}`（不存在 id） | 堆栈跟踪泄露 | 有漏洞 | 是 | | | |
| 4 | `GET /api/orders/{id}`（他人 id） | 越权 / IDOR | 有漏洞 | 是 | | | |
| 5 | `GET /api/invoices/{id}`（他人 id） | IDOR 安全对照 | 安全 | 是 | | | |
| 6 | `GET /api/admin/users`（普通用户） | 垂直越权 | 有漏洞 | 是 | | | |
| 7 | `POST /api/auth/token` | JWT alg:none | 有漏洞 | 是 | | | |
| 8 | `POST /api/auth/token-strict` | JWT 安全对照 | 安全 | 是 | | | |
| 9 | `GET /api/profile` | CORS 通配符+凭证 | 有漏洞 | 否 | | | |
| 10 | `GET /api/profile2` | CORS Origin 反射 | 有漏洞 | 否 | | | |
| 11 | `POST /api/fetch-url` | SSRF | 有漏洞 | 是 | | | |
| 12 | `POST /api/fetch-url-safe` | SSRF 安全对照 | 安全 | 是 | | | |
| 13 | `POST /api/upload` | 危险文件上传 | 有漏洞 | 否 | | | |
| 14 | `POST /api/upload-safe` | 上传安全对照 | 安全 | 否 | | | |
| 15 | `POST /api/import` | Java 反序列化 | 有漏洞 | 否 | | | |
| 16 | `GET /web/dashboard` | 缺失安全头 | 有漏洞 | 否 | | | |
| 17 | `GET /api/users/{id}` | 敏感信息泄露 | 有漏洞 | 否 | | | |
| 18 | `GET /api/users/{id}/public` | 敏感信息安全对照 | 安全 | 否 | | | |
| 19 | `GET /api/debug/config` | 调试模式泄露 | 有漏洞 | 否 | | | |
| 20 | `POST /api/checkout` | CSRF | 有漏洞 | 否 | | | |
| 21 | `GET /api/greet?name=` | XSS 反射 | 有漏洞 | 否 | | | |
| 22 | `GET /api/greet-safe?name=` | XSS 安全对照 | 安全 | 否 | | | |
| 23 | `GET /api/render?template=` | SSTI | 有漏洞 | 否 | | | |
| 24 | `GET /api/render-safe?template=` | SSTI 安全对照 | 安全 | 否 | | | |
| 25 | `GET /api/files?path=` | 路径穿越 | 有漏洞 | 否 | | | |
| 26 | `GET /api/files-safe?path=` | 路径穿越安全对照 | 安全 | 否 | | | |
| 27 | `POST /api/parse-xml` | XXE | 有漏洞 | 否 | | | |
| 28 | `POST /api/parse-xml-safe` | XXE 安全对照 | 安全 | 否 | | | |
| 29 | `GET /api/products/detail?id=` | 布尔盲注 | 有漏洞 | 否 | | | |
| 30 | `GET /api/products/detail-safe?id=` | 盲注安全对照 | 安全 | 否 | | | |
| 31 | `POST /api/transfer` | 竞态条件（Agent 专属） | 有漏洞 | 是 | | | |
| 32 | `POST /api/transfer-safe` | 竞态安全对照（Agent 专属） | 安全 | 是 | | | |
| 33 | `POST /api/reset-token` | 不安全随机数（Agent 专属） | 有漏洞 | 是 | | | |
| 34 | `POST /api/reset-token-safe` | 随机数安全对照（Agent 专属） | 安全 | 是 | | | |
| 35 | `POST /api/encrypt` | 硬编码密钥+ECB（Agent 专属） | 有漏洞 | 是 | | | |
| 36 | `POST /api/encrypt-safe` | 加密安全对照（Agent 专属） | 安全 | 是 | | | |
| 37 | `POST /api/register` | MD5 弱哈希（Agent 专属） | 有漏洞 | 是 | | | |
| 38 | `POST /api/register-safe` | 哈希安全对照（Agent 专属） | 安全 | 是 | | | |
| 39 | `GET /api/redirect?url=` | 开放重定向（Agent 专属） | 有漏洞 | 是 | | | |
| 40 | `GET /api/redirect-safe?url=` | 重定向安全对照（Agent 专属） | 安全 | 是 | | | |
| 41 | `POST /api/profile/update` | Mass Assignment（Agent 专属） | 有漏洞 | 是 | | | |
| 42 | `POST /api/profile/update-safe` | Mass Assignment 安全对照 | 安全 | 是 | | | |

## 汇总统计（跑完后填）

| 指标 | 数值 |
|---|---|
| 真漏洞检出（24 个中报 confirmed 的） | / 24 |
| 真漏洞仅报 suspected | |
| 漏报 | |
| 安全对照误报为 confirmed（18 个中） | / 18 |
| 安全对照误报为 suspected | |
| **被防幻觉机制降级的 confirmed 数**（rejectionReasons 计数） | |
| 降级理由分布（未发送过 / 未触发异常 / WAF 拦截 / 身份证据缺失） | |
| 单接口平均耗时 / token 消耗（如可统计） | |

### 特别关注的考点

- **#1（H2 显错）**：本地规则故意不覆盖 H2 报错，用来隔离测试"AI 层能否独立识别"——记一下是被动层命中还是 AI 判定命中
- **#31-42（Agent 专属）**：纯发请求测不出，检验源码调用链分析是否真的生效
- **跳层类（20 条）**：有没有真的跟进 service/DAO 层（看 Agent 步骤里有没有 read_file/find_callers 记录）
- **安全对照组**：敢不敢如实报 SAFE，是比检出率更重要的指标
