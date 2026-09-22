# API-Sentinel 基准评测记录表

> 靶场：easyshop-app（53 接口 = 32 个真实漏洞 + 21 个安全对照，标准答案来自 `GROUND_TRUTH.md`）
> 用途：跑完后把本文件交给 AI 助手，用于填充文章第九节的评测数据。

## 运行步骤

1. **启动靶场**：`cd easyshop-app && mvn spring-boot:run`（监听 8089；或用 `java -jar target/easyshop-1.0.0.jar`）
2. **Burp 加载插件**，配置 AI（建议 Claude Sonnet 级或更高）
3. **⚠️ 关键步骤：索引源码仓库** —— 在插件设置里把 `easyshop-app/src` 配置为代码仓库并索引。不做这步，"需跳层"类和 #31-42 的 Agent 专属逻辑漏洞基本测不出来
4. **用两个账号打流量**（必须经过 Burp 代理，越权测试需要双会话）：
   - alice / bob 分别登录拿 Cookie（GROUND_TRUTH.md 里有现成 curl 模板）
   - 过一遍全部 53 个接口：GET 类直接访问，POST 类用 curl 带参数发
   - 越权相关接口（#4/#5/#6/#41/#43）注意用 bob 的身份访问 alice 的资源
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
| 8 | `POST /api/auth/verify` | JWT 安全对照 | 安全 | 是 | | | |
| 9 | `GET /api/profile` | CORS 通配符+凭证 | 有漏洞 | 否 | | | |
| 10 | `GET /api/profile2` | CORS Origin 反射 | 有漏洞 | 否 | | | |
| 11 | `POST /api/fetch-url` | SSRF | 有漏洞 | 是 | | | |
| 12 | `POST /api/fetch-external` | SSRF 安全对照 | 安全 | 是 | | | |
| 13 | `POST /api/upload` | 危险文件上传 | 有漏洞 | 否 | | | |
| 14 | `POST /api/upload-image` | 上传安全对照 | 安全 | 否 | | | |
| 15 | `POST /api/import` | Java 反序列化 | 有漏洞 | 否 | | | |
| 16 | `GET /web/dashboard` | 缺失安全头 | 有漏洞 | 否 | | | |
| 17 | `GET /api/users/{id}` | 敏感信息泄露 | 有漏洞 | 否 | | | |
| 18 | `GET /api/users/{id}/public` | 敏感信息安全对照 | 安全 | 否 | | | |
| 19 | `GET /api/debug/config` | 调试模式泄露 | 有漏洞 | 否 | | | |
| 20 | `POST /api/checkout` | CSRF | 有漏洞 | 否 | | | |
| 21 | `GET /api/greet?name=` | XSS 反射 | 有漏洞 | 否 | | | |
| 22 | `GET /api/welcome?name=` | XSS 安全对照 | 安全 | 否 | | | |
| 23 | `GET /api/render?template=` | SSTI | 有漏洞 | 否 | | | |
| 24 | `GET /api/preview?template=` | SSTI 安全对照 | 安全 | 否 | | | |
| 25 | `GET /api/files?path=` | 路径穿越 | 有漏洞 | 否 | | | |
| 26 | `GET /api/documents?path=` | 路径穿越安全对照 | 安全 | 否 | | | |
| 27 | `POST /api/parse-xml` | XXE | 有漏洞 | 否 | | | |
| 28 | `POST /api/parse-config` | XXE 安全对照 | 安全 | 否 | | | |
| 29 | `GET /api/products/detail?id=` | 布尔盲注 | 有漏洞 | 否 | | | |
| 30 | `GET /api/product-info?id=` | 盲注安全对照 | 安全 | 否 | | | |
| 31 | `POST /api/transfer` | 竞态条件（Agent 专属） | 有漏洞 | 是 | | | |
| 32 | `POST /api/wallet/transfer` | 竞态安全对照（Agent 专属） | 安全 | 是 | | | |
| 33 | `POST /api/reset-token` | 不安全随机数（Agent 专属） | 有漏洞 | 是 | | | |
| 34 | `POST /api/password/reset` | 随机数安全对照（Agent 专属） | 安全 | 是 | | | |
| 35 | `POST /api/encrypt` | 硬编码密钥+ECB（Agent 专属） | 有漏洞 | 是 | | | |
| 36 | `POST /api/seal` | 加密安全对照（Agent 专属） | 安全 | 是 | | | |
| 37 | `POST /api/register` | MD5 弱哈希（Agent 专属） | 有漏洞 | 是 | | | |
| 38 | `POST /api/signup` | 哈希安全对照（Agent 专属） | 安全 | 是 | | | |
| 39 | `GET /api/redirect?url=` | 开放重定向（Agent 专属） | 有漏洞 | 是 | | | |
| 40 | `GET /api/goto?url=` | 重定向安全对照（Agent 专属） | 安全 | 是 | | | |
| 41 | `POST /api/profile/update` | Mass Assignment（Agent 专属） | 有漏洞 | 是 | | | |
| 42 | `POST /api/profile/save` | Mass Assignment 安全对照 | 安全 | 是 | | | |
| 43 | `PUT /api/orders/{id}/quantity` | IDOR 越权修改 | 有漏洞 | 是 | | | |
| 44 | `POST /api/orders` | 业务逻辑 | 有漏洞 | 否 | | | |
| 45 | `GET /api/logs?file=` | 命令注入 | 有漏洞 | 否 | | | |
| 46 | `GET /api/system-logs?file=` | 命令注入（安全对照） | 安全 | 否 | | | |
| 47 | `POST /api/mongo/login` | NoSQL 注入 | 有漏洞 | 否 | | | |
| 48 | `POST /api/mongo/auth` | NoSQL 注入（安全对照） | 安全 | 否 | | | |
| 49 | `GET /api/download?filename=` | CRLF 注入 | 有漏洞 | 否 | | | |
| 50 | `GET /api/fetch-file?filename=` | CRLF（安全对照） | 安全 | 否 | | | |
| 51 | `POST /api/coupon/apply` | 优惠券重放 | 有漏洞 | 否 | | | |
| 52 | `POST /api/coupon/redeem` | 优惠券重放（安全对照） | 安全 | 否 | | | |
| 53 | `GET /api/v0/users` | Shadow API | 有漏洞 | 否 | | | |

## 汇总统计（跑完后填）

| 指标 | 数值 |
|---|---|
| 真漏洞检出（32 个中报 confirmed 的） | / 32 |
| 真漏洞仅报 suspected | |
| 漏报 | |
| 安全对照误报为 confirmed（21 个中） | / 21 |
| 安全对照误报为 suspected | |
| **被防幻觉机制降级的 confirmed 数**（rejectionReasons 计数） | |
| 降级理由分布（未发送过 / 未触发异常 / WAF 拦截 / 身份证据缺失） | |
| 单接口平均耗时 / token 消耗（如可统计） | |

### 特别关注的考点

- **#1（H2 显错）**：本地规则故意不覆盖 H2 报错，用来隔离测试"AI 层能否独立识别"——记一下是被动层命中还是 AI 判定命中
- **#31-42（Agent 专属）**：纯发请求测不出，检验源码调用链分析是否真的生效
- **#43-53（1.1.0 新增考点）**：命令注入 / NoSQL 注入 / CRLF 注入 / 优惠券重放 / Shadow API；其中 #43（IDOR 越权修改）需双会话验证
- **跳层类（21 条）**：有没有真的跟进 service/DAO 层（看 Agent 步骤里有没有 read_file/find_callers 记录）
- **安全对照组**：敢不敢如实报 SAFE，是比检出率更重要的指标
