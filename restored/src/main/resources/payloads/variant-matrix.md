# 攻击面变体矩阵与影响链

<!-- 蒸馏自 shuvonsec/claude-bug-bounty (MIT License) 的 SKILL.md IDOR Variants/Chains、
     SSRF Impact Chain 与 Open Redirect Bypass Table（见 docs/THIRD-PARTY.md）。
     教 AI "同一漏洞类还有哪些攻击面维度没测、确认后影响能升到多高"，由
     TestGenPrompt 在命中对应漏洞类时按需注入。与 payload-library.md（基础
     payload 知识）、bypass-strategies.md（被拦截后如何绕过）正交。 -->

## IDOR：10 个变体维度（发现越权线索时逐项核对，不要只测路径替换）
V1 直接替换：URL 路径对象 ID（/api/users/123 → 456）
V2 请求体替换：POST/PUT JSON body 中的 ID（{"user_id": 456}）
V3 GraphQL node：node(id:) 换 ID 后需重新 base64 编码
V4 批量端点：?ids=1,2,3 一次请求多个对象 ID（鉴权常只校验第一个）
V5 嵌套路径：/orgs/{org_id}/users/{user_id} 两级 ID 都要换
V6 文件路径形式：/files/download?path=../other-user/file.pdf
V7 可预测 ID：纯递增数字/时间戳/短 UUID——可枚举说明影响面大
V8 方法交换：GET 403 时改 PUT/PATCH/DELETE（读有鉴权写没有是高频缺陷）
V9 版本回退：v2 有鉴权时试 v1/internal 路径
V10 头注入：X-User-ID / X-Org-ID / X-Forwarded-User 请求头直接指定身份

## IDOR 影响链（确认读越权后往哪升级——决定严重级别）
读他人普通数据 = MEDIUM；修改/删除他人数据（V8/V2 写变体）= HIGH；
命中管理端点或可通向账号接管 = CRITICAL。
发现 read IDOR 后必须测写方法（V8）才能完成定级——只报读不报写会低估影响。

## SSRF 影响链（按可达深度定级）
仅 DNS 回连 = 不算命中（Informational）；内部端口可达（Redis 6379/ES 9200/
Mongo 27017）= MEDIUM；云元数据可读（169.254.169.254）= HIGH；
元数据 + IAM 凭证外带 = CRITICAL；Docker API（2375）可达 = CRITICAL（直接 RCE）。
升级路径：确认 URL 参数 SSRF 后依次尝试 内部端口 → 云元数据 → file:// 读本地
文件 → 拿到凭证后验证其真实可用性（能否调云 API）。

## 开放重定向：验证与利用变体（单独重定向不算洞，必须串成链）
确认跳转后测 OAuth 链：redirect_uri 是否接受自己控制的域名 → 授权码窃取 → ATO。
绕过域名校验的变体（按序尝试）：
//evil.com（协议相对）→ https://target.com@evil.com（@ 技巧）→
https://target.com\@evil.com（反斜杠，部分解析器归一化为 /）→
%252F%252F（双重 URL 编码）→ //evil.com#target.com（fragment 混淆）→
?next=target.com&next=evil.com（参数污染，解析器取后值）→
/redirect/..%2F..%2Fevil.com（路径穿越式）→ //evil%09.com（tab 注入）。
