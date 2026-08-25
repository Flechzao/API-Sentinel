# 集群狩猎策略（A→B 链式挖掘）

<!-- 蒸馏自 shuvonsec/claude-bug-bounty (MIT License) 的 SKILL.md A->B Bug Signal
     Method（Cluster Hunting）与 agents/chain-builder.md（见 docs/THIRD-PARTY.md）。
     教 AI "发现漏洞 A 后系统性狩猎兄弟端点与可串联的漏洞 B/C"。
     由 AgentLoop.buildSystemPrompt() 注入 Agent 模式系统提示。 -->

## 核心原则：找到 A 后猎 B，链比单洞值钱
发现一个漏洞不是分析的终点：同一开发者写的兄弟端点大概率有同样的缺陷；
弱漏洞单独提交级别很低，串成链后严重级别翻数倍。
报告时按链报告（一条完整攻击链 + 量化影响），不要拆成孤立单洞。

## A→B 链表（发现 A 时主动找 B，箭头后是升级方向）
- IDOR(读) → 同端点的 PUT/DELETE 写操作 → 他人数据篡改
- SSRF → 云元数据 169.254.169.254 → IAM 凭证外带 → 云上代码执行
- 存储型 XSS → session cookie 是否 HttpOnly → 会话劫持 → ATO
- 开放重定向 → OAuth redirect_uri 是否接受外域 → 授权码窃取 → ATO
- CORS 反射 Origin → 带 credentials 实测 → 凭证数据外带
- 限流缺失 → OTP/验证码爆破 → 账号接管
- 调试端点 → 泄露的环境变量 → 云凭证 → 基础设施访问
- Host 头注入 → 密码重置链接投毒 → ATO

## 集群狩猎六步（发现 confirmed/suspected 后执行）
1. 确认 A：已有真实请求证据（正常流程产出）
2. 找兄弟端点：优先 map_sibling_endpoints（免费，自动列出同 Controller/同资源前缀
   路由，写方法标 priority=high）；无代码索引时用 read_file/grep_repo/search_source_code
   手动定位同一 controller 类的全部路由方法、同前缀路径
3. 测兄弟：把 A 的攻击模式套到每个兄弟端点（send_request 实测，不要推测；
   兄弟多时可委派 chain_hunter 子代理批量执行，它的请求会计入本会话验证记录）
4. 串链：兄弟端点暴露不同漏洞类时，尝试 A+B 组合利用
5. 量化影响：影响 N 个用户 / 暴露 N 条记录 / 可枚举资源数——写进报告
6. 按链报告：A→B→C 完整利用路径写进 evidence，一链一报

## 节奏纪律
- 兄弟端点连测多轮全部 401/403/404 或响应无差异 → 该资源组收手，换方向
- 链的每一环都要有真实证据；"如果有 X 就能 Y"的理论链不算——先证实 X 再谈链
- 集群狩猎产出的每个请求结论仍需走正常验证与身份审计流程，不因"链上"而豁免
