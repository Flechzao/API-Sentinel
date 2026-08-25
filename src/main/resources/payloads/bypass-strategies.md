# 绕过策略决策框架

<!-- 蒸馏自 shuvonsec/claude-bug-bounty (MIT License) 的 WAF Bypass Reference 与
     bb-methodology（见 docs/THIRD-PARTY.md）。教 AI "什么情况下该尝试什么绕过、
     失败后如何继续"，由 TestGenPrompt 在命中可绕过类漏洞时按需注入。 -->

## 规则 1：WAF 拦截时不要直接放弃
当 send_request 返回 waf_detected=true（或 Pipeline 结果显示 🛡）时：
- 调用 waf_bypass_retry 工具尝试绕过（免费，最多 4 次请求）
- 绕过成功 → 用返回的 bypass_payload 继续分析
- 绕过失败 → 报告中标注"WAF 防护有效，未能绕过"，对应发现标疑似

## 规则 2：显错注入失败时继续测盲注
当 SQL 注入 payload 未触发数据库错误回显时：
- 第一步：调用 verify_boolean_blind（true/false 条件响应对比）
- 第二步：布尔盲注也无法确认时，调用 verify_timing_blind（SLEEP 计时）
- 两步都失败 → 才能标注"未发现 SQL 注入"
- 禁止在显错失败后直接下结论"安全"

## 规则 3：SSRF 测试 IP 被拦截时尝试编码
当 127.0.0.1/169.254.169.254 被拦截时，按顺序尝试：
- 十进制 IP（2130706433）→ 十六进制（0x7f.0.0.1）→ IPv6（[::1]）→ DNS rebinding（127.0.0.1.nip.io）→ 302 重定向
- 每个变体成功即停，全部失败则放弃

## 规则 4：命令注入分隔符被拦截时尝试替换
当 ; 被拦截时，按顺序尝试：
- | → || → && → 反引号 → $() → %0a（换行符）
- 空格被拦截时：${IFS} → $IFS$9 → {cmd,arg} → < 重定向

## 规则 5：文件上传扩展名被拦截时尝试绕过
- 双扩展名（shell.php.jpg）→ 大小写变体（.pHp）→ 空字节截断（%00.jpg）→ 替代扩展名（.php5/.phtml）→ MIME 伪装
- 全部失败 → 测 SVG 存储型 XSS（SVG 通常不被拦截）

## 规则 6：SSTI 探针被拦截时尝试引擎切换
- {{7*7}} 被拦截 → 尝试 ${7*7} → <%= 7*7 %> → #{7*7}
- 不同引擎语法不同，WAF 可能只拦截其中一种
