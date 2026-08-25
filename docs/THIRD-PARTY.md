# 第三方致谢与借鉴声明 (Third-Party Attribution)

API-Sentinel 在开发过程中借鉴了开源项目 **claude-bug-bounty (BugHunter)** 的公开知识与代码思路。依据 MIT License 的要求与精神，在此登记借鉴清单。

- **项目名称**：claude-bug-bounty (BugHunter)
- **仓库地址**：https://github.com/shuvonsec/claude-bug-bounty
- **许可证**：MIT License（全文见文末）
- **借鉴性质**：知识蒸馏 + 逻辑移植。仅提取公开公认的渗透测试知识（payload 字符串、WAF 厂商签名、编码绕过手法、误报抑制规则），散文式表述以中文重写；未整段复制原项目文本。

## 借鉴清单

| 借鉴时间 | 本项目文件 | 来源 | 内容 |
|---|---|---|---|
| v1.0（此前） | `src/main/resources/payloads/payload-library.md` | `skills/security-arsenal/SKILL.md` | SQLi/XSS/SSRF/NoSQL/路径穿越/命令注入/SSTI/IDOR/JWT/XXE 的 payload 参考蒸馏 |
| v1.0（此前） | `src/main/java/.../ai/prompt/SafetyRules.java` | `skills/triage-validation/SKILL.md` | NEVER-SUBMIT 清单、kill signals、链式升级（CONDITIONALLY VALID）表 |
| 2026-08 | `src/main/java/.../detection/WafDetector.java` | `tools/waf_response_analyzer.py` | 12 家 WAF 厂商签名（body/header 正则）、拦截页关键词、加权评分与阈值思路 |
| 2026-08 | `src/main/java/.../detection/WafEncoder.java` | `tools/waf_encoder.py` | payload 编码变体生成（URL 多层编码、SQL 注释拆分、大小写混合、运算符替换、Base64 包装等） |
| 2026-08 | `src/main/resources/payloads/payload-library.md`（新增章节） | `skills/web2-vuln-classes/SKILL.md`、`skills/security-arsenal/SKILL.md` | 竞态条件、OAuth/OIDC、文件上传、GraphQL、WebSocket、请求走私等章节的 payload 蒸馏 |
| 2026-08 | `src/main/java/.../detection/ActiveProbeExecutor.java` | `tools/cors_scanner.py`、`tools/jwt_scanner.py`、`tools/crlf_scanner.py`、`tools/nosqli_scanner.py` | 主动探针判定逻辑：CORS 精确反射分级、JWT alg:none 伪造、CRLF canary 检出、NoSQL 差分/时序阈值 |
| 2026-08 | `payload-library.md`（精简重构）、`payloads/bypass-strategies.md`、`payloads/business-logic.md` | `skills/security-arsenal/SKILL.md`（WAF Bypass Reference）、`skills/web2-vuln-classes/SKILL.md`（Blind SQLi/Business Logic/Race） | 盲注 DB 函数表与指纹、绕过策略决策框架、业务逻辑触发条件 |
| 2026-08 | `src/main/java/.../detection/WafBypassEncoder.java`、`BooleanBlindVerifier.java`、`TimingBlindVerifier.java`、`BusinessLogicVerifier.java` | `tools/waf_encoder.py`（编码复用）、上述 skills 的判定方法 | 绕过策略链、布尔/时序盲注判定阈值（长度差 >5%、延迟 ≥90%）、业务逻辑 6 类测试判定标准 |
| 2026-08 | `src/main/java/.../ai/pipeline/VerdictValidator.java`（身份审计） | `validate.py` 的 Identity Check 思想 | 越权类 confirmed 身份证据强制（三问缺失自动降级 identity_not_proven），结构化 rejection_reasons |
| 2026-08 | `src/main/resources/rules/sensitive.yml`、`src/main/java/.../config/SensitiveRule.java`、`detection/SensitiveInfoDetector.java` | gh0stkey/HaE（规则正则与三层格式思想） | 敏感信息规则 13→27 条（Shiro/ViewState/passwd/win.ini/内网IP/MAC/Windows路径/Druid/Vite/SourceMap 等），主正则+排除过滤+作用域三层格式 |
| 2026-08 | `src/main/java/.../auth/AuthTestExecutor.java`（灰色区间 AI 仲裁） | sule01u/AutorizePro（Apache 2.0，越权响应语义判定思路） | Jaccard 相似度灰色区间（0.60-0.85）调 LLM 对基线/交换凭证响应对做 VULNERABLE/SAFE/UNKNOWN 裁决；prompt 为我们的自写改写版 |
| 2026-08 | `src/main/java/.../intruder/AiPayloadGenerator.java` 等（Intruder AI 载荷生成） | by-ai（MIT，Intruder AI 载荷生成思路） | Intruder Extension-generated 载荷生成器；改进了 AttackConfiguration 上下文利用（by-ai 收到但未使用），将完整请求模板+插入点上下文注入 prompt |
| 2026-08 | `src/main/resources/payloads/variant-matrix.md`、`.../ai/prompt/TestGenPrompt.java`（按需注入） | `SKILL.md` 的 IDOR Variants (10 Ways)、SSRF Impact Chain、Open Redirect Bypass Table | IDOR V1-V10 攻击面变体维度表、IDOR/SSRF 影响链定级、开放重定向 11 种绕过变体；命中对应漏洞类时注入 | 
| 2026-08 | `src/main/resources/payloads/chain-hunting.md`、`.../ai/agent/AgentLoop.java`（system prompt 注入） | `SKILL.md` 的 A->B Bug Signal Method (Cluster Hunting)、`agents/chain-builder.md` | 集群狩猎策略：A→B 链表、Cluster Hunt 六步法（确认 A→找兄弟→测兄弟→串链→量化→按链报告）、节奏纪律 |
| 2026-08 | `.../ai/agent/GoalState.java`、`.../ai/agent/AgentController.java`（级联狩猎） | CCB（claude-code 社区复刻）的 BLOCKED_CONSECUTIVE_THRESHOLD 连续阻塞熔断思想 | Controller 级联防失控：连续 N 轮无新发现熔断 + 会话预算封顶（Java 重写，无代码拷贝） |
| 2026-08 | `.../ai/patterns/PatternStore.java`（成功模式记忆） | `SKILL.md` 的 "reuse what worked" 纪律 | 已验证确认打法持久化为 (vulnType, technique, payload, endpoint, domain) 记忆，新分析注入历史成功模式 |

## 内置依赖（随仓库分发）

| 文件 | 组件 | 版权 / 许可证 | 用途 |
|---|---|---|---|
| `libs/burp-extensions-montoya-api-2026.7.jar` | Burp Suite Extensions Montoya API | © PortSwigger Ltd — Apache License 2.0（全文见文末） | 以 `compileOnly` 方式引入，编译期依赖；随仓库内置以便离线/内网环境开箱即构建。运行时由 Burp Suite 本体提供，本插件 jar 不打包该类。 |

> 说明：依据 Apache License 2.0，随附分发需保留许可证与版权声明，故在此登记并附许可证全文。

## 已知限制

- WAF 签名库覆盖国际主流 12 家厂商（Cloudflare、AWS WAF、Imperva、Akamai、F5 BIG-IP、ModSecurity、Sucuri、FortiWeb、Barracuda、Wallarm、360 WAF、Wordfence）。
- **未覆盖**部分国内常见 WAF（阿里云盾、雷池 SafeLine、深信服、长亭等），识别结果可能漏报；识别为"未拦截"不代表目标无任何防护。

## 内容取舍原则

1. 只取事实性内容：payload 字符串、检测签名、编码手法、验证规则——均为公开公认的渗透测试知识。
2. 不整段复制原项目的散文表述，用中文重写组织。
3. 借鉴文件头部注释保留来源标注。

## 上游许可证全文

```
MIT License

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 内置依赖许可证：Apache License 2.0

适用于 `libs/burp-extensions-montoya-api-2026.7.jar`（© PortSwigger Ltd）。

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   Copyright 2022 PortSwigger Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
