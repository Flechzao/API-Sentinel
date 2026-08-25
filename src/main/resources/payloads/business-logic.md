# 业务逻辑漏洞检测触发条件

<!-- 蒸馏自 shuvonsec/claude-bug-bounty (MIT License) 的 web2-vuln-classes
     Business Logic 章节（见 docs/THIRD-PARTY.md）。由 TestGenPrompt 在请求参数/
     路径命中触发字段时按需注入。注意：以下测试均为真实业务操作，仅在授权环境执行。 -->

## 价格/金额篡改
触发字段：price, total, amount, cost, fee, balance, discount, coupon_value
测试动作：调用 verify_business_logic(test_type="tamper_price", target_param=字段名)
测试值：0.01（极小值）、-100（负数）、1e-10（科学计数法）
判定标准：请求被接受且返回 2xx → 确认漏洞；4xx 校验拒绝 → 安全

## 优惠券/折扣叠加
触发路径：/coupon, /discount, /promo, /voucher
测试动作：调用 verify_business_logic(test_type="repeat_coupon")
测试方式：使用同一优惠码发送两次请求
判定标准：两次都成功 → 确认漏洞；第二次被拒 → 安全

## 多步流程跳过
触发路径：/step, /flow, /checkout, /reset, /verify
测试动作：调用 verify_business_logic(test_type="step_skip")
测试方式：修改 URL 路径直接访问最终步骤
判定标准：绕过中间步骤仍能完成操作 → 确认；4xx 或重定向回第一步 → 安全

## 并发竞态
触发条件：接口涉及余额扣减、库存扣减、限量操作（领券/秒杀/提现）
测试动作：调用 verify_business_logic(test_type="concurrent_race", count=5)
测试方式：并发发送 5 个相同请求
判定标准：超额扣减/重复领取 → 确认漏洞

## 批量枚举
触发条件：API 接受 ID 参数且返回用户数据
测试动作：调用 verify_business_logic(test_type="batch_enumeration")
测试方式：遍历相邻 ID 范围，检查是否返回他人数据
判定标准：返回非本人数据 → 确认漏洞（IDOR）

## 负数攻击
触发条件：请求体中有数值型参数（quantity/price/amount）
测试动作：调用 verify_business_logic(test_type="negative_value")
测试值：-1、-100
判定标准：负数被接受且产生异常效果 → 确认漏洞
