# API-Sentinel Benchmark 使用指南

> **本文档是 benchmark 框架的唯一使用说明**。
> - 想知道 benchmark **是什么** → 看 §1
> - 想**跑一次** benchmark → 看 §2
> - 想**看懂报告** → 看 §3
> - 想**扩展靶场** → 看 §4
> - 想看**历史数据** → 看 §5

---

## 1. Benchmark 是什么

API-Sentinel 是一个 **AI 驱动的 API 漏洞分析工具**，需要一个标准靶场来衡量它的漏洞挖掘能力。`easyshop-app/` 就是这个靶场：

- **53 个 API 端点**
- **32 个真漏洞**（SQL 注入、XSS、SSRF、IDOR、越权、Mass Assignment 等 13 类）
- **21 个安全对照**（每个漏洞类型都有一个 safe 版本，用来测误报）
- 每个端点在 `easyshop-app/GROUND_TRUTH.md` 里有**真值标注**（漏洞类型 + 是否应该被检出）

Benchmark 框架做的事：
1. 启动 `easyshop-app`（监听 `localhost:8089`）
2. 自动发流量到 53 个端点
3. 让 API-Sentinel 的 `AnalysisPipeline` 分析每个端点
4. 对比分析结果 vs `GROUND_TRUTH.md` 的真值
5. 算出 **recall / precision / FP rate / F1**
6. 写到 `build/benchmark-report.txt`

### 核心指标解释

| 指标 | 公式 | 含义 | 健康范围 |
|---|---|---|---|
| **Recall（召回率）** | TP / (TP + FN) | 真漏洞被检出的比例 | ≥ 85% |
| **Precision（精度）** | TP / (TP + FP) | 检出的里面有多少是真的 | ≥ 65% |
| **FP rate（误报率）** | FP / (FP + TN) | 安全端点被误报为漏洞的比例 | ≤ 70% |
| **F1** | 2 × precision × recall / (precision + recall) | 综合指标 | ≥ 0.75 |

**解读**：
- **Recall 掉 = 漏报增多**（危险）：工具漏掉了真漏洞
- **Precision 掉 = 误报增多**（烦人）：工具乱报漏洞
- **FP rate 掉**（数值下降是好事）= 安全端点被误报的比例降低

---

## 2. 跑一次 Benchmark（5 分钟）

### 前置条件

- JDK 17+（推荐 21）
- Maven（用来启动 `easyshop-app`）
- 已配置好 AI Provider（`~/.api-sentinel/ai-config.json` 或 UI 里配过）

### 步骤

```bash
# 1. 进入项目目录
cd /path/to/API-Sentinel

# 2. 启动 easyshop-app（第一次会自动 mvn package）
cd easyshop-app && mvn spring-boot:run
# 或者用 jar（如果之前 package 过）：
# java -jar target/easyshop-1.0.0.jar

# 保持这个终端开着，另开一个终端做下面的步骤

# 3. 在另一个终端，验证 easyshop-app 已起
curl -s http://localhost:8089/web/dashboard | head -1
# 应该返回 HTML 的第一行

# 4. 跑 benchmark（约 10 分钟）
cd /path/to/API-Sentinel
BENCHMARK_ENABLED=true BENCHMARK_BASE_URL=http://localhost:8089 \
  ./gradlew test \
    --tests 'com.flechazo.apisentinel.benchmark.BenchmarkIntegrationTest' \
    --no-daemon \
    --rerun-tasks

# 5. 看报告
cat build/benchmark-report.txt
```

### Quick 模式（快速回归，~5 分钟）

```bash
# Quick 模式只测试 ~30 个代表性端点（每种漏洞类型各一个 vuln + safe 对）
BENCHMARK_ENABLED=true BENCHMARK_MODE=quick \
  BENCHMARK_BASE_URL=http://localhost:8089 \
  ./gradlew test \
    --tests 'com.flechazo.apisentinel.benchmark.BenchmarkIntegrationTest' \
    --no-daemon --rerun-tasks
```

**Quick 模式覆盖的漏洞类型**：SQLi、IDOR、JWT、CORS、SSRF、上传、反序列化、调试信息泄露、XSS、SSTI、路径穿越、竞态条件、加密、Mass Assignment、命令注入、NoSQL 注入。

### 报告示例

```
=== API-Sentinel Benchmark Report ===
Total endpoints: 53  (vulnerable: 32, safe controls: 21)
Recall:    92.6%  (TP=25 / FN=2)
Precision: 69.4%  (TP=25 / FP=11)
FP rate:   64.7%  (FP=11 / TN+FP=17)
F1:        0.794

--- Per-row outcomes ---
  #01 [TP] GET      GET /api/users/search?name=
         detected-as: SQL注入 (MEDIUM)
  #02 [TN] GET      GET /api/products/search?name=
  ...
```

### 报告字段

| 标记 | 含义 |
|---|---|
| `[TP]` | True Positive：真漏洞，正确检出 ✅ |
| `[TN]` | True Negative：安全端点，正确没报 ✅ |
| `[FP]` | False Positive：安全端点，**被误报为漏洞** ❌ |
| `[FN]` | False Negative：真漏洞，**漏检了** ❌ |

### 自动化脚本

项目里已经有 `scripts/start-benchmark-env.sh` 和 `scripts/stop-benchmark-env.sh`：

```bash
# 启动 easyshop-app（如果装了 docker）
./scripts/start-benchmark-env.sh

# 跑 benchmark
BENCHMARK_ENABLED=true BENCHMARK_BASE_URL=http://localhost:8089 \
  ./gradlew test \
    --tests 'com.flechazo.apisentinel.benchmark.BenchmarkIntegrationTest' \
    --no-daemon

# 关闭 easyshop-app
./scripts/stop-benchmark-env.sh
```

---

## 3. 看懂报告

### 关注什么

1. **Recall 掉没掉**（最重要）：
   - 上次 92.6%，这次 90% → 掉了 2.6 pp，需要排查
   - 检查 `[FN]` 端点（漏报的），看是哪一类漏洞漏了
2. **FP rate 涨没涨**：
   - 上次 64.7%，这次 75% → 涨了 10 pp，需要排查
   - 检查 `[FP]` 端点（误报的），看是哪一类 safe 端点被误报了
3. **F1 综合**：
   - 综合 recall + precision，F1 掉说明整体质量下降

### 排查漏报（FN）

```bash
grep '\[FN\]' build/benchmark-report.txt
```

找到漏报的端点后：
- 看 `detected-as:` 字段（如果存在）→ 模型把它当成了什么
- 看 `AnalysisPipeline` 的 stage 6 输出（`build/reports/` 下的 JSON 报告）
- 检查是否是**代码改动**导致的（P0/P1 改造里有没有动到相关判定逻辑）

### 排查误报（FP）

```bash
grep '\[FP\]' build/benchmark-report.txt
```

找到误报的端点后：
- 看 `detected-as:` 字段 → 模型把它当成了什么漏洞
- 看 `VerdictValidator` 的 rejection reasons（JSON 报告里的 `rejectionReasons` 数组）
- 检查是否是 **P0-8 VerdictValidator 收紧**没覆盖到的绕过

### 对比历史

每次跑完 benchmark，把数据记到 §5 历史数据表里。如果发现某次改动后指标明显下降，用 `git bisect` 定位到哪个 commit 引入的回归。

---

## 4. 扩展靶场

### 加一个新漏洞类型

1. 在 `easyshop-app/src/main/java/.../controller/` 加一个新的 Controller，写一个有漏洞的端点和一个 safe 版本
2. 在 `easyshop-app/GROUND_TRUTH.md` 的漏洞对照表里加两行（漏洞 + safe 对照）
3. 在 `benchmark/BenchmarkTrafficDriver.java` 加对应的请求构造逻辑
4. 重跑 benchmark，看新漏洞能不能被检出

### 加一个新测试维度

例如你想加"响应时间异常检测"：

1. 在 `easyshop-app` 加几个**响应时间异常**的端点（例如故意 sleep 5s）
2. 在 `GROUND_TRUTH.md` 加对应的真值标注
3. 在 `BenchmarkMetrics.java` 加新的指标计算（例如 `latencyAnomalyRate`）
4. 在 `BenchmarkIntegrationTest.java` 加对应的断言

### 加一个新的安全对照

已有的 13 类漏洞每类都有一个 safe 版本。如果你想加更多 safe 版本（例如 SQL 注入的另一种修复方式）：

1. 在 `easyshop-app` 加端点
2. 在 `GROUND_TRUTH.md` 加一行，"结论"列写 "安全"
3. 重跑 benchmark，看 safe 端点有没有被误报

---

## 5. 历史数据

| 日期 | 改造状态 | Recall | Precision | FP rate | F1 | 备注 |
|---|---|---|---|---|---|---|
| 2026-08-26 | 原始基线（人工审计）| 83% | N/A | N/A | N/A | 仅 recall 一项，人工核对 |
| 2026-09-06 AM | P0 全清后 | 88.9% | 66.7% | 70.6% | 0.762 | 第一次自动化 benchmark |
| 2026-09-06 PM | P0+P1 主体全清 | **92.6%** | **69.4%** | **64.7%** | **0.794** | 当前基线 |
| _下次跑_ | _?_ | _?_ | _?_ | _?_ | _?_ | _你跑完填这里_ |

### 健康范围参考

- **Recall**：≥ 85% 健康，< 80% 需要排查
- **Precision**：≥ 65% 健康，< 60% 需要排查
- **FP rate**：≤ 70% 健康，> 80% 需要排查
- **F1**：≥ 0.75 健康，< 0.70 需要排查

### 什么时候要重跑 benchmark

- ✅ 改了 `AnalysisPipeline` / `AgentLoop` / `VerdictValidator` 等核心逻辑
- ✅ 改了 `VulnAnalysisPrompt` / `FinalVerdictPrompt` 等 prompt
- ✅ 升级了 AI Provider（Claude 新版 / 换了模型）
- ✅ 加了新的检测工具（tool）
- ❌ 改了 UI / 改了报告模板 / 改了 config schema → 不用跑（不影响检测能力）

---

## 6. 框架代码速览

| 文件 | 作用 | 大小 |
|---|---|---|
| `benchmark/GroundTruthEntry.java` | 一行真值记录的数据结构 | 50 行 |
| `benchmark/GroundTruthParser.java` | 解析 `GROUND_TRUTH.md` 拿 53 条真值 | 80 行 |
| `benchmark/BenchmarkMetrics.java` | 算 recall / precision / FP rate / F1 | 60 行 |
| `benchmark/BenchmarkTrafficDriver.java` | 驱动 53 端点流量捕获 | 180 行 |
| `benchmark/BenchmarkIntegrationTest.java` | 集成测试入口（`@Disabled` 默认不跑）| 90 行 |
| `benchmark/BenchmarkFrameworkTest.java` | 框架本身 11 个对抗测试 | 120 行 |

### 入口：`BenchmarkIntegrationTest`

```java
@Test
void fullBenchmarkRunProducesReportAndMeetsRegressionTargets() {
    // 1. 启动 traffic driver（捕获 53 端点流量）
    // 2. 对每个端点调 AnalysisPipeline.analyze()
    // 3. 收集所有 PipelineResult 的 FinalVerdict
    // 4. 对比 GROUND_TRUTH.md
    // 5. 算 BenchmarkMetrics
    // 6. 写到 build/benchmark-report.txt
    // 7. 断言 recall ≥ 0.84 / precision ≥ 0.60 / FP rate ≤ 0.75
}
```

### 启用 benchmark 的开关

测试默认 `@Disabled`，要启用必须设环境变量：

```bash
BENCHMARK_ENABLED=true   # 启用测试
BENCHMARK_BASE_URL=http://localhost:8089   # easyshop-app 地址
```

如果没设 `BENCHMARK_ENABLED`，测试会被 `Assumptions.assumeTrue` 跳过（不算失败）。

---

## 7. FAQ

**Q：跑一次 benchmark 要多少钱？**
A：53 个端点 × 单端点 $0.35（P0+P1 后）≈ **$15.4**。如果只用主模型（没配 fastModel）≈ $66。

**Q：跑一次要多久？**
A：约 **10 分钟**（53 端点 × 平均每端点 13 秒，含 LLM 调用）。

**Q：为什么 benchmark 不自动跑？**
A：benchmark 要启动 `easyshop-app` + 调 LLM（要 API key），不适合每次 `./gradlew test` 都跑。用 `BENCHMARK_ENABLED=true` 显式启用。

**Q：benchmark 失败了怎么办？**
A：先看报告里的 `[FN]` / `[FP]` 端点，确定是漏报还是误报。如果是 LLM 的偶发抖动（同一个端点重跑结果不同），重跑一次确认；如果是稳定失败，按 §3 排查。

**Q：怎么知道 benchmark 结果是稳定的？**
A：连续跑 3 次，看 recall / precision / FP rate 的波动。正常波动 ±2 pp，超过 ±5 pp 就是真回归。

**Q：`easyshop-app` 能部署到公网吗？**
A：**绝对不能**。靶场有 32 个真漏洞，部署到公网等于给攻击者送漏洞。只在本地跑。

**Q：能换别的靶场吗？**
A：可以，但需要：① 写一个新的 `GROUND_TRUTH.md` ② 写一个新的 `TrafficDriver` ③ 改 `BenchmarkIntegrationTest` 指向新靶场。工作量约 1-2 人日。

---

## 8. 参考

- `easyshop-app/GROUND_TRUTH.md` — 53 端点真值标注
- `docs/plan/2026-09-06改造完工报告.md` — 改造结果
- `docs/plan/0905技术分析与深度审计.md` — 原始审计报告
- `benchmark/BenchmarkIntegrationTest.java` — 集成测试源码
