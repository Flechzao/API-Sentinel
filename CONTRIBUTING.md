# Contributing to API Sentinel

Thank you for your interest in contributing to API Sentinel! This document provides guidelines for developers who want to contribute code, documentation, or ideas.

---

## 🚀 Development Setup

### Prerequisites

- **JDK 17** (required for Burp Montoya API compatibility)
- **Gradle 8.x** (or use the bundled `./gradlew`)
- **Burp Suite Professional** (recommended) or Community Edition
- **IDE**: IntelliJ IDEA recommended (with Lombok plugin if used)

### Clone and Build

```bash
git clone https://github.com/Flechzao/API-Sentinel.git
cd API-Sentinel
./gradlew shadowJar
# Output: dist/API-Sentinel-1.1.jar
```

### Load in Burp Suite

1. Build the JAR (see above)
2. Burp Suite → Extensions → Add → Extension type: Java
3. Select `dist/API-Sentinel-1.1.jar`
4. Check the "Errors" tab for any loading issues

### Run Tests

```bash
# All tests
./gradlew test

# Specific test class
./gradlew test --tests AgentLoopMechanicsTest

# With test report
./gradlew test && open build/reports/tests/test/index.html
```

**Current test status**: 1141 tests, 0 failures (see [CHANGELOG.md](CHANGELOG.md) for details)

---

## 📐 Architecture Overview

Before contributing, please review the architecture documents:

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Module dependencies, core class responsibilities, ADR decisions, dev tooling (all-in-one)
- **[README.md](README.md#产品定位)** — Product definition and design principles

### Key Modules

| Module | Responsibility |
|--------|----------------|
| `handler/` + `matching/` | API 流量捕获、归一化（Trie 精准 + 模糊匹配）、接口聚合 |
| `detection/` | 被动检测（SQL 错误、堆栈、安全头、JWT、CORS、敏感信息、未授权、Payload 库、攻击类型分类、自定义模板） |
| `ai/provider/` | LLM Provider（Claude/OpenAI/Ollama/DeepSeek）、prompt 构建、上下文管理 |
| `ai/pipeline/` | 6 阶段 Pipeline 模式、`VerdictValidator` 交叉校验、`FinalVerdict` |
| `ai/agent/` | ReAct Agent 循环、工具注册表、反思记忆、上下文压缩、多 Agent 协调 |
| `mcp/` | MCP Server（ServerSocket HTTP/1.1、JSON-RPC、会话管理、安全扫描） |
| `browser/` | Playwright 集成、agent-browser CLI、DOM 探索、视觉导航 |
| `ui/` | Swing 面板、表格、对话框 |
| `repository/` + `event/` | `ApiRepository` 持久化、`EventBus`/`UiEventBus` 跨模块通信 |

---

## 🎨 Code Style

### General Guidelines

- **Language**: Java 17 (use modern features: records, sealed classes, pattern matching)
- **Formatting**: 4 spaces (no tabs), 120 char line width
- **Naming**: camelCase for methods/variables, PascalCase for classes, UPPER_SNAKE for constants
- **Comments**: Javadoc for public APIs, inline comments for complex logic
- **Imports**: Organize by package, no wildcard imports (`import java.util.*` → explicit)

### Specific Patterns

**Records for data classes**:
```java
public record ApiEntry(String method, String path, String domain) {}
```

**Repository pattern for cross-module communication**:
```java
// ✅ Good: Use EventBus
EventBus.fire(ApiAnalyzedEvent.class, new ApiAnalyzedEvent(entry, result));

// ❌ Bad: Direct cross-module calls
aiPanel.updateResult(result);  // Don't do this
```

**Tool implementation pattern**:
```java
public class MyTool implements AgentTool {
    @Override
    public String name() { return "my_tool"; }
    
    @Override
    public String description() { return "What it does"; }
    
    @Override
    public ToolResult execute(ToolContext ctx, JsonObject params) {
        // Implementation
        return ToolResult.success(resultJson);
    }
}
```

---

## ✅ Testing Guidelines

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit tests | `src/test/java/**/*Test.java` | Isolated function/class testing |
| Integration tests | `src/test/java/**/*IntegrationTest.java` | Cross-module testing |
| Benchmark tests | `src/test/java/benchmark/` | Recall/precision/F1 evaluation |

### Writing Tests

```java
@Test
void testMyFeature() {
    // Arrange
    var input = new MyInput(...);
    
    // Act
    var result = myMethod(input);
    
    // Assert
    assertNotNull(result);
    assertEquals(expected, result.getValue());
}
```

### Test Coverage

- **New features**: Must include unit tests
- **Bug fixes**: Add a regression test that fails without the fix
- **Refactoring**: Ensure existing tests still pass

---

## 🔀 Pull Request Process

### Before Submitting

1. **Open an issue** (for large changes) to discuss the approach
2. **Fork the repo** and create a feature branch
3. **Run tests**: `./gradlew test`
4. **Update documentation** if you changed behavior

### PR Checklist

- [ ] Code follows the style guidelines
- [ ] Tests pass (`./gradlew test`)
- [ ] New tests added for new features
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (for user-visible changes)
- [ ] No compiler warnings

### PR Description Template

```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
- Tests added: [list]
- Tests passed: [yes/no]

## Related Issues
Closes #123
```

---

## 📝 Types of Contributions

### 🐛 Bug Reports

Use the GitHub issue tracker. Include:

- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Burp Suite version**
- **Java version** (`java -version`)
- **Logs** (from `~/.api-sentinel/logs/` if available)

### 💡 Feature Requests

Open an issue with the "enhancement" label. Explain:

- **Use case**: What problem does it solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Why this approach?

### 📖 Documentation

Documentation lives in `docs/`. To improve it:

1. Edit the relevant `.md` file
2. If adding new diagrams, use [Archify](references/archify-main) JSON format
3. Update the 「深入文档」section in root `README.md` if adding new documents
4. Submit a PR

### 🔧 Code Contributions

Good first issues:

- Bug fixes (see issues labeled "bug")
- Documentation improvements
- Test coverage improvements
- Performance optimizations (with benchmarks)

---

## 🏗️ Adding New Features

### Adding a New Agent Tool

1. Create `src/main/java/com/flechazo/apisentinel/ai/agent/tool/MyTool.java`
2. Implement `AgentTool` interface (`name()` / `description()` / `inputSchema()` / `execute(String argumentsJson)`)
3. Register in `StandardToolRegistry`（按只读/有状态决定是否进并行集）
4. Add tests in `src/test/java/.../MyToolTest.java`
5. Update `docs/FEATURES.md` tool parameter table

### Adding a New Passive Detector

1. Create `src/main/java/com/flechazo/apisentinel/detection/MyDetector.java`
2. 在 `HeuristicDetector` 中注册（或实现独立检测器类）
3. Add test cases with real HTTP traffic
4. Update `docs/FEATURES.md` detection rules table

### Adding a New LLM Provider

1. Create `src/main/java/com/flechazo/apisentinel/ai/provider/MyProvider.java`
2. Implement `LlmProvider` interface（`complete(LlmRequest)` / `isAvailable()` / `getId()` / `configure(...)`）
3. Register in Provider 选择逻辑
4. Add UI fields in `AiSettingsPanel`
5. Test with real API calls

---

## 🧪 Running the Benchmark

The benchmark evaluates recall/precision/F1 on 53 endpoints (32 vulnerabilities + 21 safe):

```bash
# Start the demo app
cd easyshop-app
mvn spring-boot:run

# Run benchmark (in another terminal)
BENCHMARK_ENABLED=true ./gradlew test --tests BenchmarkIntegrationTest

# View results
cat build/benchmark-report.txt
```

**Target metrics** (DeepSeek-V4-Pro + V4-Flash):
- Recall ≥ 90%
- Precision ≥ 65%
- F1 ≥ 0.75

---

## 📞 Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security issues**: See [SECURITY.md](SECURITY.md)

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).

---

## 🙏 Thank You

Your contributions help make API Sentinel better for everyone. Whether it's a bug report, documentation fix, or new feature, we appreciate your time and effort!
