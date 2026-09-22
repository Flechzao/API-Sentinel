# API Sentinel 配置示例

> 本目录包含 API Sentinel 的各种配置模板和示例文件，帮助你快速上手。

---

## 📁 文件说明

### AI 配置

| 文件 | 用途 | 复制到 |
|------|------|--------|
| [ai-config.json.template](ai-config.json.template) | AI 服务商配置模板 | `~/.api-sentinel/ai-config.json` |

包含 Claude / OpenAI / Ollama / DeepSeek 四种服务商的配置示例。

### 主配置

| 文件 | 用途 | 复制到 |
|------|------|--------|
| [config.json.template](config.json.template) | 主配置文件模板 | `~/.api-sentinel/config.json` |

包含匹配模式、检测开关、MCP Server、预算管理、浏览器自动化等所有配置项。

### MCP 客户端配置

| 文件 | 用途 | 复制到 |
|------|------|--------|
| [mcp-client-config.json](mcp-client-config.json) | MCP 客户端配置示例 | 你的 MCP 客户端配置文件 |

Claude Code / Qoder / Codex 等 MCP 客户端的连接配置示例。

### 浏览器自动化

| 文件 | 用途 | 复制到 |
|------|------|--------|
| [login-profiles.json](login-profiles.json) | 登录配置模板 | `~/.api-sentinel/login-profiles.json` |

浏览器自动登录的多环境配置示例（管理员/普通用户/SSO）。

### 自定义敏感信息规则

| 文件 | 用途 | 复制到 |
|------|------|--------|
| [custom-sensitive-rules.json](custom-sensitive-rules.json) | 自定义规则示例 | `~/.api-sentinel/sensitive-rules.json` |

HaE 风格三层格式（主正则 + 排除过滤 + 作用域）的自定义规则示例。

---

## 🚀 快速开始

### 1. 配置 AI

```bash
# 复制模板
cp examples/ai-config.json.template ~/.api-sentinel/ai-config.json

# 编辑填入真实 API Key
vim ~/.api-sentinel/ai-config.json
```

或者在 UI 中配置：**API Sentinel 标签页 → 设置 ⚙ → AI 设置**

### 2. 配置主参数（可选）

```bash
# 复制模板
cp examples/config.json.template ~/.api-sentinel/config.json

# 根据需要调整
vim ~/.api-sentinel/config.json
```

大多数配置可以在 UI 中调整，无需手动编辑文件。

### 3. 配置 MCP 客户端（可选）

```bash
# 查看示例
cat examples/mcp-client-config.json

# 复制到你的 MCP 客户端配置目录
cp examples/mcp-client-config.json .mcp.json

# 编辑填入真实 token（从 Burp 控制台复制）
vim .mcp.json
```

### 4. 配置浏览器自动登录（可选）

```bash
# 复制模板
cp examples/login-profiles.json ~/.api-sentinel/login-profiles.json

# 编辑填入真实账号密码
vim ~/.api-sentinel/login-profiles.json
```

或者在 AI 对话中直接告诉 agent 账号密码（agent 检测到 401/403 时会主动询问），登录成功后可勾选"记住此账号"自动沉淀为 profile。

### 5. 添加自定义敏感信息规则（可选）

```bash
# 复制模板
cp examples/custom-sensitive-rules.json ~/.api-sentinel/sensitive-rules.json

# 根据需要添加/修改规则
vim ~/.api-sentinel/sensitive-rules.json
```

或者在 UI 中添加：**设置 → 检测 → 敏感信息规则 → 添加**

---

## 💡 常见场景配置

### 场景 1：本地开发（Ollama + 无限预算）

```json
{
  "provider": "ollama",
  "endpoint": "http://localhost:11434/v1",
  "apiKey": "ollama",
  "model": "deepseek-coder-v2"
}
```

```json
{
  "budgetMode": "MONITOR_ONLY",
  "dailyBudgetTokens": 999999999
}
```

**优点**：数据不出本机，无预算限制  
**缺点**：模型质量可能不如云端大模型

### 场景 2：生产测试（Claude + 严格预算）

```json
{
  "provider": "claude",
  "endpoint": "https://api.anthropic.com",
  "apiKey": "sk-ant-xxx",
  "model": "claude-sonnet-4-20250514"
}
```

```json
{
  "budgetMode": "ENFORCE",
  "dailyBudgetTokens": 100000,
  "perRequestMaxTokens": 20000
}
```

**优点**：高质量分析  
**缺点**：需要 API Key，有成本

### 场景 3：团队协作（MCP Server + Claude Code）

1. 在 Burp 中启用 MCP Server：
```json
{
  "mcpServerEnabled": true,
  "mcpServerPort": 9877,
  "mcpAllowActiveTools": false
}
```

2. 在 Claude Code 项目中配置 `.mcp.json`：
```json
{
  "mcpServers": {
    "api-sentinel": {
      "type": "http",
      "url": "http://127.0.0.1:9877/mcp",
      "headers": {
        "Authorization": "Bearer <从 Burp 控制台复制>"
      }
    }
  }
}
```

3. 在 Claude Code 中使用：
```
你：列出所有已捕获的 API
你：分析 /api/users/{id} 是否有越权
你：这个接口的后端源码是什么？
```

### 场景 4：浏览器自动化（自动登录 + 探索）

1. 配置登录：
```json
{
  "profiles": [
    {
      "name": "测试环境",
      "loginUrl": "https://test.example.com/login",
      "username": "admin@test.com",
      "password": "password123",
      "strategy": "CUSTOM_FORM",
      "formSelectors": {
        "username": "#email",
        "password": "#password",
        "submit": "button[type='submit']"
      },
      "successIndicators": ["/dashboard"],
      "persistCookies": true
    }
  ]
}
```

> 💡 **更省事的做法**：不写配置文件，让 agent 在分析时自动问你账号密码，填完后勾选"记住"即可自动沉淀成 profile。

2. 配置前端 URL：
```json
{
  "browserFrontendUrl": "https://test.example.com",
  "browserEnabled": true
}
```

3. 使用 Agent 工具：
```
browser_login(profile_name="测试环境")
browser_explore(target_api="POST /api/v1/roles", start_url="https://test.example.com")
browser_auto_crawl(start_url="https://test.example.com")
```

### 场景 5：自定义敏感信息规则

添加公司内部 API Key 检测：

```json
{
  "name": "公司内部 API Key",
  "regex": "(api[_-]?key|apikey)\\s*[:=]\\s*['\"]([a-zA-Z0-9]{32,})['\"]",
  "exclude": "example|test|demo",
  "scope": "response"
}
```

**字段说明**：
- `name`：规则名称（在 UI 中显示）
- `regex`：主正则表达式（匹配敏感信息）
- `exclude`：排除正则（减少误报）
- `scope`：作用域（`request` / `response` / `any`）

---

## 🔧 配置文件位置

所有配置文件默认在 `~/.api-sentinel/` 目录：

```
~/.api-sentinel/
├── ai-config.json          # AI 服务商配置
├── config.json             # 主配置
├── data.json               # 接口数据 + 分析历史
├── rules.json              # 学习规则 + 误报抑制
├── sensitive-rules.json    # 自定义敏感信息规则
├── login-profiles.json     # 浏览器登录配置
├── chat-history.json       # AI 对话历史
├── code-index.json         # 代码仓库索引缓存
├── patterns.json           # 成功模式记忆
└── logs/                   # 日志目录
    └── api-sentinel.log
```

**便携模式**：设置环境变量 `API_SENTINEL_HOME=/path/to/dir`，所有文件从该目录读写。

---

## 📚 相关文档

- [快速开始](../README.md#快速开始)
- [配置说明](../README.md#配置)
- [MCP Server](../README.md#mcp-server让-claude-调用)
- [浏览器自动化](../README.md#-浏览器自动化探索v11-新增)
- [功能参考](../docs/FEATURES.md) — 被动检测规则、工具参数
- [产品定义](../README.md#产品定位) — 设计原则、不做清单

---

## ❓ 常见问题

**Q: 配置文件格式错误怎么办？**  
A: API Sentinel 会在启动时报错并回退到默认值。检查 JSON 语法（可用 `jq` 或在线 JSON 验证器）。

**Q: 修改配置后需要重启 Burp 吗？**  
A: 大部分配置即时生效（UI 修改）。手动编辑文件后需重载扩展（Extensions → Unload → Load）。

**Q: 如何备份配置？**  
A: 复制整个 `~/.api-sentinel/` 目录即可。

**Q: 配置文件中哪些字段不能删？**  
A: 所有字段都是可选的（有默认值）。删除字段会回退到默认值。

**Q: 如何在团队间共享配置？**  
A: 分享 `ai-config.json` 和 `config.json`（删除 apiKey）。不要分享 `data.json`（含敏感流量数据）。

---

## 🆘 获取帮助

- **文档**：[README.md](../README.md#深入文档)
- **贡献**：[CONTRIBUTING.md](../CONTRIBUTING.md)
- **安全问题**：[SECURITY.md](../SECURITY.md)
- **Bug 报告**：GitHub Issues
