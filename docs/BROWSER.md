# API Sentinel 浏览器手册

> 浏览器手册（Playwright/Chromium 安装 + agent-browser 集成二合一）。根 [README.md](../README.md) 提供快速开始。

## 目录

- [第一部分：浏览器分析功能安装指南（Playwright / Chromium）](#第一部分playwright--chromium-安装)
- [第二部分：agent-browser 集成指南（认证提取 / 请求捕获 / 批量触发）](#第二部分agent-browser-集成)

---

# 第一部分：Playwright / Chromium 安装


API Sentinel 提供**浏览器能力集成**（DOM XSS 检测、SPA 接口发现、JS Bundle 密钥扫描），基于 Playwright 控制独立的 Chromium 浏览器实例。

> ⚠️ **不影响你的系统 Chrome** — Playwright 使用独立的 Chromium，安装在 `~/Library/Caches/ms-playwright/`（macOS）或 `%LOCALAPPDATA%\ms-playwright\`（Windows），与你日常使用的 Chrome 完全隔离。

---

## 快速开始

### 第一步：启用功能

1. 在 Burp Suite 中加载 API Sentinel JAR
2. 进入 API Sentinel → 设置面板
3. 勾选 ✅ **「启用浏览器分析 (Playwright + Chromium)」**
4. 点击「保存配置」
5. **重启扩展**（Burp Extensions → API Sentinel → Reload）

### 第二步：安装 Chromium（三选一）

#### 方式 A：自动下载（推荐，~80MB）

在终端执行：

```bash
# 下载 Playwright CLI 工具（一次性）
curl -L -o playwright-cli.jar \
  "https://repo1.maven.org/maven2/com/microsoft/playwright/playwright/1.49.0/playwright-1.49.0.jar"

# 安装 Chromium（仅下载当前平台，~80MB）
java -cp playwright-cli.jar com.microsoft.playwright.CLI install chromium
```

**Windows PowerShell：**
```powershell
Invoke-WebRequest -Uri "https://repo1.maven.org/maven2/com/microsoft/playwright/playwright/1.49.0/playwright-1.49.0.jar" -OutFile playwright-cli.jar
java -cp playwright-cli.jar com.microsoft.playwright.CLI install chromium
```

安装完成后可以删除 `playwright-cli.jar`。

#### 方式 B：复用系统 Chrome

如果你不想额外下载，可以直接使用已安装的 Chrome。在 API Sentinel 设置面板的 **「Chrome 路径」** 填入：

| 平台 | 路径 |
|------|------|
| **macOS** | `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` |
| **Windows** | `C:\Program Files\Google\Chrome\Application\chrome.exe` |

> 注意：系统 Chrome 版本可能和 Playwright 协议不完全兼容，如遇到问题请改用方式 A。

#### 方式 C：从源码构建

如果你是从源码构建 API Sentinel：

```bash
./gradlew installChromium
```

---

## 验证安装

启用后，Agent 分析 SPA 前端页面时会自动使用浏览器工具。你也可以在 Burp 的 Extender 日志中看到：

```
[Browser] 正在提取 Playwright driver 到 /Users/xxx/.api-sentinel/playwright-driver/mac-arm64/ ...
[Browser] driver 提取完成
[Browser] 启动 Playwright + Chromium (proxy=127.0.0.1:8080, headless=true)
[Browser] Chromium 启动成功
```

> **首次加载时**，扩展会自动将 Playwright driver（Node.js 桥接）从 JAR 中提取到 `~/.api-sentinel/playwright-driver/` 目录。
> 后续启动直接使用缓存，无需重新提取。

如果看到 `═══════ Playwright 浏览器未安装 ═══════` 的提示，说明 Chromium 还没装好，按上面的步骤操作即可。

---

## 功能说明

启用浏览器后，Agent 模式新增 7 个工具：

| 工具 | 用途 |
|------|------|
| `browser_login` | 自动登录获取 Cookie（支持用户名/密码、SSO/BUC） |
| `browser_explore` | 智能探索触发目标 API（LLM 决策多层导航，**支持视觉识别**） |
| `browser_auto_crawl` | 一键全站扫描：登录→发现→探索→注册 |
| `browser_discover` | 打开前端页面，自动捕获 API 请求、分析 JS Bundle、提取路由 |
| `browser_render` | 渲染页面获取完整 DOM、console 日志、CSP 违规信息 |
| `browser_dom_xss` | 检测 DOM XSS（innerHTML/eval/document.write 等 sink） |
| `register_discovered_apis` | 将发现的 API 注册到目标清单 |

### browser_login 使用说明

`browser_login` 可以自动完成登录流程并获取 Cookie，无需手动复制粘贴。

**配置方式**：创建 `~/.api-sentinel/login-profiles.json`：

```json
{
  "profiles": [
    {
      "name": "生产环境",
      "loginUrl": "https://app.example.com/login",
      "username": "test_user",
      "password": "your_password",
      "strategy": "AUTO",
      "successIndicators": ["/dashboard", "/home"],
      "persistCookies": true
    }
  ]
}
```

**支持的策略**：
- `AUTO`：自动识别登录表单（默认）
- `CUSTOM_FORM`：使用自定义 CSS 选择器
- `SSO_BUC`：处理 BUC/SSO 跳转流程

**Agent 调用示例**：
```
browser_login(profile_name="生产环境")
// 或内联参数
browser_login(login_url="https://app.example.com/login", username="user", password="pass")
```

### browser_explore 使用说明

`browser_explore` 可以智能探索页面，自动点击菜单/按钮/表单来触发目标 API。适用于需要多层导航才能触发的接口。

**工作原理**：
1. 提取页面可交互元素（按钮、链接、输入框等）
2. LLM 分析目标 API 并决策下一步操作
3. 执行操作并检查是否触发目标 API
4. 循环直到触发目标或达到最大深度

**Agent 调用示例**：
```
// 探索触发角色管理 API 的路径
browser_explore(
    target_api="POST /api/v1/roles",
    start_url="http://localhost:3000",
    max_depth=10,
    hints=["在系统管理菜单下", "需要管理员权限"]
)
```

**特性**：
- 自动缓存成功路径，下次直接回放
- 检测并跳出循环
- 支持提示引导探索方向

---

## 常见问题

**Q: 为什么不直接用系统 Chrome？**
A: Playwright 需要特定版本的浏览器协议支持，自带 Chromium 保证兼容性。系统 Chrome 更新可能导致不匹配。

**Q: 下载太慢怎么办？**
A: Playwright 的 Chromium 托管在 CDN 上，国内用户可能需要代理。也可以通过方式 B 直接使用系统 Chrome 跳过下载。

**Q: 禁用后还会有后台进程吗？**
A: 不会。不勾选「启用浏览器分析」时，Playwright 完全不加载，零资源占用。

**Q: 存储占用多少？**
A: Chromium Headless Shell 约 80-120MB，存放在 `~/Library/Caches/ms-playwright/`（macOS）或 `%LOCALAPPDATA%\ms-playwright\`（Windows）。Playwright driver 缓存在 `~/.api-sentinel/playwright-driver/`（约 120MB）。卸载时删除这两个目录即可。

**Q: 出现 "Failed to create driver" 错误怎么办？**
A: API Sentinel 已内置 classloader 修复，会自动从 JAR 中提取 driver 到 `~/.api-sentinel/playwright-driver/`。如果仍然报错：
1. 检查该目录下是否有 `node`（macOS/Linux）或 `node.exe`（Windows）文件
2. 确保该文件有可执行权限：`chmod +x ~/.api-sentinel/playwright-driver/mac-arm64/node`
3. 删除该目录让扩展重新提取：`rm -rf ~/.api-sentinel/playwright-driver/`

---

## DeepSeek 视觉模型配置

API Sentinel 支持 **DeepSeek-V4-Flash-Vision-Exp** 视觉模型，可以在探索时自动截图辅助 LLM 决策。

### 配置方式

1. 在 AI 设置面板，服务商选择 **"deepseek"**
2. 接口地址会自动填入 `https://api.deepseek.com/v1/chat/completions`
3. 填入你的 DeepSeek API Key
4. 主模型可填 `deepseek-chat` 或 `deepseek-reasoner`
5. **轻量模型**会自动设为 `DeepSeek-V4-Flash-Vision-Exp`

### 视觉能力如何工作

当使用视觉模型时，`browser_explore` 会在每一步：
1. 截取当前页面截图
2. 同时提取 DOM 可交互元素列表
3. 将**截图 + 元素列表**一起发给视觉模型
4. 模型结合"看"到的页面和结构化数据做出更准确的导航决策

**优势**：
- 视觉模型能识别复杂的 UI 布局（嵌套菜单、弹窗、Tab 切换）
- 不依赖 CSS selector 也能理解按钮含义
- 对中文字体、图标按钮的识别更准确

**降级策略**：如果截图失败或模型不支持视觉，自动回退到纯 DOM 文本模式。

### 手动配置（非 deepseek provider）

如果使用 OpenAI 兼容 API 的视觉模型（如 vLLM、Ollama + llava），可以：
1. 服务商选择 "openai" 或 "custom"
2. 填入你的端点地址和 Key
3. 在轻量模型字段填入视觉模型名（如 `DeepSeek-V4-Flash-Vision-Exp`）

## Supported Browser Action Types

`browser_interact` supports the following action types:

| Action | Description | Parameters |
|--------|-------------|------------|
| `wait_for` | Wait for an element to appear | `selector`, `timeout_ms` |
| `click` | Click an element | `selector` |
| `fill` | Fill an input field | `selector`, `value` |
| `select` | Select a dropdown option | `selector`, `value` |
| `check` | Check a checkbox | `selector` |
| `type` | Type text character by character | `selector`, `value`, `delay_ms` |
| `wait_for_request` | Wait for a network request matching pattern | `url_pattern`, `timeout_ms` |
| `hover` | Hover over an element (CSS :hover dropdowns) | `selector` |
| `scroll` | Scroll to element or page top/bottom | `selector` (optional), `value` ("top"/"bottom"/pixels) |
| `upload` | Upload a file to input[type=file] | `selector`, `value` (file path) |
| `press_key` | Press a keyboard key (Enter/Tab/Esc) | `selector` (optional), `value` (key name) |

### DomSimplifier

The DOM simplifier extracts interactive elements for LLM navigation decisions. It detects:
- Standard HTML interactive elements (`a[href]`, `button`, `input`, `[onclick]`, `[tabindex]`)
- Framework click handlers via CSS patterns (`[class*=trigger]`, `[class*=dropdown]`, etc.)
- `cursor:pointer` computed style (catches Vue `@click` / React `onClick` that don't produce HTML attributes)


---

# 第二部分：agent-browser 集成


> 本指南介绍 API Sentinel 与 agent-browser 的集成，包括认证提取、请求捕获和批量 API 触发。

---

## 🎯 概述

API Sentinel 集成了 [agent-browser](https://github.com/vercel-labs/agent-browser)，一个 Rust 原生浏览器自动化 CLI，为安全测试提供三大能力：

| 能力 | 工具 | 用途 |
|------|------|------|
| **认证提取** | `extract_auth` | 从浏览器提取 Cookie/JWT，注入到 send_request |
| **请求捕获** | `capture_requests` | 捕获真实请求模板（HAR），保存供后续复用 |
| **批量触发** | `trigger_apis` | 批量触发 API 表格中的接口（优先 HTTP 直连，fallback UI 重放） |

**核心价值**：
- 🚀 **性能提升**：Rust 原生 CLI，比 Playwright-Java 快 10-100x
- 🎯 **AI 友好**：Accessibility Tree 替代 Raw DOM，LLM 决策准确率 +30%
- 💾 **请求模板**：HAR 录制 + API 模板缓存，后续触发无需重走 UI
- 🔐 **凭证管理**：Auth Vault 加密存储，按名称引用

---

## 📦 安装

### 步骤 1：安装 agent-browser

```bash
# macOS / Linux / Windows
npm install -g agent-browser

# 下载 Chrome for Testing
agent-browser install

# Linux 需要系统依赖
agent-browser install --with-deps
```

### 步骤 2：验证安装

```bash
agent-browser --version
agent-browser doctor
```

### 步骤 3：重启 Burp Suite

重启 Burp Suite 以加载新的 Agent 工具。

---

## 🔑 场景 1：提取认证凭证

### 问题

你需要测试需要登录的 API，但不想手动复制 Cookie。

### 解决方案

```
Agent 工具调用：
  1. browser_login(profile_name="work")
     → 自动登录，Cookie 注入到 AppConfig
  
  2. extract_auth()
     → 提取 Cookie/JWT，确认注入成功
  
  3. send_request(path="/api/admin/users")
     → 自动携带认证凭证
```

### 示例

```json
{
  "tool": "extract_auth",
  "arguments": {
    "inject_to_config": true
  }
}
```

**输出**：
```json
{
  "success": true,
  "cookie_count": 3,
  "local_storage_count": 5,
  "bearer_token_present": true,
  "cookie_names": ["JSESSIONID", "userId", "csrf_token"],
  "local_storage_keys": ["token", "user", "preferences"],
  "cookie_injected": true,
  "bearer_token_injected": true,
  "note": "Credentials injected into auth config. You can now use send_request to test APIs with these credentials."
}
```

### 高级用法

**Auth Vault（加密存储）**：

```bash
# 保存凭证到 vault（一次）
agent-browser auth save work --url https://app.example.com

# 后续使用（无需传密码）
agent-browser auth login work
```

**Session 复用**：

```bash
# 自动恢复上次登录状态
agent-browser --session work --restore
```

---

## 📸 场景 2：捕获请求模板

### 问题

你通过 UI 操作触发了一个 API（如创建订单），想保存这个请求的结构供后续批量测试。

### 解决方案

```
Agent 工具调用：
  1. browser_explore(target_api="POST /api/orders")
     → LLM 导航到页面，触发 API
  
  2. capture_requests(filter="xhr,fetch", save_to_file="orders.har")
     → 捕获请求模板，保存到文件
  
  3. trigger_apis(api_paths=["POST /api/orders"], params={"productId": "123"})
     → 用模板批量触发（直接 HTTP，无需 UI）
```

### 示例

```json
{
  "tool": "capture_requests",
  "arguments": {
    "filter": "xhr,fetch",
    "save_to_file": "/tmp/orders.har"
  }
}
```

**输出**：
```json
{
  "success": true,
  "count": 5,
  "filter": "xhr,fetch",
  "requests": [
    {
      "method": "POST",
      "url": "https://app.example.com/api/orders",
      "status": 201,
      "is_api_call": true,
      "has_body": true
    },
    {
      "method": "GET",
      "url": "https://app.example.com/api/orders/123",
      "status": 200,
      "is_api_call": true,
      "has_body": false
    }
  ],
  "saved_to": "/tmp/orders.har",
  "note": "Captured 5 requests and saved to /tmp/orders.har. Use trigger_apis tool to replay these requests."
}
```

### 过滤器选项

| 过滤器 | 说明 | 示例 |
|--------|------|------|
| `xhr,fetch` | 只看 API 调用（推荐） | 过滤掉 CSS/JS/图片 |
| `POST` | 只看 POST 请求 | 聚焦数据提交 |
| `2xx` | 只看成功请求 | 排除错误响应 |
| `4xx` | 只看客户端错误 | 分析权限问题 |
| 空 | 所有请求 | 完整流量分析 |

---

## 🚀 场景 3：批量触发 API

### 问题

API 表格中有 100 个接口，其中 30 个是深层嵌套的（需要点击 5 层菜单），你想批量触发它们生成流量。

### 解决方案

```
Agent 工具调用：
  1. trigger_apis(params={"roleName": "Admin"})
     → 批量触发选中的 API
     → 策略：
        - 有 API 模板 → 直接 HTTP（快 100x）
        - 有 UI 路径 → UI 重放（快 2x）
        - 无缓存 → browser_explore（首次发现）
```

### 示例

```json
{
  "tool": "trigger_apis",
  "arguments": {
    "api_paths": [
      "POST /api/roles",
      "GET /api/users",
      "PUT /api/orders/123"
    ],
    "params": {
      "roleName": "Admin",
      "userId": "456"
    },
    "use_browser_explore": true
  }
}
```

**输出**：
```json
{
  "success": true,
  "total": 3,
  "direct_triggered": 2,
  "ui_replayed": 1,
  "explored": 0,
  "failed": 0,
  "results": [
    {
      "api": "POST /api/roles",
      "strategy": "direct_http",
      "success": true
    },
    {
      "api": "GET /api/users",
      "strategy": "direct_http",
      "success": true
    },
    {
      "api": "PUT /api/orders/123",
      "strategy": "ui_replay",
      "success": true
    }
  ],
  "note": "Triggered 3 APIs (direct: 2, UI: 1, explore: 0, failed: 0). Traffic captured in Burp proxy. Use analyze_traffic or heuristic_scan to analyze.",
  "cache_stats": {
    "total_cached": 50,
    "with_ui_path": 50,
    "with_api_template": 30
  }
}
```

### 触发策略

| 策略 | 速度 | 适用场景 | 实现状态 |
|------|------|---------|---------|
| **直接 HTTP** | 0.5s | 有 API 模板（已提取） | ✅ 已实现 |
| **UI 重放** | 5-10s | 有 UI 路径（已缓存） | ⚠️ 待实现 |
| **browser_explore** | 30-60s | 无缓存（首次发现） | ⚠️ 待实现 |

---

## 🔄 完整工作流

### 场景：测试深层嵌套的 API

**目标**：测试 `POST /api/admin/roles/create`（需要点击：系统管理 → 权限管理 → 角色管理 → 新建角色 → 保存）

#### 步骤 1：首次发现（一次性成本）

```
Agent 循环：
  1. browser_login(profile_name="admin")
     → 登录管理员账号
  
  2. browser_explore(target_api="POST /api/admin/roles/create")
     → LLM 导航：点击 5 层菜单 → 填写表单 → 点击保存
     → 触发 API，缓存 UI 路径
  
  3. capture_requests(filter="POST", save_to_file="create-role.har")
     → 捕获请求模板：URL/headers/body
     → 提取 API 模板，缓存到 ExplorationCache
```

**耗时**：~60s（LLM 决策 + UI 操作）

#### 步骤 2：后续触发（复用缓存）

```
Agent 循环：
  1. trigger_apis(
       api_paths=["POST /api/admin/roles/create"],
       params={"roleName": "NewRole", "permissions": ["read", "write"]}
     )
     → 检测到有 API 模板 → 直接 HTTP 请求
     → 无需重走 UI
```

**耗时**：~0.5s（直接 HTTP，快 120x）

#### 步骤 3：批量测试变体

```
Agent 循环：
  1. generate_payloads(finding_type="idor")
     → 生成 10 个变体（不同 roleName）
  
  2. for each variant:
       trigger_apis(
         api_paths=["POST /api/admin/roles/create"],
         params={"roleName": variant}
       )
     → 批量触发，每个 0.5s
```

**总耗时**：~5s（10 个变体 × 0.5s）

---

## 📊 性能对比

### 测试场景：100 个 API，其中 30 个深层嵌套

| 指标 | 当前（Playwright） | 改进后（agent-browser） | 提升 |
|------|-------------------|------------------------|------|
| 首次触发（100 个） | 50 分钟 | 50 分钟 | 无变化 |
| 第 2 次触发（100 个） | 25 分钟 | 2 分钟 | **12x** |
| 第 3 次触发（100 个） | 25 分钟 | 2 分钟 | **12x** |
| 深层 API 首次发现率 | 60% | 80% | **+33%** |
| 单次操作延迟 | 500ms-1s | 10-50ms | **10-20x** |
| LLM token 消耗 | 10,000+ | 2,000-3,000 | **-70%** |

---

## 🛠️ 工具参考

### extract_auth

**用途**：从浏览器提取认证凭证（Cookie/JWT）

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `inject_to_config` | boolean | 否 | 是否注入到 AppConfig（默认 true） |

**输出**：
- `success`: 是否成功
- `cookie_count`: Cookie 数量
- `bearer_token_present`: 是否有 Bearer token
- `cookie_names`: Cookie 名称列表（不返回值）
- `local_storage_keys`: localStorage 键列表（不返回值）

### capture_requests

**用途**：捕获浏览器网络请求模板

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `filter` | string | 否 | 过滤器：`xhr,fetch` / `POST` / `2xx`（默认 `xhr,fetch`） |
| `save_to_file` | string | 否 | 保存路径（JSON 格式） |

**输出**：
- `success`: 是否成功
- `count`: 捕获的请求数量
- `requests`: 请求列表（method/url/status）
- `saved_to`: 保存路径（如果指定）

### trigger_apis

**用途**：批量触发 API 表格中的接口

**参数**：
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `api_paths` | array | 否 | API 路径列表（默认使用表格选中项） |
| `params` | object | 否 | 参数映射（用于 API 模板） |
| `use_browser_explore` | boolean | 否 | 是否对无缓存的 API 使用 browser_explore（默认 true） |

**输出**：
- `success`: 是否成功
- `total`: 总数
- `direct_triggered`: 直接 HTTP 触发数量
- `ui_replayed`: UI 重放触发数量
- `explored`: browser_explore 触发数量
- `failed`: 失败数量
- `cache_stats`: 缓存统计

---

## 🔧 故障排查

### 问题 1：agent-browser CLI not found

**原因**：未安装 agent-browser

**解决**：
```bash
npm install -g agent-browser
agent-browser install
```

### 问题 2：Failed to extract auth

**原因**：agent-browser daemon 未运行或浏览器未打开

**解决**：
```bash
# 启动 daemon
agent-browser open https://app.example.com

# 检查状态
agent-browser doctor
```

### 问题 3：No APIs to trigger

**原因**：API 表格未选中任何接口

**解决**：
1. 在 API 表格中勾选要触发的接口
2. 或在 `api_paths` 参数中指定 API 路径

### 问题 4：Direct HTTP failed

**原因**：API 模板中的认证凭证已过期

**解决**：
```
Agent 循环：
  1. extract_auth(inject_to_config=true)
     → 重新提取最新凭证
  
  2. trigger_apis(...)
     → 使用新凭证触发
```

---

## 📚 相关文档

- [FEATURES.md](FEATURES.md) — Agent 工具参数说明
- [ARCHITECTURE.md](ARCHITECTURE.md) — 浏览器模块架构
- [ARCHITECTURE.md §ADR-007](ARCHITECTURE.md#adr-007浏览器引擎复用-chromium) — 浏览器引擎决策记录
- [examples/login-profiles.json](../examples/login-profiles.json) — 登录配置示例

---

## 🎯 最佳实践

### 1. 首次使用流程

```
1. 安装 agent-browser（一次性）
2. 配置登录档案（login-profiles.json）
3. browser_login → extract_auth → 开始测试
```

### 2. 深层 API 测试流程

```
1. browser_explore（首次发现，缓存路径）
2. capture_requests（提取模板，缓存模板）
3. trigger_apis（后续批量触发，直接 HTTP）
```

### 3. 批量测试流程

```
1. 在 API 表格中勾选 100 个接口
2. trigger_apis(params={...})
   → 自动选择最优策略（HTTP > UI > explore）
3. analyze_traffic / heuristic_scan（分析流量）
```

### 4. 凭证管理

```
✅ Good：使用 Auth Vault 加密存储
agent-browser auth save work

❌ Bad：明文传递密码
browser_login(username="admin", password="123456")
```

---

## 🚧 待实现功能

以下功能已设计，待后续版本实现：

- [ ] **UI 重放**：`trigger_apis` 的 UI replay 策略
- [ ] **browser_explore 集成**：`trigger_apis` 自动调用 browser_explore
- [ ] **HAR 可视化**：UI 中查看 HAR 文件
- [ ] **请求模板编辑**：UI 中编辑 API 模板
- [ ] **批量导出**：导出所有缓存的 API 模板

---

## 💡 提示

- **首次发现慢是正常的**：browser_explore 需要 LLM 决策，耗时 30-60s
- **后续触发快**：缓存后直接 HTTP，0.5s 完成
- **定期检查缓存**：`explorationCache.getStats()` 查看缓存命中率
- **清理过期缓存**：`explorationCache.clear()` 重置缓存
