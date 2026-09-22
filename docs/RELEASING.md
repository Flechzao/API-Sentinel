# 制品打包与发布

> API Sentinel 的发布制品**按平台分别构建**：每个 jar 只内嵌当前构建平台的 Playwright 驱动（约 43MB），用户按平台下载对应 jar，首次用浏览器功能时驱动自动提取，零配置。

---

## 为什么按平台分别构建

`build.gradle.kts` 的 shadowJar 打包时**只保留当前构建 OS 的 Playwright Node.js 驱动**，排除其它 4 个平台（`mac` / `mac-arm64` / `win32_x64` / `linux` / `linux-arm64`），把单 jar 从 ~140MB 压到 ~43MB。

代价：一个 jar 只服务一个平台——把非该平台的驱动塞给用户，浏览器功能（`browser_login` / `browser_explore` / `browser_auto_crawl`）会因找不到匹配驱动而失效（重定位 fat-jar 里 Playwright 默认查找不工作）。所以公共发布要出**多平台制品**，不能只出单个。

---

## 平台与制品对照

| 运行平台 | 制品文件名 | 构建环境 |
|---|---|---|
| macOS Apple Silicon | `API-Sentinel-<ver>-mac-arm64.jar` | macos-14 |
| macOS Intel | `API-Sentinel-<ver>-mac-x64.jar` | macos-13 |
| Windows x64 | `API-Sentinel-<ver>-win32-x64.jar` | windows-latest |
| Linux x64 | `API-Sentinel-<ver>-linux-x64.jar` | ubuntu-latest |

> Burp 用户主力是 Mac/Windows。若用户群无 Intel Mac，可只保留 `mac-arm64`。

---

## 本地单平台构建（开发自测）

```bash
# 需 JDK 17
./gradlew shadowJar
# 产物：dist/API-Sentinel-<version>.jar（仅含当前 OS 驱动）
```

本地构建的 jar **只适合同平台自测**，不要直接拿去发给其它平台用户。

---

## 多平台发布构建（GitHub Actions）

发布在外部 CI 完成：构建在 GitHub runner 上跑，制品直接落到 GitHub Release，**不经内部平台、不搬大文件**。

流程：

1. 改 `build.gradle.kts` 顶部 `version = "X.Y"` 为目标版本；
2. 更新 README 版本徽章 `version-X.Y`、CHANGELOG 对应版本段；
3. 提交；
4. 打 tag 并推送：`git tag vX.Y && git push origin vX.Y`；
5. GitHub Actions（`.github/workflows/release.yml`）矩阵在 4 个平台 runner 各跑 `./gradlew shadowJar`，重命名加平台后缀，汇总后创建 Release 并上传 4 个 jar。

CI 也能在 Actions 页手动触发（`workflow_dispatch`）做矩阵自测，不创建 Release。

### 依赖说明

- `libs/`（vendored Burp Montoya API）已在仓库内，CI checkout 即可离线编译该依赖；
- 其余依赖（Playwright / Gson / SnakeYAML / RSyntaxTextArea 等）从 Maven Central 拉，GitHub runner 有网。

---

## 切发版清单

- [ ] `build.gradle.kts` 的 `version` 已改为目标版本
- [ ] README 版本徽章已改（`version-X.Y`）
- [ ] CHANGELOG 有对应版本段
- [ ] `./gradlew test` 通过
- [ ] 打 tag `vX.Y` 推送 → CI 出 4 平台 jar → 自动建 Release

---

## 附：替代方案与取舍

| 方案 | 单 jar 体积 | 跨平台 | 适用 |
|---|---|---|---|
| **矩阵出多平台 jar**（默认/推荐） | ~43MB × 4 | 全覆盖 | 公共发布 |
| 单个通用 jar（注释掉 `exclude("driver/...")` 循环） | ~140MB | 全覆盖 | 不愿出多 jar |
| 驱动改运行时下载（不打包进 jar） | ~16MB | 全覆盖（首用需联网） | 需改构建+代码+文档，最省体积但破坏"零配置" |

若要出"无浏览器"精简 jar（不含 Playwright），需加一个 gradle 构建变体排除 `playwright` 依赖——当前未实现，可作为后续体积优化项。
