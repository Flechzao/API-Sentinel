package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.ConfigManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

/**
 * Browser automation configuration panel.
 * Moved from AiSettingsPanel to Advanced settings tab for better organization.
 */
public class BrowserConfigPanel extends JPanel {

    private final JCheckBox browserEnabledCheck;
    private final JCheckBox browserHeadlessCheck;
    private final JTextField browserChromePathField;
    private final JTextField browserMaxPagesField;
    private final JTextField browserFrontendUrlField;
    private final JLabel statusLabel;

    private BrowserConfigCallback onBrowserConfigChanged;

    /** Callback for browser configuration changes. */
    @FunctionalInterface
    public interface BrowserConfigCallback {
        void onBrowserConfigChanged(boolean enabled, boolean headless, String chromePath,
                                    int maxPages, String frontendUrl);
    }

    public BrowserConfigPanel(BurpTheme theme) {
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        // Title
        JLabel title = new JLabel(I18n.get("ai_settings_browser_capabilities"));
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(title, gbc);
        row++;

        // Browser enabled
        browserEnabledCheck = new JCheckBox(I18n.get("ai_settings_browser_enabled"));
        browserEnabledCheck.setToolTipText(I18n.get("ai_settings_browser_enabled_tooltip"));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(browserEnabledCheck, gbc);
        row++;

        // Headless mode
        browserHeadlessCheck = new JCheckBox(I18n.get("ai_settings_browser_headless"));
        browserHeadlessCheck.setSelected(true);
        browserHeadlessCheck.setToolTipText(I18n.get("ai_settings_browser_headless_tooltip"));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(browserHeadlessCheck, gbc);
        row++;

        // Chrome path
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_chrome_path")), gbc);
        browserChromePathField = new JTextField("", 30);
        browserChromePathField.setToolTipText(I18n.get("ai_settings_chrome_path_tooltip"));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(browserChromePathField, gbc);
        row++;

        // Browser detection helper buttons
        JPanel browserBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        browserBtnPanel.setOpaque(false);

        JButton detectChromeBtn = new JButton("检测本地浏览器");
        detectChromeBtn.setToolTipText("自动检测系统 Chrome/Edge/Chromium 并填入路径");
        detectChromeBtn.addActionListener(e -> {
            String detected = detectSystemBrowserForUI();
            if (detected != null) {
                browserChromePathField.setText(detected);
                JOptionPane.showMessageDialog(this,
                        "检测到: " + detected,
                        "浏览器检测成功",
                        JOptionPane.INFORMATION_MESSAGE);
                notifyConfigChanged();
            } else {
                JOptionPane.showMessageDialog(this,
                        "未在标准位置检测到 Chrome/Edge/Chromium。\n"
                        + "您可以手动输入路径或安装 Playwright Chromium。",
                        "未检测到浏览器",
                        JOptionPane.WARNING_MESSAGE);
            }
        });
        browserBtnPanel.add(detectChromeBtn);

        JButton installPlaywrightBtn = new JButton("安装 Playwright Chromium");
        installPlaywrightBtn.setToolTipText("运行: npx playwright install chromium（需要 Node.js）");
        installPlaywrightBtn.addActionListener(e -> {
            // Check if already installed
            String existingPath = detectPlaywrightChromiumForUI();
            if (existingPath != null) {
                browserChromePathField.setText(existingPath);
                notifyConfigChanged();
                JOptionPane.showMessageDialog(this,
                        "已检测到并填入 Playwright Chromium 路径:\n" + existingPath,
                        "设置完成",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // Not installed, proceed with installation
            int choice = JOptionPane.showConfirmDialog(this,
                    "将执行命令:\nnpx playwright install chromium\n\n"
                    + "需要已安装 Node.js/npm。\n"
                    + "将安装到 ~/Library/Caches/ms-playwright/（约 150MB）。\n\n"
                    + "继续安装？",
                    "安装 Playwright Chromium",
                    JOptionPane.YES_NO_OPTION);
            if (choice == JOptionPane.YES_OPTION) {
                new Thread(() -> {
                    try {
                        ProcessBuilder pb = new ProcessBuilder("npx", "playwright", "install", "chromium");
                        pb.redirectErrorStream(true);
                        Process proc = pb.start();
                        java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.InputStreamReader(proc.getInputStream()));
                        StringBuilder output = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            output.append(line).append("\n");
                        }
                        int exitCode = proc.waitFor();
                        SwingUtilities.invokeLater(() -> {
                            if (exitCode == 0) {
                                JOptionPane.showMessageDialog(this,
                                        "安装完成。\nPlaywright Chromium 已安装到 ~/Library/Caches/ms-playwright/\n\n"
                                        + "已自动填入路径，可以使用浏览器功能。",
                                        "安装成功",
                                        JOptionPane.INFORMATION_MESSAGE);
                                String newPath = detectPlaywrightChromiumForUI();
                                if (newPath != null) {
                                    browserChromePathField.setText(newPath);
                                } else {
                                    browserChromePathField.setText("");
                                }
                                notifyConfigChanged();
                            } else {
                                JOptionPane.showMessageDialog(this,
                                        "安装失败（退出码: " + exitCode + "）\n\n"
                                        + output.toString() + "\n\n"
                                        + "请手动执行: npx playwright install chromium",
                                        "安装失败",
                                        JOptionPane.ERROR_MESSAGE);
                            }
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(this,
                                    "执行命令失败: " + ex.getMessage() + "\n\n"
                                    + "请手动执行: npx playwright install chromium",
                                    "错误",
                                    JOptionPane.ERROR_MESSAGE);
                        });
                    }
                }, "PlaywrightInstaller").start();
            }
        });
        browserBtnPanel.add(installPlaywrightBtn);

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(browserBtnPanel, gbc);
        row++;

        // Max pages
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_max_pages")), gbc);
        browserMaxPagesField = new JTextField("10", 5);
        browserMaxPagesField.setToolTipText(I18n.get("ai_settings_max_pages_tooltip"));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(browserMaxPagesField, gbc);
        row++;

        // Frontend base URL
        gbc.gridwidth = 1; gbc.weightx = 0;
        gbc.gridx = 0; gbc.gridy = row;
        add(new JLabel(I18n.get("ai_settings_frontend_base_url")), gbc);
        browserFrontendUrlField = new JTextField("", 30);
        browserFrontendUrlField.setToolTipText(I18n.get("ai_settings_frontend_base_url_tooltip"));
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
        add(browserFrontendUrlField, gbc);
        row++;

        // Auto-save on checkbox toggle
        browserEnabledCheck.addActionListener(e -> notifyConfigChanged());

        // Status label
        statusLabel = new JLabel(" ");
        statusLabel.setFont(theme.displayFont(Font.ITALIC, 12f));
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        add(statusLabel, gbc);
        row++;

        // Spacer
        gbc.gridy = row; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        add(new JLabel(), gbc);

        // Language listener
        I18n.addLangListener(lang -> SwingUtilities.invokeLater(() -> {
            if (browserEnabledCheck != null) {
                browserEnabledCheck.setText(I18n.get("ai_settings_browser_enabled"));
                browserEnabledCheck.setToolTipText(I18n.get("ai_settings_browser_enabled_tooltip"));
            }
            if (browserHeadlessCheck != null) {
                browserHeadlessCheck.setText(I18n.get("ai_settings_browser_headless"));
                browserHeadlessCheck.setToolTipText(I18n.get("ai_settings_browser_headless_tooltip"));
            }
        }));
    }

    private void notifyConfigChanged() {
        if (onBrowserConfigChanged != null) {
            onBrowserConfigChanged.onBrowserConfigChanged(
                    isBrowserEnabled(), isBrowserHeadless(),
                    getBrowserChromePath(), getBrowserMaxPages(), getBrowserFrontendUrl());
        }
    }

    public void setOnBrowserConfigChanged(BrowserConfigCallback callback) {
        this.onBrowserConfigChanged = callback;
    }

    public boolean isBrowserEnabled() { return browserEnabledCheck.isSelected(); }
    public boolean isBrowserHeadless() { return browserHeadlessCheck.isSelected(); }
    public String getBrowserChromePath() { return browserChromePathField.getText().trim(); }
    public String getBrowserFrontendUrl() { return browserFrontendUrlField.getText().trim(); }
    public int getBrowserMaxPages() {
        try { return Math.max(1, Math.min(50, Integer.parseInt(browserMaxPagesField.getText().trim()))); }
        catch (NumberFormatException e) { return 10; }
    }

    public void setBrowserConfig(boolean enabled, boolean headless, String chromePath, int maxPages) {
        setBrowserConfig(enabled, headless, chromePath, maxPages, "");
    }

    public void setBrowserConfig(boolean enabled, boolean headless, String chromePath,
                                  int maxPages, String frontendUrl) {
        browserEnabledCheck.setSelected(enabled);
        browserHeadlessCheck.setSelected(headless);
        browserChromePathField.setText(chromePath != null ? chromePath : "");
        browserMaxPagesField.setText(String.valueOf(maxPages > 0 ? maxPages : 10));
        browserFrontendUrlField.setText(frontendUrl != null ? frontendUrl : "");
    }

    private String detectSystemBrowserForUI() {
        String os = System.getProperty("os.name").toLowerCase();
        String[] candidates;

        if (os.contains("mac")) {
            candidates = new String[]{
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    "/Applications/Chromium.app/Contents/MacOS/Chromium",
                    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
            };
        } else if (os.contains("windows")) {
            String programFiles = System.getenv("ProgramFiles");
            String programFilesX86 = System.getenv("ProgramFiles(x86)");
            String localAppData = System.getenv("LOCALAPPDATA");
            candidates = new String[]{
                    programFiles + "\\Google\\Chrome\\Application\\chrome.exe",
                    programFilesX86 + "\\Google\\Chrome\\Application\\chrome.exe",
                    programFiles + "\\Microsoft\\Edge\\Application\\msedge.exe",
                    programFilesX86 + "\\Microsoft\\Edge\\Application\\msedge.exe",
                    localAppData + "\\Google\\Chrome\\Application\\chrome.exe"
            };
        } else {
            candidates = new String[]{
                    "/usr/bin/google-chrome",
                    "/usr/bin/google-chrome-stable",
                    "/usr/bin/chromium",
                    "/usr/bin/chromium-browser",
                    "/usr/bin/microsoft-edge",
                    "/usr/bin/microsoft-edge-stable",
                    "/snap/bin/chromium",
                    "/snap/bin/google-chrome"
            };
        }

        for (String path : candidates) {
            if (path != null && new File(path).exists()) {
                return path;
            }
        }
        return null;
    }

    private String detectPlaywrightChromiumForUI() {
        String os = System.getProperty("os.name").toLowerCase();
        Path[] cacheDirs;
        if (os.contains("mac")) {
            cacheDirs = new Path[]{
                Paths.get(System.getProperty("user.home"), ".cache", "ms-playwright"),
                Paths.get(System.getProperty("user.home"), "Library", "Caches", "ms-playwright")
            };
        } else {
            cacheDirs = new Path[]{
                Paths.get(System.getProperty("user.home"), ".cache", "ms-playwright")
            };
        }

        for (Path cacheDir : cacheDirs) {
            if (!Files.isDirectory(cacheDir)) {
                continue;
            }
            try {
                String result = Files.list(cacheDir)
                        .filter(p -> p.getFileName().toString().startsWith("chromium-"))
                        .sorted((a, b) -> b.getFileName().toString().compareTo(a.getFileName().toString()))
                        .map(chromiumDir -> {
                            String execName;
                            if (os.contains("mac")) {
                                execName = "chrome-mac/Chromium.app/Contents/MacOS/Chromium";
                            } else if (os.contains("windows")) {
                                execName = "chrome-win\\chrome.exe";
                            } else {
                                execName = "chrome-linux/chrome";
                            }
                            Path execPath = chromiumDir.resolve(execName);
                            return Files.exists(execPath) ? execPath.toString() : null;
                        })
                        .filter(p -> p != null)
                        .findFirst()
                        .orElse(null);
                if (result != null) {
                    return result;
                }
            } catch (Exception e) {
                // Continue to next cache dir
            }
        }
        return null;
    }
}
