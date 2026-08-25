package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.importer.SwaggerImporter;
import com.flechazo.apisentinel.util.UrlUtils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

/**
 * Modal dialog for batch API import.
 * Supports plain-text import and Swagger/OpenAPI file import.
 */
public class ImportDialog extends JDialog {

    private final BurpTheme theme;
    private final JTextArea textArea;
    private final JCheckBox urlEncodeCb;
    private final JCheckBox scanHistoryCb;
    private final Runnable onScanHistory;

    public ImportDialog(Window owner, Consumer<String> onImport, Runnable onScanHistory, BurpTheme theme) {
        super(owner, "批量导入 API", ModalityType.APPLICATION_MODAL);
        this.theme = theme;
        this.onScanHistory = onScanHistory;
        setSize(740, 460);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(8, 0));
        getRootPane().setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Left: text area
        textArea = new JTextArea();
        textArea.setFont(theme.editorFont(12f));
        textArea.setLineWrap(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("API 列表（每行一个）"));
        add(scrollPane, BorderLayout.CENTER);

        // Right: hints + options + file import buttons
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setPreferredSize(new Dimension(220, 0));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 4));

        JLabel title = new JLabel("API Sentinel v" + com.flechazo.apisentinel.ApiSentinelExtension.VERSION);
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        title.setAlignmentX(LEFT_ALIGNMENT);
        rightPanel.add(title);
        rightPanel.add(Box.createVerticalStrut(12));

        String[] hints = {
            "导入格式（每行一个）:",
            "GET /api/v1/users",
            "POST /api/v1/login",
            "/api/v1/orders/{id}",
            "/api/v1/admin/**",
            "",
            "支持带/不带 HTTP 方法",
            "支持 {id} 路径占位符",
            "支持 /** 匹配所有子路径",
            "重复的 API 会自动跳过"
        };
        for (String h : hints) {
            JLabel l = new JLabel(h);
            l.setFont(theme.editorFont(11f));
            l.setAlignmentX(LEFT_ALIGNMENT);
            rightPanel.add(l);
            rightPanel.add(Box.createVerticalStrut(2));
        }

        rightPanel.add(Box.createVerticalStrut(12));

        // --- Import options ---
        JLabel optLabel = new JLabel("导入选项:");
        optLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        optLabel.setAlignmentX(LEFT_ALIGNMENT);
        rightPanel.add(optLabel);
        rightPanel.add(Box.createVerticalStrut(4));

        urlEncodeCb = new JCheckBox("URL 编码路径");
        urlEncodeCb.setFont(theme.displayFont(Font.PLAIN, 11f));
        urlEncodeCb.setAlignmentX(LEFT_ALIGNMENT);
        urlEncodeCb.setToolTipText("将路径中的 / 编码为 %2F，用于匹配部分系统中被编码的路径流量");
        rightPanel.add(urlEncodeCb);
        rightPanel.add(Box.createVerticalStrut(4));

        scanHistoryCb = new JCheckBox("导入后扫描历史流量");
        scanHistoryCb.setFont(theme.displayFont(Font.PLAIN, 11f));
        scanHistoryCb.setAlignmentX(LEFT_ALIGNMENT);
        scanHistoryCb.setSelected(true);  // 默认开启
        scanHistoryCb.setToolTipText("导入完成后自动扫描 Burp Proxy History，为已出现过的接口补充匹配信息");
        rightPanel.add(scanHistoryCb);

        rightPanel.add(Box.createVerticalStrut(12));

        // --- File import buttons ---
        JLabel fileLabel = new JLabel("从文件导入:");
        fileLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        fileLabel.setAlignmentX(LEFT_ALIGNMENT);
        rightPanel.add(fileLabel);
        rightPanel.add(Box.createVerticalStrut(6));

        // Plain text labels, not emoji — emoji glyphs render at inconsistent
        // sizes/baselines across OS fonts and can show as missing-glyph boxes
        // on Linux, unlike the rest of this app's buttons (all plain text).
        JButton txtFileBtn = new JButton("文本文件 (.txt)");
        txtFileBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        txtFileBtn.setAlignmentX(LEFT_ALIGNMENT);
        txtFileBtn.setMaximumSize(new Dimension(200, 28));
        txtFileBtn.addActionListener(e -> importFromTextFile());
        rightPanel.add(txtFileBtn);
        rightPanel.add(Box.createVerticalStrut(4));

        JButton swaggerBtn = new JButton("Swagger / OpenAPI");
        swaggerBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        swaggerBtn.setAlignmentX(LEFT_ALIGNMENT);
        swaggerBtn.setMaximumSize(new Dimension(200, 28));
        swaggerBtn.setForeground(theme.statusOk());
        swaggerBtn.addActionListener(e -> importFromSwagger());
        rightPanel.add(swaggerBtn);

        rightPanel.add(Box.createVerticalGlue());
        add(rightPanel, BorderLayout.EAST);

        // Bottom: buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton importBtn = new JButton(I18n.get("import_api"));
        importBtn.setFont(theme.displayFont(Font.BOLD, 12f));
        importBtn.addActionListener(e -> {
            String text = textArea.getText();
            if (text != null && !text.isBlank()) {
                if (urlEncodeCb.isSelected()) {
                    text = applyUrlEncode(text);
                }
                onImport.accept(text);

                // Trigger history scan after import if checked
                if (scanHistoryCb.isSelected() && onScanHistory != null) {
                    onScanHistory.run();
                }
            }
            dispose();
        });

        JButton cancelBtn = new JButton("取消");
        cancelBtn.setFont(theme.displayFont(Font.PLAIN, 12f));
        cancelBtn.addActionListener(e -> dispose());

        buttonPanel.add(importBtn);
        buttonPanel.add(cancelBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        // ESC cancels; apply Burp's L&F to the whole dialog surface.
        getRootPane().registerKeyboardAction(e -> dispose(),
                javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        theme.apply(this);
    }

    /**
     * URL-encode the path portion of each line.
     * "GET /api/v1/users" → "GET %2Fapi%2Fv1%2Fusers"
     */
    private String applyUrlEncode(String text) {
        StringBuilder sb = new StringBuilder();
        for (String line : text.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                sb.append(line).append("\n");
                continue;
            }
            // Preserve inline comments
            String comment = "";
            if (trimmed.contains("  #")) {
                int commentIdx = trimmed.indexOf("  #");
                comment = trimmed.substring(commentIdx);
                trimmed = trimmed.substring(0, commentIdx).trim();
            }
            // Split method and path
            String[] parts = trimmed.split("\\s+", 2);
            if (parts.length == 2 && isHttpMethod(parts[0].toUpperCase())) {
                sb.append(parts[0]).append(" ").append(UrlUtils.urlEncode(parts[1].trim()));
            } else {
                sb.append(UrlUtils.urlEncode(trimmed));
            }
            if (!comment.isEmpty()) sb.append(comment);
            sb.append("\n");
        }
        return sb.toString();
    }

    private static boolean isHttpMethod(String m) {
        return switch (m) {
            case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" -> true;
            default -> false;
        };
    }

    /**
     * Import API list from a plain text file.
     */
    private void importFromTextFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择 API 列表文件");
        chooser.setFileFilter(new FileNameExtensionFilter("文本文件 (*.txt)", "txt"));
        chooser.addChoosableFileFilter(new FileNameExtensionFilter("所有支持的格式", "txt", "csv"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String content = Files.readString(chooser.getSelectedFile().toPath());
                textArea.setText(content);
                textArea.setCaretPosition(0);
            } catch (IOException ex) {
                ThemedDialogs.error(this, "读取文件失败: " + ex.getMessage(), "错误");
            }
        }
    }

    /**
     * Import API endpoints from a Swagger/OpenAPI document.
     */
    private void importFromSwagger() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择 Swagger / OpenAPI 文件");
        chooser.setFileFilter(new FileNameExtensionFilter(
            "Swagger/OpenAPI (*.json, *.yaml, *.yml)", "json", "yaml", "yml"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Path file = chooser.getSelectedFile().toPath();
                List<SwaggerImporter.ApiEndpoint> endpoints = SwaggerImporter.parseFile(file);

                if (endpoints.isEmpty()) {
                    ThemedDialogs.warn(this,
                        "未在文件中找到任何 API 端点。\n请确认这是有效的 Swagger 2.0 或 OpenAPI 3.0 文档。",
                        "解析结果");
                    return;
                }

                // Build text representation for the textArea
                StringBuilder sb = new StringBuilder();
                sb.append("# Imported from: ").append(file.getFileName()).append("\n");
                sb.append("# Found ").append(endpoints.size()).append(" endpoints\n\n");
                for (SwaggerImporter.ApiEndpoint ep : endpoints) {
                    sb.append(ep.method()).append(" ").append(ep.path());
                    if (ep.summary() != null && !ep.summary().isEmpty()) {
                        sb.append("  # ").append(ep.summary());
                    }
                    sb.append("\n");
                }

                textArea.setText(sb.toString());
                textArea.setCaretPosition(0);

                ThemedDialogs.info(this,
                    String.format("已解析 %d 个 API 端点，请确认后点击「导入」按钮。",
                        endpoints.size()),
                    "Swagger 导入");

            } catch (Exception ex) {
                ThemedDialogs.error(this, "解析 Swagger 文件失败: " + ex.getMessage(), "错误");
            }
        }
    }
}
