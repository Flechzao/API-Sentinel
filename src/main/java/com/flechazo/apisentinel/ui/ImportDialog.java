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
        super(owner, I18n.get("import_dialog_title"), ModalityType.APPLICATION_MODAL);
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
        scrollPane.setBorder(BorderFactory.createTitledBorder(I18n.get("import_list_border")));
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

        // Format hints (localized, keep example paths as-is)
        JLabel formatHeader = new JLabel(I18n.get("import_format_header"));
        formatHeader.setFont(theme.displayFont(Font.BOLD, 11f));
        formatHeader.setAlignmentX(LEFT_ALIGNMENT);
        rightPanel.add(formatHeader);
        rightPanel.add(Box.createVerticalStrut(2));

        String[] examples = {
            "GET /api/v1/users",
            "POST /api/v1/login",
            "/api/v1/orders/{id}",
            "/api/v1/admin/**",
            "GET /api/v1/users api.example.com"
        };
        for (String ex : examples) {
            JLabel l = new JLabel(ex);
            l.setFont(theme.editorFont(11f));
            l.setAlignmentX(LEFT_ALIGNMENT);
            rightPanel.add(l);
            rightPanel.add(Box.createVerticalStrut(2));
        }
        rightPanel.add(Box.createVerticalStrut(6));

        String[] hints = {
            I18n.get("import_format_no_method"),
            I18n.get("import_format_path_var"),
            I18n.get("import_format_wildcard"),
            I18n.get("import_format_domain"),
            I18n.get("import_format_dedup")
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
        JLabel optLabel = new JLabel(I18n.get("import_options_label"));
        optLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        optLabel.setAlignmentX(LEFT_ALIGNMENT);
        rightPanel.add(optLabel);
        rightPanel.add(Box.createVerticalStrut(4));

        urlEncodeCb = new JCheckBox(I18n.get("import_url_encode"));
        urlEncodeCb.setFont(theme.displayFont(Font.PLAIN, 11f));
        urlEncodeCb.setAlignmentX(LEFT_ALIGNMENT);
        urlEncodeCb.setToolTipText(I18n.get("import_url_encode_tip"));
        rightPanel.add(urlEncodeCb);
        rightPanel.add(Box.createVerticalStrut(4));

        scanHistoryCb = new JCheckBox(I18n.get("import_scan_history"));
        scanHistoryCb.setFont(theme.displayFont(Font.PLAIN, 11f));
        scanHistoryCb.setAlignmentX(LEFT_ALIGNMENT);
        scanHistoryCb.setSelected(true);  // default on
        scanHistoryCb.setToolTipText(I18n.get("import_scan_history_tip"));
        rightPanel.add(scanHistoryCb);

        rightPanel.add(Box.createVerticalStrut(12));

        // --- File import buttons ---
        JLabel fileLabel = new JLabel(I18n.get("import_from_file"));
        fileLabel.setFont(theme.displayFont(Font.BOLD, 12f));
        fileLabel.setAlignmentX(LEFT_ALIGNMENT);
        rightPanel.add(fileLabel);
        rightPanel.add(Box.createVerticalStrut(6));

        // Plain text labels, not emoji — emoji glyphs render at inconsistent
        // sizes/baselines across OS fonts and can show as missing-glyph boxes
        // on Linux, unlike the rest of this app's buttons (all plain text).
        JButton txtFileBtn = new JButton(I18n.get("import_txt_btn"));
        txtFileBtn.setFont(theme.displayFont(Font.PLAIN, 11f));
        txtFileBtn.setAlignmentX(LEFT_ALIGNMENT);
        txtFileBtn.setMaximumSize(new Dimension(200, 28));
        txtFileBtn.addActionListener(e -> importFromTextFile());
        rightPanel.add(txtFileBtn);
        rightPanel.add(Box.createVerticalStrut(4));

        JButton swaggerBtn = new JButton(I18n.get("import_swagger_btn"));
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

        JButton cancelBtn = new JButton(I18n.get("import_cancel"));
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
        chooser.setDialogTitle(I18n.get("import_choose_txt"));
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.get("import_filter_txt"), "txt"));
        chooser.addChoosableFileFilter(new FileNameExtensionFilter(I18n.get("import_filter_all"), "txt", "csv"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String content = Files.readString(chooser.getSelectedFile().toPath());
                textArea.setText(content);
                textArea.setCaretPosition(0);
            } catch (IOException ex) {
                ThemedDialogs.error(this, I18n.get("import_read_err") + ex.getMessage(), I18n.get("import_err_title"));
            }
        }
    }

    /**
     * Import API endpoints from a Swagger/OpenAPI document.
     */
    private void importFromSwagger() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(I18n.get("import_choose_swagger"));
        chooser.setFileFilter(new FileNameExtensionFilter(
            I18n.get("import_filter_swagger"), "json", "yaml", "yml"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Path file = chooser.getSelectedFile().toPath();
                List<SwaggerImporter.ApiEndpoint> endpoints = SwaggerImporter.parseFile(file);

                if (endpoints.isEmpty()) {
                    ThemedDialogs.warn(this,
                        I18n.get("import_swagger_empty"),
                        I18n.get("import_swagger_empty_title"));
                    return;
                }

                // Build text representation for the textArea
                StringBuilder sb = new StringBuilder();
                sb.append(I18n.get("import_comment_from")).append(file.getFileName()).append("\n");
                sb.append(String.format(I18n.get("import_comment_found"), endpoints.size())).append("\n\n");
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
                    String.format(I18n.get("import_swagger_ok"), endpoints.size()),
                    I18n.get("import_swagger_ok_title"));

            } catch (Exception ex) {
                ThemedDialogs.error(this, I18n.get("import_swagger_err") + ex.getMessage(), I18n.get("import_err_title"));
            }
        }
    }
}
