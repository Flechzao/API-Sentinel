package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;

/**
 * Mini-Repeater popup dialog for re-sending a confirmed/suspected
 * vulnerability's payload. Pre-fills the request from the original
 * PayloadResult, lets the user edit and re-send manually.
 */
class ReplayDialog extends JDialog {

    private final MontoyaApi api;
    private final BurpTheme theme;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JLabel statusLabel;
    private final JButton sendBtn;

    ReplayDialog(Window owner, MontoyaApi api, String findingTitle, String rawRequest, ApiEntry entry) {
        super(owner, "重放验证 — " + findingTitle, ModalityType.MODELESS);
        this.api = api;

        setSize(1000, 600);
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout(0, 0));

        BurpTheme theme = new BurpTheme(api);
        this.theme = theme;

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, theme.separator()));

        sendBtn = new JButton("发送");
        sendBtn.setFont(theme.displayFont(Font.BOLD, 13f));
        sendBtn.setFocusPainted(false);
        sendBtn.addActionListener(e -> sendRequest());
        toolbar.add(sendBtn);

        statusLabel = new JLabel("就绪");
        statusLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(statusLabel);

        add(toolbar, BorderLayout.NORTH);

        // Editors
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editorSplit.setResizeWeight(0.5);
        editorSplit.setDividerLocation(480);
        add(editorSplit, BorderLayout.CENTER);

        // Pre-fill request. Build it with the REAL target HttpService so the
        // editor's request actually carries a host/port/protocol — creating a
        // request with no service makes sendRequest() throw
        // "HTTP service cannot be null".
        HttpService defaultService = resolveService(entry, rawRequest != null ? rawRequest : "");
        if (rawRequest != null && !rawRequest.isEmpty()) {
            try {
                requestEditor.setRequest(HttpRequest.httpRequest(defaultService, rawRequest));
            } catch (Exception ex) {
                requestEditor.setRequest(HttpRequest.httpRequest(
                        HttpService.httpService("localhost", 443, true), rawRequest));
            }
        } else {
            // No captured request — build a template from the ApiEntry so the
            // editor has a valid HttpService and the user can edit + send
            // without hitting "HTTP service cannot be null".
            String template = buildTemplateRequest(entry);
            try {
                requestEditor.setRequest(HttpRequest.httpRequest(defaultService, template));
                statusLabel.setText("无原始请求 — 已从接口信息生成模板，请编辑后发送");
                statusLabel.setForeground(theme.riskMedium());
            } catch (Exception ex) {
                statusLabel.setText("无可用请求数据 — 请手动输入");
                statusLabel.setForeground(theme.riskMedium());
            }
        }

        theme.apply(this);
        // ESC closes the (modeless) dialog.
        getRootPane().registerKeyboardAction(e -> dispose(),
                javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    /**
     * Resolve the target HttpService for the replayed request.
     * Priority: entry.lastUrl (authoritative scheme+host+port) → entry.domain
     * (host:port, scheme inferred) → the request's Host header → localhost.
     */
    private static HttpService resolveService(ApiEntry entry, String rawRequest) {
        if (entry != null) {
            String url = entry.getLastUrl();
            if (url != null && !url.isBlank()) {
                try {
                    java.net.URI uri = java.net.URI.create(url.trim());
                    String host = uri.getHost();
                    if (host != null && !host.isBlank()) {
                        boolean https = !"http".equalsIgnoreCase(uri.getScheme());
                        int port = uri.getPort();
                        if (port <= 0) port = https ? 443 : 80;
                        return HttpService.httpService(host, port, https);
                    }
                } catch (Exception ignored) {}
            }
            String domain = entry.getDomain();
            if (domain != null && !domain.isBlank()) {
                String host = domain.contains(":") ? domain.split(":")[0] : domain;
                int port = 443;
                if (domain.contains(":")) {
                    try { port = Integer.parseInt(domain.split(":")[1]); } catch (Exception ignored) {}
                }
                return HttpService.httpService(host, port, port != 80);
            }
        }
        String hostHeader = HttpMessageUtils.getHeader(rawRequest, "Host");
        if (hostHeader != null && !hostHeader.isBlank()) {
            String host = hostHeader.contains(":") ? hostHeader.split(":")[0] : hostHeader;
            int port = 443;
            if (hostHeader.contains(":")) {
                try { port = Integer.parseInt(hostHeader.split(":")[1]); } catch (Exception ignored) {}
            }
            return HttpService.httpService(host, port, port != 80);
        }
        return HttpService.httpService("localhost", 443, true);
    }

    /**
     * Build a minimal HTTP request template from the ApiEntry's method +
     * path + domain, so the editor has something to work with even when
     * no raw request was captured. The user can then edit and send it.
     */
    private static String buildTemplateRequest(ApiEntry entry) {
        if (entry == null) {
            return "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        }
        String method = entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET";
        String path = entry.getApiPath() != null ? entry.getApiPath() : "/";
        String host = entry.getDomain() != null ? entry.getDomain() : "localhost";
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {
            sb.append("Content-Type: application/json\r\n");
            sb.append("Content-Length: 0\r\n");
        }
        sb.append("\r\n");
        return sb.toString();
    }

    private void sendRequest() {
        HttpRequest request = requestEditor.getRequest();
        if (request == null) {
            statusLabel.setText("请求为空");
            statusLabel.setForeground(theme.statusError());
            return;
        }

        sendBtn.setEnabled(false);
        statusLabel.setText("发送中...");
        statusLabel.setForeground(theme.mutedText());

        new SwingWorker<HttpRequestResponse, Void>() {
            long startTime;

            @Override
            protected HttpRequestResponse doInBackground() {
                startTime = System.currentTimeMillis();
                return api.http().sendRequest(request);
            }

            @Override
            protected void done() {
                sendBtn.setEnabled(true);
                try {
                    HttpRequestResponse result = get();
                    long elapsed = System.currentTimeMillis() - startTime;
                    if (result.response() != null) {
                        responseEditor.setResponse(result.response());
                        int code = result.response().statusCode();
                        statusLabel.setText(String.format("完成 — %d — %dms — %d bytes",
                                code, elapsed, result.response().body().length()));
                        statusLabel.setForeground(code >= 500 ? theme.riskHigh()
                                : code >= 400 ? theme.riskMedium()
                                : theme.riskSafe());
                    } else {
                        statusLabel.setText("无响应");
                        statusLabel.setForeground(theme.statusError());
                    }
                } catch (Exception ex) {
                    statusLabel.setText("发送失败: " + ex.getMessage());
                    statusLabel.setForeground(theme.statusError());
                }
            }
        }.execute();
    }
}
