package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;

/**
 * Side-by-side evidence comparison: shows two request/response pairs next to
 * each other so a vulnerability can be confirmed by inspecting the "before vs
 * after" packets. For an IDOR/越权 finding the two sides are the two sessions
 * (owner vs attacker) hitting the same endpoint — the visual proof that one
 * session read another's data.
 *
 * <p>Read-only Montoya editors on both sides. For a byte-level diff, the
 * Repeater's existing "⇋ Comparer" button still routes to Burp's native
 * Comparer; this dialog is the in-plugin at-a-glance pair view.
 */
final class EvidenceCompareDialog {

    private EvidenceCompareDialog() {}

    /** Open a modeless side-by-side comparison window. Raw request/response
     *  strings may be null/blank (the corresponding editor is left empty). */
    static void show(MontoyaApi api, Component parent, String title,
                     String leftLabel, String leftReq, String leftResp,
                     String rightLabel, String rightReq, String rightResp) {
        Window owner = parent != null ? SwingUtilities.getWindowAncestor(parent) : null;
        JDialog dialog = new JDialog(owner, title == null ? "证据对比" : title,
                Dialog.ModalityType.MODELESS);

        JComponent left = buildColumn(api, leftLabel, leftReq, leftResp);
        JComponent right = buildColumn(api, rightLabel, rightReq, rightResp);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setResizeWeight(0.5);
        split.setBorder(null);

        dialog.setContentPane(split);
        dialog.setSize(1180, 760);
        dialog.setMinimumSize(new Dimension(820, 520));
        dialog.setLocationRelativeTo(owner);
        try { new BurpTheme(api).apply(dialog); } catch (Exception ignored) {}
        // Split divider must be positioned after the dialog is realized.
        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.5));
        dialog.setVisible(true);
        dialog.toFront();
    }

    /** One column: a header label over a request editor (top) + response
     *  editor (bottom), both read-only. */
    private static JComponent buildColumn(MontoyaApi api, String label, String rawReq, String rawResp) {
        JPanel col = new JPanel(new BorderLayout());

        JLabel header = new JLabel(" " + (label == null || label.isBlank() ? "包" : label));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 13f));
        header.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        col.add(header, BorderLayout.NORTH);

        HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        if (rawReq != null && !rawReq.isBlank()) {
            try { reqEditor.setRequest(HttpRequest.httpRequest(rawReq)); } catch (Exception ignored) {}
        }
        if (rawResp != null && !rawResp.isBlank()) {
            try {
                respEditor.setResponse(HttpResponse.httpResponse(rawResp));
            } catch (Exception e) {
                try { respEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + rawResp)); }
                catch (Exception ignored) {}
            }
        }

        JPanel reqWrap = titled("Request", reqEditor.uiComponent());
        JPanel respWrap = titled("Response", respEditor.uiComponent());
        JSplitPane vSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqWrap, respWrap);
        vSplit.setResizeWeight(0.5);
        vSplit.setBorder(null);
        SwingUtilities.invokeLater(() -> vSplit.setDividerLocation(0.5));
        col.add(vSplit, BorderLayout.CENTER);
        return col;
    }

    private static JPanel titled(String title, Component body) {
        JPanel p = new JPanel(new BorderLayout());
        JLabel l = new JLabel(" " + title);
        l.setFont(l.getFont().deriveFont(Font.PLAIN, 11f));
        l.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        p.add(l, BorderLayout.NORTH);
        p.add(body, BorderLayout.CENTER);
        return p;
    }
}
