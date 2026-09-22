package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.util.BambdaBuilder;
import com.flechazo.apisentinel.util.BambdaFilterSettings;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Full standalone Bambda builder — a Java rewrite of the Bambda++ plugin's
 * generation panel. Configure HTTP method / domain / keyword / MIME / status /
 * search / extension / annotation / listener filters, generate the Bambda, and
 * copy it into Burp's native Bambda editor. Config persists to JSON.
 */
public class BambdaBuilderPanel extends JPanel {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final com.flechazo.apisentinel.config.ConfigManager configManager;
    private final com.flechazo.apisentinel.repository.ApiRepository repository;
    private final burp.api.montoya.MontoyaApi montoya;

    // --- Extension filters ---
    private final JCheckBox methodEnabled = new JCheckBox(I18n.get("bambda_exclude_method"));
    private final Map<String, JCheckBox> methodChecks = new LinkedHashMap<>();
    private final JCheckBox keywordsEnabled = new JCheckBox(I18n.get("bambda_include_keywords"));
    private final JTextField keywordsField = new JTextField(30);
    private final JCheckBox excludeKeywordsEnabled = new JCheckBox(I18n.get("bambda_exclude_keywords"));
    private final JTextField excludeKeywordsField = new JTextField(30);
    private final JCheckBox domainEnabled = new JCheckBox("排除域名（逗号分隔，支持 * 通配）");
    private final JTextArea domainArea = new JTextArea(3, 40);

    // --- Burp-style filters ---
    private final JCheckBox inScope = new JCheckBox(I18n.get("bambda_in_scope_only"));
    private final JCheckBox hasResponse = new JCheckBox(I18n.get("bambda_hide_no_response"));
    private final JCheckBox parameterized = new JCheckBox(I18n.get("bambda_parameterized_only"));
    private final Map<String, JCheckBox> mimeChecks = new LinkedHashMap<>();
    private final Map<String, JCheckBox> statusChecks = new LinkedHashMap<>();
    private final JCheckBox searchEnabled = new JCheckBox(I18n.get("bambda_search_filter_enabled"));
    private final JTextField searchField = new JTextField(20);
    private final JCheckBox searchRegex = new JCheckBox(I18n.get("bambda_search_regex"));
    private final JCheckBox searchCase = new JCheckBox(I18n.get("bambda_search_case_sensitive"));
    private final JCheckBox searchNegative = new JCheckBox(I18n.get("bambda_search_negative"));
    private final JCheckBox showOnlyExtEnabled = new JCheckBox(I18n.get("bambda_show_only_ext"));
    private final JTextField showOnlyExtField = new JTextField(16);
    private final JCheckBox hideExtEnabled = new JCheckBox(I18n.get("bambda_hide_ext"));
    private final JTextField hideExtField = new JTextField(16);
    private final JCheckBox notesOnly = new JCheckBox(I18n.get("bambda_notes_only"));
    private final JCheckBox highlightOnly = new JCheckBox(I18n.get("bambda_highlight_only"));
    private final JTextField portField = new JTextField(8);

    private final JTextArea output = new JTextArea(10, 60);

    public BambdaBuilderPanel(MontoyaApi api) {
        this(api, null, null);
    }

    public BambdaBuilderPanel(MontoyaApi api, com.flechazo.apisentinel.config.ConfigManager configManager) {
        this(api, configManager, null);
    }

    public BambdaBuilderPanel(MontoyaApi api, com.flechazo.apisentinel.config.ConfigManager configManager,
                              com.flechazo.apisentinel.repository.ApiRepository repository) {
        this.configManager = configManager;
        this.repository = repository;
        this.montoya = api;
        setLayout(new BorderLayout());

        // ===== TOP: compact runtime toggles + asset generation =====
        JPanel topBar = new JPanel();
        topBar.setLayout(new BoxLayout(topBar, BoxLayout.Y_AXIS));
        topBar.setBorder(new EmptyBorder(4, 4, 4, 4));

        if (configManager != null) {
            JPanel optRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            optRow.setBorder(BorderFactory.createTitledBorder(I18n.get("bambda_runtime_filter")));
            JCheckBox optCheck = new JCheckBox(I18n.get("bambda_filter_options_preflight"));
            optCheck.setToolTipText(I18n.get("bambda_filter_options_preflight_tooltip"));
            optCheck.setSelected(configManager.getConfig().isFilterOptionsPreflightEnabled());
            optCheck.addActionListener(e -> configManager.setFilterOptionsPreflightEnabled(optCheck.isSelected()));
            JCheckBox hlCheck = new JCheckBox(I18n.get("bambda_highlight_keywords"));
            hlCheck.setToolTipText(I18n.get("bambda_highlight_keywords_tooltip"));
            hlCheck.setSelected(configManager.getConfig().isBambdaHighlightEnabled());
            JTextField hlField = new JTextField(configManager.getConfig().getBambdaHighlightKeywords(), 18);
            hlCheck.addActionListener(e -> configManager.setBambdaHighlightEnabled(hlCheck.isSelected()));
            hlField.addActionListener(e -> configManager.setBambdaHighlightKeywords(hlField.getText().trim()));
            optRow.add(optCheck);
            optRow.add(new JLabel(I18n.get("bambda_keywords_label")));
            optRow.add(hlField);
            optRow.add(hlCheck);
            topBar.add(optRow);
        }

        if (repository != null) {
            JPanel assetRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            assetRow.setBorder(BorderFactory.createTitledBorder(I18n.get("bambda_generate_from_assets")));
            JComboBox<String> assetScope = new JComboBox<>(new String[]{
                    I18n.get("bambda_scope_all_apis"), I18n.get("bambda_scope_traffic_only"), I18n.get("bambda_scope_in_scope"), I18n.get("bambda_scope_risk")});
            JCheckBox includeFilters = new JCheckBox(I18n.get("bambda_include_filters"), true);
            includeFilters.setToolTipText(I18n.get("bambda_include_filters_tooltip"));
            JButton assetGen = new JButton(I18n.get("bambda_generate_filter_code"));
            assetGen.addActionListener(e -> generateFromAssets(assetScope.getSelectedIndex(), includeFilters.isSelected()));
            assetRow.add(new JLabel(I18n.get("bambda_scope_label")));
            assetRow.add(assetScope);
            assetRow.add(includeFilters);
            assetRow.add(assetGen);
            topBar.add(assetRow);
        }

        // ===== MIDDLE: tabbed filter panels (only one visible at a time) =====
        JTabbedPane filterTabs = new JTabbedPane();
        JScrollPane extScroll = new JScrollPane(buildExtensionFilters());
        extScroll.setBorder(null);
        extScroll.getVerticalScrollBar().setUnitIncrement(16);
        JScrollPane burpScroll = new JScrollPane(buildBurpFilters());
        burpScroll.setBorder(null);
        burpScroll.getVerticalScrollBar().setUnitIncrement(16);
        filterTabs.addTab(I18n.get("bambda_tab_extension_filter"), extScroll);
        filterTabs.addTab("Burp 风格过滤", burpScroll);
        filterTabs.setBorder(new EmptyBorder(2, 4, 2, 4));

        // ===== BOTTOM: buttons + output =====
        output.setEditable(false);
        BurpTheme theme = safeTheme(api);
        if (theme != null) output.setFont(theme.editorFont(12f));
        else output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        output.setLineWrap(false);
        JScrollPane outScroll = new JScrollPane(output);
        outScroll.setBorder(BorderFactory.createTitledBorder(I18n.get("bambda_generated_code_title")));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton gen = new JButton(I18n.get("bambda_generate_code"));
        gen.addActionListener(e -> output.setText(BambdaBuilder.build(collect())));
        JButton apply = new JButton(I18n.get("bambda_apply_to_burp"));
        apply.setToolTipText(I18n.get("bambda_apply_to_burp_tooltip"));
        apply.addActionListener(e -> applyToBurp());
        JButton copy = new JButton(I18n.get("bambda_copy"));
        copy.addActionListener(e -> {
            String c = output.getText();
            if (c == null || c.isBlank()) c = BambdaBuilder.build(collect());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(c), null);
        });
        JButton save = new JButton(I18n.get("bambda_save_config"));
        save.addActionListener(e -> saveConfig());
        JButton load = new JButton(I18n.get("bambda_load_config"));
        load.addActionListener(e -> { loadConfig(); output.setText(BambdaBuilder.build(collect())); });
        buttons.add(gen); buttons.add(apply); buttons.add(copy); buttons.add(save); buttons.add(load);
        buttons.add(new JLabel(I18n.get("bambda_preset_label")));
        buttons.add(presetButton(I18n.get("bambda_preset_default"), this::presetDefault));
        buttons.add(presetButton(I18n.get("bambda_preset_static_noise"), this::presetStaticNoise));
        buttons.add(presetButton(I18n.get("bambda_preset_dynamic_apis"), this::presetDynamicApis));
        buttons.add(presetButton(I18n.get("bambda_preset_write_ops"), this::presetWriteOps));

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(buttons, BorderLayout.NORTH);
        bottom.add(outScroll, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, filterTabs, bottom);
        split.setResizeWeight(0.55);
        split.setBorder(null);

        add(topBar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        initDefaults();
        wireExtMutualExclusion();
        loadConfig();
        output.setText(BambdaBuilder.build(collect()));

        // Auto-refresh on language toggle
        I18n.addLangListener(lang -> javax.swing.SwingUtilities.invokeLater(() -> {
            methodEnabled.setText(I18n.get("bambda_exclude_method"));
            keywordsEnabled.setText(I18n.get("bambda_include_keywords"));
            excludeKeywordsEnabled.setText(I18n.get("bambda_exclude_keywords"));
            domainEnabled.setText(I18n.get("bambda_exclude_domain"));
            inScope.setText(I18n.get("bambda_in_scope_only"));
            hasResponse.setText(I18n.get("bambda_hide_no_response"));
            parameterized.setText(I18n.get("bambda_parameterized_only"));
            searchEnabled.setText(I18n.get("bambda_search_filter_enabled"));
            searchRegex.setText(I18n.get("bambda_search_regex"));
            searchCase.setText(I18n.get("bambda_search_case_sensitive"));
            searchNegative.setText(I18n.get("bambda_search_negative"));
            showOnlyExtEnabled.setText(I18n.get("bambda_show_only_ext"));
            hideExtEnabled.setText(I18n.get("bambda_hide_ext"));
            notesOnly.setText(I18n.get("bambda_notes_only"));
            highlightOnly.setText(I18n.get("bambda_highlight_only"));
        }));
    }

    /** Build a FILTER Bambda from captured API entries matching the chosen scope. */
    private void generateFromAssets(int scopeIndex, boolean includeFilters) {
        if (repository == null) return;
        List<com.flechazo.apisentinel.model.ApiEntry> all = repository.findAll();
        List<com.flechazo.apisentinel.model.ApiEntry> picked = new ArrayList<>();
        for (com.flechazo.apisentinel.model.ApiEntry e : all) {
            boolean keep = switch (scopeIndex) {
                case 1 -> e.hasTrafficData();
                case 2 -> isInScope(e);
                case 3 -> {
                    String r = e.getDisplayRisk();
                    yield r != null && (r.equalsIgnoreCase("HIGH") || r.equalsIgnoreCase("MEDIUM"));
                }
                default -> true;
            };
            if (keep) picked.add(e);
        }
        if (picked.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.get("bambda_no_apis_in_scope"));
            return;
        }
        String code = generateCombinedBambda(picked, includeFilters);
        output.setText(code);
        output.setCaretPosition(0);
    }

    /**
     * Generate a Bambda that matches the given API entries. Always excludes
     * OPTIONS preflight. Optionally includes extension filter conditions
     * (method/domain/keyword/MIME/etc. from current panel settings).
     *
     * @param entries        the API entries to match
     * @param includeFilters whether to include extension filter conditions
     * @return the generated Bambda code
     */
    public String generateCombinedBambda(List<com.flechazo.apisentinel.model.ApiEntry> entries,
                                           boolean includeFilters) {
        String assetCode = com.flechazo.apisentinel.util.BambdaCodeGen.generateBatch(
                entries, com.flechazo.apisentinel.util.BambdaCodeGen.Mode.FILTER);
        String assetVars = stripCommentsAndReturn(assetCode);

        // OPTIONS preflight exclusion — ALWAYS added regardless of includeFilters.
        String optionsCond = "!\"OPTIONS\".equals(requestResponse.request().method())";

        if (!includeFilters) {
            // Path matching only + OPTIONS exclusion. No extension filter variables.
            return "// API Sentinel — " + entries.size() + " " + I18n.get("bambda_asset_filter_comment") + "\n"
                    + assetVars + "\n"
                    + "return matched && " + optionsCond + ";\n";
        }

        // Combined: extension filters + asset matching + OPTIONS exclusion.
        String filterCode = BambdaBuilder.build(collect());
        String filterVars = stripCommentsAndReturn(filterCode);
        String filterCond = extractConditions(filterCode);

        // Deduplicate: reuse filter's host/path if already declared.
        if (filterVars.contains("String host =")) {
            assetVars = assetVars.replace("String reqHost = requestResponse.request().httpService().host();\n", "");
            assetVars = assetVars.replace("reqHost", "host");
        }
        if (filterVars.contains("String path =")) {
            assetVars = assetVars.replace("String reqPath = requestResponse.request().pathWithoutQuery();\n", "");
            assetVars = assetVars.replace("reqPath", "path");
        }

        return "// API Sentinel — " + entries.size() + " " + I18n.get("bambda_asset_filter_ext_comment") + "\n"
                + filterVars + "\n"
                + assetVars + "\n"
                + "return " + filterCond + " && matched && " + optionsCond + ";\n";
    }

    /** Strip // comment lines AND the final return line, keep variable declarations. */
    private static String stripCommentsAndReturn(String code) {
        StringBuilder out = new StringBuilder();
        for (String line : code.split("\n", -1)) {
            if (line.stripLeading().startsWith("//")) continue;
            if (line.stripLeading().startsWith("return ")) break;
            out.append(line).append("\n");
        }
        String result = out.toString().strip();
        return result.isEmpty() ? "" : result + "\n";
    }

    /** Extract the condition expression from 'return <conditions>;' (last line). */
    private static String extractConditions(String code) {
        int idx = code.lastIndexOf("return ");
        if (idx < 0) return "true";
        String tail = code.substring(idx + 7);
        int semi = tail.lastIndexOf(';');
        if (semi >= 0) tail = tail.substring(0, semi);
        return tail.strip();
    }

    private boolean isInScope(com.flechazo.apisentinel.model.ApiEntry e) {
        if (montoya == null) return false;
        try {
            String url = e.getLastUrl();
            if (url == null || url.isBlank()) {
                String d = e.getDomain();
                if (d == null || d.isBlank()) return false;
                url = "https://" + d + (e.getApiPath() == null ? "" : e.getApiPath());
            }
            return montoya.scope().isInScope(url);
        } catch (Exception ex) {
            return false;
        }
    }

    // ======================== layout ========================

    private JComponent buildExtensionFilters() {
        JPanel g = titled(I18n.get("bambda_section_extension_filter"));
        g.setLayout(new GridBagLayout());
        GridBagConstraints c = gbc();

        // HTTP method
        JPanel methodPanel = titled("HTTP 方法");
        methodPanel.setLayout(new BorderLayout());
        JPanel methodTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        methodTop.add(methodEnabled);
        methodPanel.add(methodTop, BorderLayout.NORTH);
        JPanel methodGrid = new JPanel(new GridLayout(0, 4, 4, 2));
        for (String m : BambdaFilterSettings.ALL_METHODS) {
            JCheckBox cb = new JCheckBox(m);
            methodChecks.put(m, cb);
            methodGrid.add(cb);
        }
        methodPanel.add(methodGrid, BorderLayout.CENTER);
        c.gridx = 0; c.gridy = 0; c.weightx = 1;
        g.add(methodPanel, c);

        // Keywords
        JPanel kw = titled(I18n.get("bambda_section_keywords"));
        kw.setLayout(new GridBagLayout());
        GridBagConstraints kc = gbc();
        kc.gridx = 0; kc.gridy = 0; kw.add(keywordsEnabled, kc);
        kc.gridy = 1; kw.add(keywordsField, kc);
        kc.gridy = 2; kw.add(excludeKeywordsEnabled, kc);
        kc.gridy = 3; kw.add(excludeKeywordsField, kc);
        c.gridx = 1; g.add(kw, c);

        // Exclude domains
        JPanel dm = titled(I18n.get("bambda_section_domain_filter"));
        dm.setLayout(new BorderLayout());
        JPanel dmTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        dmTop.add(domainEnabled);
        dm.add(dmTop, BorderLayout.NORTH);
        domainArea.setLineWrap(true);
        JScrollPane ds = new JScrollPane(domainArea);
        ds.setPreferredSize(new Dimension(0, 80));
        dm.add(ds, BorderLayout.CENTER);
        c.gridx = 0; c.gridy = 1; c.gridwidth = 2; c.fill = GridBagConstraints.BOTH;
        g.add(dm, c);

        return g;
    }

    private JComponent buildBurpFilters() {
        JPanel g = titled("Burp 风格过滤");
        g.setLayout(new GridBagLayout());
        GridBagConstraints c = gbc();

        // Request type
        JPanel rt = titled(I18n.get("bambda_section_request_type"));
        rt.setLayout(new GridLayout(0, 1, 2, 2));
        rt.add(inScope); rt.add(hasResponse); rt.add(parameterized);
        c.gridx = 0; c.gridy = 0; g.add(rt, c);

        // MIME
        JPanel mime = titled(I18n.get("bambda_section_mime_type"));
        mime.setLayout(new GridLayout(0, 2, 2, 2));
        for (String label : BambdaFilterSettings.ALL_MIME) {
            JCheckBox cb = new JCheckBox(label);
            mimeChecks.put(label, cb);
            mime.add(cb);
        }
        c.gridx = 1; g.add(mime, c);

        // Status
        JPanel st = titled(I18n.get("bambda_section_status_code"));
        st.setLayout(new GridLayout(0, 2, 2, 2));
        for (String label : BambdaFilterSettings.ALL_STATUS) {
            JCheckBox cb = new JCheckBox(label);
            statusChecks.put(label, cb);
            st.add(cb);
        }
        c.gridx = 2; g.add(st, c);

        // Search
        JPanel se = titled(I18n.get("bambda_section_search"));
        se.setLayout(new GridBagLayout());
        GridBagConstraints sc = gbc();
        sc.gridx = 0; sc.gridy = 0; sc.gridwidth = 2; se.add(searchEnabled, sc);
        sc.gridy = 1; se.add(searchField, sc);
        sc.gridy = 2; sc.gridwidth = 1; se.add(searchRegex, sc);
        sc.gridx = 1; se.add(searchCase, sc);
        sc.gridx = 0; sc.gridy = 3; se.add(searchNegative, sc);
        c.gridx = 0; c.gridy = 1; g.add(se, c);

        // Extension
        JPanel ext = titled(I18n.get("bambda_section_extension"));
        ext.setLayout(new GridBagLayout());
        GridBagConstraints ec = gbc();
        ec.gridx = 0; ec.gridy = 0; ext.add(showOnlyExtEnabled, ec);
        ec.gridx = 1; ext.add(showOnlyExtField, ec);
        ec.gridx = 0; ec.gridy = 1; ext.add(hideExtEnabled, ec);
        ec.gridx = 1; ext.add(hideExtField, ec);
        c.gridx = 1; c.gridy = 1; g.add(ext, c);

        // Annotation + listener
        JPanel an = titled(I18n.get("bambda_section_annotation_listener"));
        an.setLayout(new GridBagLayout());
        GridBagConstraints ac = gbc();
        ac.gridx = 0; ac.gridy = 0; an.add(notesOnly, ac);
        ac.gridy = 1; an.add(highlightOnly, ac);
        JPanel portRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        portRow.add(new JLabel(I18n.get("bambda_listener_port_label")));
        portRow.add(portField);
        ac.gridy = 2; an.add(portRow, ac);
        c.gridx = 2; c.gridy = 1; g.add(an, c);

        return g;
    }

    /** Import the generated Bambda directly into Burp's Proxy history filter
     *  via the official Montoya API. importBambda expects a JSON string with
     *  id/name/function/location fields (not raw code). Shows compilation
     *  errors if the code doesn't compile in the Bambda context. */
    /** Copy the generated Bambda to clipboard with paste instructions. */
    private void applyToBurp() {
        String code = output.getText();
        if (code == null || code.isBlank()) {
            code = BambdaBuilder.build(collect());
            output.setText(code);
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(code), null);
        JOptionPane.showMessageDialog(this,
                I18n.get("bambda_copied_to_clipboard_msg"),
                I18n.get("bambda_copied_title"), JOptionPane.INFORMATION_MESSAGE);
    }

    // ======================== presets ========================

    private JButton presetButton(String label, java.util.function.Supplier<BambdaFilterSettings> preset) {
        JButton b = new JButton(label);
        b.addActionListener(e -> {
            apply(preset.get());
            wireExtMutualExclusionRefresh();
            output.setText(BambdaBuilder.build(collect()));
            output.setCaretPosition(0);
        });
        return b;
    }

    private BambdaFilterSettings presetDefault() {
        return new BambdaFilterSettings();
    }

    /** Hide static/asset noise: drop static extensions + non-business methods. */
    private BambdaFilterSettings presetStaticNoise() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterMethodEnabled = true;
        s.methods = new ArrayList<>(List.of("HEAD", "OPTIONS", "TRACE", "CONNECT"));
        s.showOnlyExtEnabled = false;
        s.hideExtEnabled = true;
        s.hideExt = "js,css,gif,jpg,jpeg,png,svg,ico,woff,woff2,ttf,map";
        return s;
    }

    /** Focus on dynamic API traffic: dynamic MIME only + hide static + drop noise methods. */
    private BambdaFilterSettings presetDynamicApis() {
        BambdaFilterSettings s = presetStaticNoise();
        s.mimeTypes = new ArrayList<>(List.of("HTML", "Script", "XML", "Other text"));
        return s;
    }

    /** Only state-changing requests: exclude read/noise verbs. */
    private BambdaFilterSettings presetWriteOps() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterMethodEnabled = true;
        s.methods = new ArrayList<>(List.of("GET", "HEAD", "OPTIONS", "TRACE", "CONNECT"));
        return s;
    }

    // ======================== state ========================

    private void initDefaults() {
        BambdaFilterSettings d = new BambdaFilterSettings();
        apply(d);
    }

    private void wireExtMutualExclusion() {
        java.awt.event.ActionListener l = e -> {
            boolean showOn = showOnlyExtEnabled.isSelected();
            if (showOn) { hideExtEnabled.setSelected(false); }
            hideExtEnabled.setEnabled(!showOn);
            hideExtField.setEnabled(!showOn && hideExtEnabled.isSelected());
            showOnlyExtField.setEnabled(showOn);
        };
        showOnlyExtEnabled.addActionListener(l);
        hideExtEnabled.addActionListener(l);
        l.actionPerformed(null);
    }

    /** Collect current UI state into a settings snapshot. */
    private BambdaFilterSettings collect() {
        BambdaFilterSettings s = new BambdaFilterSettings();
        s.filterMethodEnabled = methodEnabled.isSelected();
        s.methods = selected(methodChecks);
        s.filterKeywordsEnabled = keywordsEnabled.isSelected();
        s.keywords = keywordsField.getText();
        s.filterExcludeKeywordsEnabled = excludeKeywordsEnabled.isSelected();
        s.excludeKeywords = excludeKeywordsField.getText();
        s.filterDomainEnabled = domainEnabled.isSelected();
        s.domains = domainArea.getText();
        s.filterInScope = inScope.isSelected();
        s.filterHasResponse = hasResponse.isSelected();
        s.filterParameterized = parameterized.isSelected();
        s.mimeTypes = selected(mimeChecks);
        s.statusCodes = selected(statusChecks);
        s.searchFilterEnabled = searchEnabled.isSelected();
        s.searchTerm = searchField.getText();
        s.searchRegex = searchRegex.isSelected();
        s.searchCaseSensitive = searchCase.isSelected();
        s.searchNegative = searchNegative.isSelected();
        s.showOnlyExtEnabled = showOnlyExtEnabled.isSelected();
        s.showOnlyExt = showOnlyExtField.getText();
        s.hideExtEnabled = hideExtEnabled.isSelected();
        s.hideExt = hideExtField.getText();
        s.filterNotesOnly = notesOnly.isSelected();
        s.highlightEnabled = highlightOnly.isSelected();
        s.listenerPort = portField.getText().trim();
        return s;
    }

    /** Push a settings snapshot into the UI controls. */
    private void apply(BambdaFilterSettings s) {
        methodEnabled.setSelected(s.filterMethodEnabled);
        setSelected(methodChecks, s.methods);
        keywordsEnabled.setSelected(s.filterKeywordsEnabled);
        keywordsField.setText(s.keywords);
        excludeKeywordsEnabled.setSelected(s.filterExcludeKeywordsEnabled);
        excludeKeywordsField.setText(s.excludeKeywords);
        domainEnabled.setSelected(s.filterDomainEnabled);
        domainArea.setText(s.domains);
        inScope.setSelected(s.filterInScope);
        hasResponse.setSelected(s.filterHasResponse);
        parameterized.setSelected(s.filterParameterized);
        setSelected(mimeChecks, s.mimeTypes);
        setSelected(statusChecks, s.statusCodes);
        searchEnabled.setSelected(s.searchFilterEnabled);
        searchField.setText(s.searchTerm);
        searchRegex.setSelected(s.searchRegex);
        searchCase.setSelected(s.searchCaseSensitive);
        searchNegative.setSelected(s.searchNegative);
        showOnlyExtEnabled.setSelected(s.showOnlyExtEnabled);
        showOnlyExtField.setText(s.showOnlyExt);
        hideExtEnabled.setSelected(s.hideExtEnabled);
        hideExtField.setText(s.hideExt);
        notesOnly.setSelected(s.filterNotesOnly);
        highlightOnly.setSelected(s.highlightEnabled);
        portField.setText(s.listenerPort);
    }

    private static List<String> selected(Map<String, JCheckBox> checks) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> e : checks.entrySet()) {
            if (e.getValue().isSelected()) out.add(e.getKey());
        }
        return out;
    }

    private static void setSelected(Map<String, JCheckBox> checks, List<String> on) {
        java.util.Set<String> set = on == null ? java.util.Set.of() : new java.util.HashSet<>(on);
        for (Map.Entry<String, JCheckBox> e : checks.entrySet()) {
            e.getValue().setSelected(set.contains(e.getKey()));
        }
    }

    // ======================== persistence ========================

    /** Montoya persistence key (survives with the extension/project — the
     *  official replacement for hand-managed config files). */
    private static final String PERSIST_KEY = "bambda_builder_config";

    private static Path legacyConfigPath() {
        return com.flechazo.apisentinel.config.AppPaths.configFile().getParent().resolve("bambda_builder.json");
    }

    private void saveConfig() {
        String json = GSON.toJson(collect());
        try {
            if (montoya != null) {
                montoya.persistence().extensionData().setString(PERSIST_KEY, json);
            } else {
                Path p = legacyConfigPath();
                Files.createDirectories(p.getParent());
                Files.writeString(p, json, StandardCharsets.UTF_8);
            }
            JOptionPane.showMessageDialog(this, I18n.get("bambda_config_saved"));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, I18n.get("bambda_save_failed") + ex.getMessage(), "Bambda", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadConfig() {
        try {
            String json = null;
            if (montoya != null) {
                json = montoya.persistence().extensionData().getString(PERSIST_KEY);
            }
            if (json == null || json.isBlank()) {
                // One-time migration from the legacy file (if present).
                Path p = legacyConfigPath();
                if (Files.exists(p)) json = Files.readString(p, StandardCharsets.UTF_8);
            }
            if (json == null || json.isBlank()) return;
            BambdaFilterSettings s = GSON.fromJson(json, BambdaFilterSettings.class);
            if (s != null) { apply(s); wireExtMutualExclusionRefresh(); }
        } catch (Exception ignored) {
            // corrupt/legacy config — keep current UI state
        }
    }

    private void wireExtMutualExclusionRefresh() {
        boolean showOn = showOnlyExtEnabled.isSelected();
        hideExtEnabled.setEnabled(!showOn);
        hideExtField.setEnabled(!showOn && hideExtEnabled.isSelected());
        showOnlyExtField.setEnabled(showOn);
    }

    // ======================== ui helpers ========================

    private static JPanel titled(String title) {
        JPanel p = new JPanel();
        p.setBorder(BorderFactory.createTitledBorder(title));
        return p;
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(2, 2, 2, 2);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.weightx = 1;
        return c;
    }

    private static BurpTheme safeTheme(MontoyaApi api) {
        try { return new BurpTheme(api); } catch (Exception e) { return null; }
    }
}
