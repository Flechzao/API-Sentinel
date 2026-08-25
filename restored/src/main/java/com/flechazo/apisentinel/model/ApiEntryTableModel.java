package com.flechazo.apisentinel.model;

import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.repository.ApiRepository;

import javax.swing.table.AbstractTableModel;
import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ApiEntryTableModel extends AbstractTableModel {

    // New column layout:
    // 0:方法  1:接口路径  2:域名  3:响应码  4:风险  5:发现  6:被动  7:状态  8:流量  9:备注  10:操作
    public static final int COL_METHOD   = 0;
    public static final int COL_PATH     = 1;
    public static final int COL_DOMAIN   = 2;
    public static final int COL_STATUS_CODE = 3;
    public static final int COL_RISK     = 4;
    public static final int COL_FINDINGS = 5;
    public static final int COL_PASSIVE  = 6;
    public static final int COL_STATE    = 7;
    public static final int COL_TRAFFIC  = 8;
    public static final int COL_NOTE     = 9;
    public static final int COL_ACTION   = 10;

    private List<ApiEntry> displayList = new ArrayList<>();
    private final ApiRepository repository;

    // --- Filter state ---
    private volatile ApiStatus statusFilter = null;
    private volatile String domainFilter = null;
    private volatile String riskFilter = null; // null = all; HIGH/MEDIUM/LOW/SAFE/--"未分析"
    private java.util.function.BiConsumer<ApiEntry, String> onPathEdit;

    /** Paths with an in-flight full analysis (Pipeline/Agent) — drives the ⚙
     *  badge in COL_STATE. Purely runtime display state: never persisted and
     *  never written back into ApiStatus, so cancelling an analysis can never
     *  corrupt the user's real test state. */
    private final java.util.Set<String> analyzingPaths =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    public ApiEntryTableModel(ApiRepository repository) {
        this.repository = repository;
        refreshFromRepository();
    }

    public void setStatusFilter(ApiStatus filter) {
        this.statusFilter = filter;
        refreshFromRepository();
    }

    public void setDomainFilter(String domain) {
        this.domainFilter = (domain != null && !domain.isEmpty()) ? domain : null;
        refreshFromRepository();
    }

    public void setRiskFilter(String risk) {
        this.riskFilter = (risk != null && !risk.isEmpty()) ? risk : null;
        refreshFromRepository();
    }

    public void setFilter(ApiStatus status, String domain) {
        this.statusFilter = status;
        this.domainFilter = (domain != null && !domain.isEmpty()) ? domain : null;
        refreshFromRepository();
    }

    public ApiStatus getStatusFilter() { return statusFilter; }
    public String getDomainFilter() { return domainFilter; }

    public void refreshFromRepository() {
        SwingUtilities.invokeLater(() -> {
            this.displayList = applyFilters(repository.findAll());
            fireTableDataChanged();
        });
    }

    public void refreshFromRepositorySync() {
        assert SwingUtilities.isEventDispatchThread() : "refreshFromRepositorySync must be called on EDT";
        this.displayList = applyFilters(repository.findAll());
        fireTableDataChanged();
    }

    public void refreshI18n() {
        // No-op on the model — column names are resolved dynamically via
        // getColumnName(). Caller must repaint the table header.
    }

    private List<ApiEntry> applyFilters(List<ApiEntry> all) {
        List<ApiEntry> result = all;
        if (statusFilter != null) {
            result = result.stream()
                    .filter(e -> e.getStatus() == statusFilter)
                    .collect(Collectors.toList());
        }
        if (domainFilter != null) {
            result = result.stream()
                    .filter(e -> domainFilter.equalsIgnoreCase(e.getDomain()))
                    .collect(Collectors.toList());
        }
        if (riskFilter != null) {
            // "--" means "未分析" (no analysis record yet)
            if ("--".equals(riskFilter)) {
                result = result.stream()
                        .filter(e -> "--".equals(e.getDisplayRisk()))
                        .collect(Collectors.toList());
            } else {
                result = result.stream()
                        .filter(e -> riskFilter.equalsIgnoreCase(e.getDisplayRisk()))
                        .collect(Collectors.toList());
            }
        }
        return new ArrayList<>(result);
    }

    @Override public int getRowCount() { return displayList.size(); }
    @Override public int getColumnCount() { return 11; }
    @Override public String getColumnName(int column) {
        return switch (column) {
            case COL_METHOD -> com.flechazo.apisentinel.ui.I18n.get("col_method");
            case COL_PATH -> com.flechazo.apisentinel.ui.I18n.get("col_path");
            case COL_DOMAIN -> com.flechazo.apisentinel.ui.I18n.get("col_domain");
            case COL_STATUS_CODE -> com.flechazo.apisentinel.ui.I18n.get("col_status_code");
            case COL_RISK -> com.flechazo.apisentinel.ui.I18n.get("col_risk");
            case COL_FINDINGS -> com.flechazo.apisentinel.ui.I18n.get("col_findings");
            case COL_PASSIVE -> com.flechazo.apisentinel.ui.I18n.get("col_passive");
            case COL_STATE -> com.flechazo.apisentinel.ui.I18n.get("col_state");
            case COL_TRAFFIC -> com.flechazo.apisentinel.ui.I18n.get("col_traffic");
            case COL_NOTE -> com.flechazo.apisentinel.ui.I18n.get("col_note");
            case COL_ACTION -> com.flechazo.apisentinel.ui.I18n.get("col_action");
            default -> "";
        };
    }
    @Override public Class<?> getColumnClass(int columnIndex) { return String.class; }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == COL_METHOD || columnIndex == COL_PATH
                || columnIndex == COL_DOMAIN || columnIndex == COL_STATE
                || columnIndex == COL_RISK || columnIndex == COL_NOTE
                || columnIndex == COL_ACTION;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= displayList.size()) return null;
        ApiEntry e = displayList.get(rowIndex);
        return switch (columnIndex) {
            case COL_METHOD     -> e.getHttpMethod();
            case COL_PATH       -> e.getApiPath();
            case COL_DOMAIN     -> e.getDomain();
            case COL_STATUS_CODE -> e.getLastStatusCode() > 0 ? String.valueOf(e.getLastStatusCode()) : "--";
            case COL_RISK       -> e.getDisplayRisk();
            case COL_FINDINGS   -> e.getDisplayFindings();
            case COL_PASSIVE    -> e.getDisplayPassiveSummary();
            case COL_STATE      -> analyzingPaths.contains(e.getApiPath())
                    ? "⚙ " + e.getStatus().getDisplayName()
                    : e.getStatus().getDisplayName();
            case COL_TRAFFIC    -> e.hasTrafficData() ? "✓" : "✗";
            case COL_NOTE       -> e.getNote();
            case COL_ACTION     -> "▶";
            default -> null;
        };
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= displayList.size()) return;
        ApiEntry e = displayList.get(rowIndex);
        String val = aValue == null ? "" : aValue.toString().trim();
        switch (columnIndex) {
            case COL_METHOD -> {
                if (!val.isEmpty()) repository.updateMethod(e.getApiPath(), val);
            }
            case COL_DOMAIN -> repository.updateDomain(e.getApiPath(), val);
            case COL_STATE -> {
                // The ⚙ analyzing badge prefixes the cell text; strip it so
                // the ApiStatus match below still succeeds mid-analysis.
                if (val.startsWith("⚙ ")) val = val.substring(2).trim();
                // Free text → match to ApiStatus by display name
                for (ApiStatus s : ApiStatus.values()) {
                    if (s.getDisplayName().equals(val) || s.name().equalsIgnoreCase(val)) {
                        repository.updateStatus(e.getApiPath(), s, null,
                                s == ApiStatus.UNTESTED ? "" : s.getDisplayName());
                        break;
                    }
                }
            }
            case COL_RISK -> {
                e.setManualRisk(val);
                repository.markDirty();
            }
            case COL_PATH -> {
                if (val.isEmpty() || val.equals(e.getApiPath())) return;
                // Path is the identity key — delegate to the presenter which owns
                // the match engine (it must re-index the trie too).
                if (onPathEdit != null) onPathEdit.accept(e, val);
            }
            case COL_NOTE -> repository.updateNote(e.getApiPath(), val);
            default -> {}
        }
        fireTableRowsUpdated(rowIndex, rowIndex);
    }

    public void setOnPathEdit(java.util.function.BiConsumer<ApiEntry, String> cb) {
        this.onPathEdit = cb;
    }

    /** Mark the repository dirty so analysis-record additions get persisted
     *  on the debounced flush / extension unload. */
    public void markRepositoryDirty() {
        repository.markDirty();
    }

    /** The backing repository — facades use it for cross-endpoint vuln
     *  attribution and detached-entry (cascade sibling) adoption. */
    public ApiRepository getRepository() {
        return repository;
    }

    public ApiEntry getEntryAt(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < displayList.size()) {
            return displayList.get(rowIndex);
        }
        return null;
    }

    public int findRowByPath(String apiPath) {
        for (int i = 0; i < displayList.size(); i++) {
            if (displayList.get(i).getApiPath().equalsIgnoreCase(apiPath)) return i;
        }
        return -1;
    }

    /** Mark the row's state cell as "analyzing" (⚙ prefix) while a full
     *  Pipeline/Agent run is in flight. Called from the facades' lifecycle. */
    public void markAnalyzing(String apiPath) {
        if (apiPath == null || !analyzingPaths.add(apiPath)) return;
        int row = findRowByPath(apiPath);
        if (row >= 0) notifyRowUpdated(row);
    }

    /** Drop the ⚙ badge — the run finished, failed or was cancelled. */
    public void clearAnalyzing(String apiPath) {
        if (apiPath == null || !analyzingPaths.remove(apiPath)) return;
        int row = findRowByPath(apiPath);
        if (row >= 0) notifyRowUpdated(row);
    }

    public boolean isAnalyzing(String apiPath) {
        return apiPath != null && analyzingPaths.contains(apiPath);
    }

    public void notifyRowUpdated(int row) {
        if (row >= 0 && row < displayList.size()) {
            SwingUtilities.invokeLater(() -> fireTableRowsUpdated(row, row));
        }
    }
}
