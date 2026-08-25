package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.repository.ApiRepository;

import java.util.HashSet;
import java.util.Set;

public class StatusPresenter {

    private final MontoyaApi api;
    private final ApiRepository repository;
    private final ApiEntryTableModel tableModel;
    private final LeveledLogger logger;

    public StatusPresenter(MontoyaApi api, ApiRepository repository,
                           ApiEntryTableModel tableModel, LeveledLogger logger) {
        this.api = api;
        this.repository = repository;
        this.tableModel = tableModel;
        this.logger = logger;
    }

    public void onToggleStatus(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry != null) entry.cycleTestStatus();
        }
        tableModel.refreshFromRepository();
    }

    public void onToggleVulnType(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry != null) entry.cycleVulnType();
        }
        tableModel.refreshFromRepository();
    }

    public void onMoveTestedToTop() {
        repository.moveTestedToTop();
        tableModel.refreshFromRepository();
    }

    public void onAddDomainsToScope(int[] selectedRows) {
        if (selectedRows == null || selectedRows.length == 0) return;
        Set<String> domains = new HashSet<>();
        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry != null && !entry.getDomain().isEmpty()) domains.add(entry.getDomain());
        }
        for (String domain : domains) {
            try {
                api.scope().includeInScope("https://" + domain);
                logger.info("已添加到Scope: %s", domain);
            } catch (Exception e) {
                logger.error("添加Scope失败: %s", e.getMessage());
            }
        }
    }
}
