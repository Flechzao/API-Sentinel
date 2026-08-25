package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.export.CsvExporter;
import com.flechazo.apisentinel.export.FullReportExporter;
import com.flechazo.apisentinel.export.MarkdownExporter;
import com.flechazo.apisentinel.export.ReportExporter;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.repository.ApiRepository;

import javax.swing.*;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ExportPresenter {

    private final ApiRepository repository;
    private final CsvExporter csvExporter;
    private final MarkdownExporter markdownExporter;
    private final FullReportExporter fullReportExporter;
    private ApiSentinelTab view;

    public ExportPresenter(ApiRepository repository) {
        this.repository = repository;
        this.csvExporter = new CsvExporter();
        this.markdownExporter = new MarkdownExporter();
        this.fullReportExporter = new FullReportExporter();
    }

    void setView(ApiSentinelTab view) {
        this.view = view;
    }

    public void onExportCsv() {
        exportWithChoice("api-sentinel-report.csv", "CSV", csvExporter);
    }

    public void onExportMarkdown() {
        exportWithChoice("api-sentinel-report.md", "报告", markdownExporter);
    }

    public void onExportFullReport() {
        exportWithChoice("api-sentinel-full-report.md", "完整报告", fullReportExporter);
    }

    /**
     * Ask the user whether to export all entries or only the currently selected
     * rows. Previously every export dumped the entire repository, producing noisy
     * reports even when the user had filtered/selected specific rows.
     */
    private void exportWithChoice(String defaultFileName, String label, ReportExporter exporter) {
        int selectedCount = view != null && view.getTablePanel() != null
                ? view.getTablePanel().getSelectedRows().length : 0;

        Object[] options;
        int choice;
        if (selectedCount > 0) {
            options = new Object[]{"导出选中行 (" + selectedCount + ")", "导出全部", "取消"};
            choice = JOptionPane.showOptionDialog(view,
                    "导出范围：选中 " + selectedCount + " 行，或全部 " + repository.size() + " 个 API？",
                    "导出" + label,
                    JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        } else {
            options = new Object[]{"导出全部 (" + repository.size() + ")", "取消"};
            choice = JOptionPane.showOptionDialog(view,
                    "未选中行，将导出全部 " + repository.size() + " 个 API。",
                    "导出" + label,
                    JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        }

        boolean exportSelected;
        if (choice == JOptionPane.CANCEL_OPTION || choice == JOptionPane.CLOSED_OPTION) return;
        if (selectedCount > 0) {
            if (choice == JOptionPane.YES_OPTION) exportSelected = true;
            else if (choice == JOptionPane.NO_OPTION) exportSelected = false;
            else return;
        } else {
            exportSelected = false;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(defaultFileName));
        if (chooser.showSaveDialog(view) != JFileChooser.APPROVE_OPTION) return;

        try {
            Path path = chooser.getSelectedFile().toPath();
            List<ApiEntry> toExport = exportSelected ? getSelectedEntries() : repository.findAll();
            exporter.export(toExport, path);
            JOptionPane.showMessageDialog(view, "导出成功: " + path + " (" + toExport.size() + " 条)",
                    label, JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(view, "导出失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private List<ApiEntry> getSelectedEntries() {
        List<ApiEntry> out = new ArrayList<>();
        int[] rows = view.getTablePanel().getSelectedRows();
        for (int i : rows) {
            int modelRow = view.getTablePanel().getTable().convertRowIndexToModel(i);
            ApiEntry e = tableModel(modelRow);
            if (e != null) out.add(e);
        }
        return out;
    }

    private ApiEntry tableModel(int modelRow) {
        return view.getTablePanel().getTableModel().getEntryAt(modelRow);
    }
}
