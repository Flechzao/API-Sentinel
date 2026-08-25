package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.ai.queue.TaskRecord;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Panel showing the analysis task queue as a detail tab.
 * Displays task status, timing, and findings count with color coding.
 */
public class TaskQueuePanel extends JPanel {

    private final AnalysisTaskQueue taskQueue;
    private final TaskQueueTableModel tableModel;
    private final JTable table;
    private final BurpTheme theme;
    private Timer refreshTimer;

    public TaskQueuePanel(AnalysisTaskQueue taskQueue, BurpTheme theme) {
        this.taskQueue = taskQueue;
        this.theme = theme;
        setLayout(new BorderLayout(0, 4));

        // Header
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel title = new JLabel("分析任务队列");
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        header.add(title);
        add(header, BorderLayout.NORTH);

        // Table
        tableModel = new TaskQueueTableModel();
        table = new JTable(tableModel);
        table.setRowHeight(24);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(false);
        table.setFont(theme.displayFont(Font.PLAIN, 12f));

        // Column widths
        var cm = table.getColumnModel();
        cm.getColumn(0).setPreferredWidth(40);   // #
        cm.getColumn(0).setMaxWidth(50);
        cm.getColumn(1).setPreferredWidth(250);   // API路径
        cm.getColumn(2).setPreferredWidth(100);   // 分析模式
        cm.getColumn(2).setMaxWidth(120);
        cm.getColumn(3).setPreferredWidth(80);    // 状态
        cm.getColumn(3).setMaxWidth(100);
        cm.getColumn(4).setPreferredWidth(140);   // 开始时间
        cm.getColumn(4).setMaxWidth(160);
        cm.getColumn(5).setPreferredWidth(70);    // 耗时
        cm.getColumn(5).setMaxWidth(90);
        cm.getColumn(6).setPreferredWidth(60);    // 发现数
        cm.getColumn(6).setMaxWidth(80);

        // Status column color renderer
        cm.getColumn(3).setCellRenderer(new StatusCellRenderer());

        add(new JScrollPane(table), BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        JButton pauseBtn = new JButton("暂停队列");
        pauseBtn.addActionListener(e -> {
            taskQueue.setPaused(true);
            pauseBtn.setEnabled(false);
        });
        buttonPanel.add(pauseBtn);

        JButton resumeBtn = new JButton("恢复队列");
        resumeBtn.addActionListener(e -> {
            taskQueue.setPaused(false);
            pauseBtn.setEnabled(true);
        });
        buttonPanel.add(resumeBtn);

        JButton clearBtn = new JButton("清空已完成");
        clearBtn.addActionListener(e -> {
            taskQueue.clearCompletedRecords();
            refreshTable();
        });
        buttonPanel.add(clearBtn);

        JLabel hint = new JLabel("提示: 点击任意任务行可查看其对应的 AI 对话");
        hint.setFont(theme.displayFont(Font.ITALIC, 11f));
        hint.setForeground(Color.GRAY);
        buttonPanel.add(hint);

        add(buttonPanel, BorderLayout.SOUTH);

        // Per-row right-click: cancel queued / retry failed
        javax.swing.JPopupMenu rowMenu = new javax.swing.JPopupMenu();
        javax.swing.JMenuItem cancelItem = new javax.swing.JMenuItem("取消任务");
        cancelItem.addActionListener(e -> {
            TaskRecord r = selectedRecord();
            if (r != null && taskQueue.cancel(r.getId())) refreshTable();
        });
        rowMenu.add(cancelItem);
        javax.swing.JMenuItem retryItem = new javax.swing.JMenuItem("重试任务");
        retryItem.addActionListener(e -> {
            TaskRecord r = selectedRecord();
            if (r != null && taskQueue.retry(r.getId())) refreshTable();
        });
        rowMenu.add(retryItem);
        rowMenu.addSeparator();
        javax.swing.JMenuItem deleteItem = new javax.swing.JMenuItem("删除该行记录");
        deleteItem.addActionListener(e -> {
            TaskRecord r = selectedRecord();
            if (r != null && taskQueue.removeRecord(r.getId())) {
                refreshTable();
            } else if (r != null) {
                ToastNotification.show(this, "排队中/进行中的任务不能直接删除，请先取消",
                        ToastNotification.ToastType.WARNING, 3000);
            }
        });
        rowMenu.add(deleteItem);
        table.setComponentPopupMenu(rowMenu);

        // Row selection -> notify listener with the selected TaskRecord (containment: queue -> chat)
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                TaskRecord record = tableModel.getRecordAt(row);
                if (record != null && onTaskSelected != null) {
                    onTaskSelected.accept(record);
                }
            }
        });

        // Auto-refresh every 2 seconds — but skip the EDT table rebuild when
        // nothing can have changed: no unfinished tasks AND the same records in
        // the same statuses as last time (fingerprint). Active tasks still get
        // live progress updates; a quiet session costs one cheap list walk.
        refreshTimer = new Timer(2000, e -> {
            List<TaskRecord> records = taskQueue.getTaskRecords();
            int fingerprint = records.size();
            boolean anyActive = false;
            for (TaskRecord r : records) {
                TaskRecord.TaskStatus s = r.getStatus();
                fingerprint = fingerprint * 31 + s.hashCode();
                if (s != TaskRecord.TaskStatus.COMPLETED
                        && s != TaskRecord.TaskStatus.FAILED
                        && s != TaskRecord.TaskStatus.CANCELLED) {
                    anyActive = true;
                }
            }
            if (!anyActive && fingerprint == lastRecordsFingerprint) return;
            lastRecordsFingerprint = fingerprint;
            SwingUtilities.invokeLater(() -> tableModel.refresh(records));
        });
        refreshTimer.setRepeats(true);
        refreshTimer.start();
    }

    private int lastRecordsFingerprint = -1;

    private java.util.function.Consumer<TaskRecord> onTaskSelected;

    /** Set the callback fired when a task row is selected, so callers can show its associated AI conversation. */
    public void setOnTaskSelected(java.util.function.Consumer<TaskRecord> handler) {
        this.onTaskSelected = handler;
    }

    public void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            tableModel.refresh(taskQueue.getTaskRecords());
        });
    }

    public void shutdown() {
        if (refreshTimer != null) refreshTimer.stop();
    }

    private TaskRecord selectedRecord() {
        int row = table.getSelectedRow();
        if (row < 0) return null;
        int modelRow = table.convertRowIndexToModel(row);
        return tableModel.getRecordAt(modelRow);
    }

    // --- Table Model ---
    private static class TaskQueueTableModel extends AbstractTableModel {

        private static final String[] COLUMNS = {"#", "API路径", "分析模式", "状态", "开始时间", "耗时", "发现数"};
        private List<TaskRecord> records = new ArrayList<>();
        private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

        public void refresh(List<TaskRecord> newRecords) {
            this.records = new ArrayList<>(newRecords);
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() { return records.size(); }

        @Override
        public int getColumnCount() { return COLUMNS.length; }

        @Override
        public String getColumnName(int col) { return COLUMNS[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row < 0 || row >= records.size()) return null;
            TaskRecord r = records.get(row);
            return switch (col) {
                case 0 -> row + 1;
                case 1 -> r.getApiPath();
                case 2 -> r.getMode();
                case 3 -> r.getStatus().getDisplayName();
                case 4 -> r.getStartTime() > 0 ? sdf.format(new Date(r.getStartTime())) : "-";
                case 5 -> r.getElapsedDisplay();
                case 6 -> r.getStatus() == TaskRecord.TaskStatus.COMPLETED ? r.getFindingsCount() : "-";
                default -> null;
            };
        }

        public TaskRecord getRecordAt(int row) {
            if (row >= 0 && row < records.size()) return records.get(row);
            return null;
        }
    }

    // --- Status color renderer ---
    // Non-static (inner class) so it can read the enclosing panel's BurpTheme —
    // previously hard-coded pastel background+foreground pairs regardless of
    // Burp's light/dark theme, which looked like stickers glued onto a dark
    // table. Now just theme-aware foreground text, no background tint, matching
    // how ApiTablePanel's own status/risk columns are styled.
    private class StatusCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int col) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            setHorizontalAlignment(CENTER);
            setFont(theme.displayFont(Font.BOLD, 11f));

            // Show the failure reason on hover so users don't have to dig in logs.
            int modelRow = table.convertRowIndexToModel(row);
            if (modelRow >= 0 && table.getModel() instanceof TaskQueueTableModel m) {
                TaskRecord rec = m.getRecordAt(modelRow);
                if (rec != null && rec.getStatus() == TaskRecord.TaskStatus.FAILED
                        && rec.getError() != null && !rec.getError().isBlank()) {
                    setToolTipText("失败原因: " + rec.getError());
                } else {
                    setToolTipText(null);
                }
            }

            if (!isSelected && value != null) {
                String status = value.toString();
                setForeground(switch (status) {
                    case "排队中" -> theme.mutedText();
                    case "进行中" -> theme.statusPending();
                    case "已完成" -> theme.statusOk();
                    case "失败" -> theme.statusError();
                    case "已取消" -> theme.mutedText();
                    default -> table.getForeground();
                });
            }
            return this;
        }
    }
}
