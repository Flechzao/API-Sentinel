package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.config.CodeRepo;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class CodeRepoPanel extends JPanel {

    private final DefaultTableModel tableModel;
    private final JTable repoTable;
    private final JLabel statusLabel;
    private final List<CodeRepo> repos = new ArrayList<>();

    private Consumer<CodeRepo> onIndexRepo;
    private Consumer<List<CodeRepo>> onIndexAll;
    private Consumer<List<CodeRepo>> onReposChanged;
    private final BurpTheme theme;

    public CodeRepoPanel(List<CodeRepo> initialRepos,
                         Consumer<CodeRepo> onIndexRepo,
                         Consumer<List<CodeRepo>> onIndexAll,
                         Consumer<List<CodeRepo>> onReposChanged,
                         BurpTheme theme) {
        this.onIndexRepo = onIndexRepo;
        this.onIndexAll = onIndexAll;
        this.onReposChanged = onReposChanged;
        this.theme = theme;
        if (initialRepos != null) repos.addAll(initialRepos);

        setLayout(new BorderLayout(0, 4));

        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JLabel title = new JLabel(I18n.get("repo_mgmt"));
        title.setFont(theme.displayFont(Font.BOLD, 14f));
        header.add(title);
        JLabel frameworkLabel = new JLabel("(Spring / Flask / FastAPI / Django / Express / Koa)");
        frameworkLabel.setFont(theme.displayFont(Font.ITALIC, 12f));
        frameworkLabel.setForeground(theme.mutedText());
        header.add(frameworkLabel);
        add(header, BorderLayout.NORTH);

        tableModel = new DefaultTableModel(new String[]{"名称", "路径", "关联域名", "路由数", "状态"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        repoTable = new JTable(tableModel);
        repoTable.setRowHeight(24);
        repoTable.getColumnModel().getColumn(0).setPreferredWidth(100);
        repoTable.getColumnModel().getColumn(0).setMaxWidth(150);
        repoTable.getColumnModel().getColumn(1).setPreferredWidth(250);
        repoTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        repoTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        repoTable.getColumnModel().getColumn(3).setMaxWidth(80);
        repoTable.getColumnModel().getColumn(4).setPreferredWidth(70);
        repoTable.getColumnModel().getColumn(4).setMaxWidth(90);
        refreshTable();
        add(new JScrollPane(repoTable), BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        statusLabel = new JLabel(I18n.get("status_ready"));
        statusLabel.setFont(theme.displayFont(Font.PLAIN, 12f));
        statusLabel.setForeground(theme.mutedText());

        JButton addBtn = new JButton(I18n.get("repo_add"));
        addBtn.addActionListener(e -> showAddDialog());
        btnPanel.add(addBtn);

        JButton editBtn = new JButton(I18n.get("repo_edit"));
        editBtn.addActionListener(e -> editSelected());
        btnPanel.add(editBtn);

        JButton removeBtn = new JButton(I18n.get("repo_remove"));
        removeBtn.addActionListener(e -> removeSelected());
        btnPanel.add(removeBtn);

        btnPanel.add(Box.createHorizontalStrut(12));

        JButton indexOneBtn = new JButton(I18n.get("repo_index_selected"));
        indexOneBtn.addActionListener(e -> indexSelected());
        btnPanel.add(indexOneBtn);

        JButton indexAllBtn = new JButton(I18n.get("repo_index_all"));
        indexAllBtn.setForeground(theme.statusOk());
        indexAllBtn.addActionListener(e -> {
            if (onIndexAll != null && !repos.isEmpty()) {
                statusLabel.setText("正在索引所有仓库...");
                onIndexAll.accept(new ArrayList<>(repos));
            }
        });
        btnPanel.add(indexAllBtn);

        btnPanel.add(Box.createHorizontalStrut(12));
        btnPanel.add(statusLabel);

        add(btnPanel, BorderLayout.SOUTH);
    }

    private void showAddDialog() {
        showRepoDialog(null);
    }

    private void editSelected() {
        int row = repoTable.getSelectedRow();
        if (row < 0 || row >= repos.size()) return;
        showRepoDialog(repos.get(row));
    }

    private void showRepoDialog(CodeRepo existing) {
        JTextField nameField = new JTextField(existing != null ? existing.getName() : "", 20);
        JTextField pathField = new JTextField(existing != null ? existing.getPath() : "", 35);
        JTextField domainsField = new JTextField(
                existing != null ? String.join(", ", existing.getDomains()) : "", 35);

        JButton browseBtn = new JButton(I18n.get("repo_browse"));
        browseBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                pathField.setText(chooser.getSelectedFile().getAbsolutePath());
                if (nameField.getText().isEmpty()) {
                    nameField.setText(chooser.getSelectedFile().getName());
                }
            }
        });

        JPanel pathRow = new JPanel(new BorderLayout(4, 0));
        pathRow.add(pathField, BorderLayout.CENTER);
        pathRow.add(browseBtn, BorderLayout.EAST);

        JPanel panel = new JPanel(new GridLayout(3, 2, 4, 6));
        panel.add(new JLabel("名称:"));
        panel.add(nameField);
        panel.add(new JLabel("路径:"));
        panel.add(pathRow);
        panel.add(new JLabel("关联域名/IP (逗号分隔):"));
        panel.add(domainsField);

        String title = existing != null ? I18n.get("repo_dialog_edit") : I18n.get("repo_add");
        int result = JOptionPane.showConfirmDialog(this, panel, title, JOptionPane.OK_CANCEL_OPTION);
        if (result != JOptionPane.OK_OPTION) return;

        String name = nameField.getText().trim();
        String path = pathField.getText().trim();
        if (name.isEmpty() || path.isEmpty()) return;

        List<String> domains = Arrays.stream(domainsField.getText().split("[,;，；]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        if (existing != null) {
            existing.setName(name);
            existing.setPath(path);
            existing.setDomains(domains);
        } else {
            repos.add(new CodeRepo(name, path, domains));
        }
        refreshTable();
        notifyReposChanged();
    }

    private void removeSelected() {
        int[] selected = repoTable.getSelectedRows();
        if (selected.length == 0) return;
        for (int i = selected.length - 1; i >= 0; i--) {
            if (selected[i] >= 0 && selected[i] < repos.size()) {
                repos.remove(selected[i]);
            }
        }
        refreshTable();
        notifyReposChanged();
    }

    private void indexSelected() {
        int row = repoTable.getSelectedRow();
        if (row < 0 || row >= repos.size()) return;
        if (onIndexRepo != null) {
            statusLabel.setText("正在索引: " + repos.get(row).getName() + "...");
            onIndexRepo.accept(repos.get(row));
        }
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (CodeRepo repo : repos) {
            tableModel.addRow(new Object[]{
                    repo.getName(),
                    repo.getPath(),
                    String.join(", ", repo.getDomains()),
                    repo.isIndexed() ? repo.getRouteCount() : "-",
                    repo.isIndexed() ? I18n.get("repo_indexed") : I18n.get("repo_not_indexed")
            });
        }
    }

    private void notifyReposChanged() {
        if (onReposChanged != null) onReposChanged.accept(new ArrayList<>(repos));
    }

    public void updateRepoStatus(String repoName, int routeCount) {
        SwingUtilities.invokeLater(() -> {
            for (CodeRepo repo : repos) {
                if (repo.getName().equals(repoName)) {
                    repo.setIndexed(true);
                    repo.setRouteCount(routeCount);
                    break;
                }
            }
            refreshTable();
            int total = repos.stream().filter(CodeRepo::isIndexed).mapToInt(CodeRepo::getRouteCount).sum();
            statusLabel.setText("索引完成 (" + total + " 条路由)");
        });
    }

    public void setIndexError(String error) {
        SwingUtilities.invokeLater(() -> statusLabel.setText("索引失败: " + error));
    }

    public List<CodeRepo> getRepos() {
        return new ArrayList<>(repos);
    }
}
