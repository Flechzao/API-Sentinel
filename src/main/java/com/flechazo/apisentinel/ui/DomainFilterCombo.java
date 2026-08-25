package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.repository.ApiRepository;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * A JComboBox that shows all unique domains from the repository,
 * with entry counts, and triggers domain filter changes.
 */
public class DomainFilterCombo extends JPanel {

    private static final String ALL_DOMAINS = "所有域名";

    private final JComboBox<String> comboBox;
    private final ApiRepository repository;
    private final BurpTheme theme;
    private final Consumer<String> onDomainChanged;

    // Map from display string to actual domain
    private final Map<String, String> displayToDomain = new LinkedHashMap<>();

    public DomainFilterCombo(ApiRepository repository, Consumer<String> onDomainChanged, BurpTheme theme) {
        this.repository = repository;
        this.onDomainChanged = onDomainChanged;
        this.theme = theme;

        setLayout(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);

        JLabel label = new JLabel("域名:");
        label.setFont(theme.displayFont(Font.BOLD, 12f));
        label.setForeground(new Color(80, 80, 80));
        add(label);

        comboBox = new JComboBox<>();
        comboBox.setFont(theme.displayFont(Font.PLAIN, 12f));
        comboBox.setPreferredSize(new Dimension(220, 24));
        comboBox.addActionListener(e -> {
            String selected = (String) comboBox.getSelectedItem();
            if (selected == null) return;
            String domain = displayToDomain.getOrDefault(selected, null);
            onDomainChanged.accept(domain);
        });
        add(comboBox);

        repository.addChangeListener(() -> SwingUtilities.invokeLater(this::refreshDomains));
        refreshDomains();
    }

    /**
     * Refresh the domain list from the repository.
     */
    public void refreshDomains() {
        List<ApiEntry> all = repository.findAll();

        // Count by domain
        Map<String, Integer> domainCounts = new TreeMap<>();
        for (ApiEntry entry : all) {
            String domain = entry.getDomain();
            if (domain != null && !domain.isEmpty()) {
                domainCounts.merge(domain, 1, Integer::sum);
            }
        }

        // Remember current selection
        String currentSelection = (String) comboBox.getSelectedItem();
        String currentDomain = displayToDomain.getOrDefault(currentSelection, null);

        displayToDomain.clear();
        comboBox.removeAllItems();

        // "All domains" option
        String allDisplay = ALL_DOMAINS + " (" + all.size() + ")";
        displayToDomain.put(allDisplay, null);
        comboBox.addItem(allDisplay);

        // Individual domains sorted by count (descending)
        List<Map.Entry<String, Integer>> sorted = new ArrayList<>(domainCounts.entrySet());
        sorted.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        for (Map.Entry<String, Integer> entry : sorted) {
            String display = entry.getKey() + " (" + entry.getValue() + ")";
            displayToDomain.put(display, entry.getKey());
            comboBox.addItem(display);
        }

        // Restore selection if domain still exists
        if (currentDomain != null) {
            for (Map.Entry<String, String> entry : displayToDomain.entrySet()) {
                if (currentDomain.equals(entry.getValue())) {
                    comboBox.setSelectedItem(entry.getKey());
                    return;
                }
            }
        }

        // Default to "all"
        comboBox.setSelectedIndex(0);
    }

    private void startAutoRefresh() {
        // Removed: now event-driven via repository.addChangeListener
    }

    public void shutdown() {
        // No timer to stop - event-driven now
    }
}
