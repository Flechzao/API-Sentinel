package com.flechazo.apisentinel.model;

import com.flechazo.apisentinel.repository.InMemoryApiRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The ⚙ analyzing badge is runtime-only display state: it must prefix
 * COL_STATE while a full analysis runs, disappear afterwards, never leak
 * onto other rows, and never survive into the persisted ApiStatus.
 */
class ApiEntryTableModelAnalyzingTest {

    private ApiEntryTableModel model;

    @BeforeEach
    void setUp() throws Exception {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(new ApiEntry("GET", "/api/a"));
        repo.add(new ApiEntry("POST", "/api/b"));
        model = new ApiEntryTableModel(repo);
        // The constructor refreshes via invokeLater; pump the EDT queue so
        // displayList is populated before assertions run.
        SwingUtilities.invokeAndWait(() -> {});
    }

    @Test
    void stateColumnShowsGearBadgeWhileAnalyzing() {
        int row = model.findRowByPath("/api/a");
        assertThat(row).isGreaterThanOrEqualTo(0);

        assertThat(model.getValueAt(row, ApiEntryTableModel.COL_STATE)).isEqualTo("未测试");

        model.markAnalyzing("/api/a");

        assertThat(model.getValueAt(row, ApiEntryTableModel.COL_STATE)).isEqualTo("⚙ 未测试");
        assertThat(model.isAnalyzing("/api/a")).isTrue();
    }

    @Test
    void clearAnalyzingRestoresPlainState() {
        model.markAnalyzing("/api/b");
        model.clearAnalyzing("/api/b");

        int row = model.findRowByPath("/api/b");
        assertThat(model.getValueAt(row, ApiEntryTableModel.COL_STATE)).isEqualTo("未测试");
        assertThat(model.isAnalyzing("/api/b")).isFalse();
    }

    @Test
    void badgeDoesNotLeakOntoSiblingRows() {
        model.markAnalyzing("/api/a");

        int rowB = model.findRowByPath("/api/b");
        assertThat(model.getValueAt(rowB, ApiEntryTableModel.COL_STATE)).isEqualTo("未测试");
        assertThat(model.isAnalyzing("/api/b")).isFalse();
    }

    @Test
    void nullAndUnknownPathsAreSafeNoOps() {
        model.markAnalyzing(null);
        model.clearAnalyzing(null);
        model.clearAnalyzing("/does/not/exist");

        assertThat(model.isAnalyzing("/does/not/exist")).isFalse();
    }

    @Test
    void repeatedMarkThenSingleClearEndsAnalyzing() {
        model.markAnalyzing("/api/a");
        model.markAnalyzing("/api/a");
        model.clearAnalyzing("/api/a");

        assertThat(model.isAnalyzing("/api/a")).isFalse();
    }

    @Test
    void badgeNeverChangesThePersistedStatus() {
        model.markAnalyzing("/api/a");

        int row = model.findRowByPath("/api/a");
        ApiEntry entry = model.getEntryAt(row);

        // The ⚙ is display-only — the entry's real status is untouched, so a
        // cancelled analysis can never corrupt the user's test state.
        assertThat(entry.getStatus()).isEqualTo(ApiStatus.UNTESTED);
    }
}
