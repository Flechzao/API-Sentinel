package com.flechazo.apisentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.swing.SwingUtils;
import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Deterministic replay of the Agent-completion call sequence (the exact
 * order AgentFacade.onAgentComplete + PipelineFacade.handlePipelineComplete
 * fire things) against a REAL AiAnalysisPanel on the EDT, asserting the
 * final UI state. Built to hunt the "report button gone / progress bar
 * color-only / test-case rows lost" field report: whatever this sequence
 * leaves wrong, the user sees.
 */
class AiAnalysisPanelCompletionFlowTest {

    private static MontoyaApi mockApi() {
        MontoyaApi api = mock(MontoyaApi.class);
        UserInterface ui = mock(UserInterface.class);
        when(api.userInterface()).thenReturn(ui);
        when(ui.currentTheme()).thenReturn(Theme.DARK);
        when(ui.currentDisplayFont()).thenReturn(new Font("SansSerif", Font.PLAIN, 12));
        when(ui.currentEditorFont()).thenReturn(new Font("Monospaced", Font.PLAIN, 12));
        SwingUtils swing = mock(SwingUtils.class);
        when(ui.swingUtils()).thenReturn(swing);
        return api;
    }

    private static Object field(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static void edt(Runnable r) throws Exception {
        SwingUtilities.invokeAndWait(r);
    }

    @Test
    void agentCompletionSequenceLeavesSettledUi() throws Exception {
        AiAnalysisPanel panel = new AiAnalysisPanel(mockApi());

        ApiEntry entry = new ApiEntry("GET", "/api/x");
        entry.setDomain("example.com");

        SuspectedVuln suspected = new SuspectedVuln("SQL注入", "疑似注入", "reason",
                "curl ...", "MEDIUM", "", "' OR 1=1--");
        FinalVerdict verdict = new FinalVerdict("MEDIUM", List.of(), List.of(suspected),
                "summary", "recs", 1234);
        PipelineResult result = new PipelineResult(null, null, List.of(), List.of(),
                verdict, null, null, null);

        // ── the exact order the completion path fires things ──
        // run start (AgentFacade.executeAgentForEntry)
        edt(() -> panel.resetPipelineProgress(true));
        // onAgentComplete cleanup
        edt(() -> panel.setAgentRunning(false));
        edt(panel::finishAgentProgress);
        // handlePipelineComplete: refreshFromRepository clears the table
        // selection -> presenter's selection listener fires showEntryHistory(null)
        edt(() -> panel.showEntryHistory(null));
        // handlePipelineComplete: verdict UI
        edt(() -> panel.showFinalVerdict(verdict, null, "AGENT", List.of()));
        // record persisted, then refreshHistoryForEntry re-renders it
        AnalysisRecord record = new AnalysisRecord("AGENT",
                new AnalysisResult(List.of(), "ok", AnalysisResult.RiskLevel.LOW, 10, 5, "", null))
                .withPipelineResult(result);
        entry.addAnalysisRecord(record);
        edt(() -> panel.refreshHistoryForEntry(entry));
        // report sinks
        edt(() -> panel.setJsonReportPath(Path.of("/tmp/x.json")));
        edt(() -> panel.setReportPath(Path.of("/tmp/x.html")));

        // ── final observable state ──
        JButton viewReportBtn = (JButton) field(panel, "viewReportBtn");
        JButton viewJsonBtn = (JButton) field(panel, "viewJsonBtn");
        JProgressBar bar = (JProgressBar) field(panel, "progressBar");
        JLabel statusLabel = (JLabel) field(panel, "statusLabel");

        assertThat(viewJsonBtn.isVisible()).as("JSON report button visible").isTrue();
        assertThat(viewReportBtn.isVisible()).as("HTML report button visible").isTrue();
        assertThat(bar.isVisible()).as("progress bar visible").isTrue();
        assertThat(bar.isIndeterminate()).as("progress bar determinate").isFalse();
        // Completion text is now a ProgressQuips line (not literally "完成");
        // assert it settled to some non-running text instead.
        assertThat(bar.getString()).as("progress bar settled").isNotBlank()
                .doesNotContain("运行中");
        assertThat(statusLabel.getText()).contains("完成");
    }

    /** Adversarial interleaving: the refresh-triggered selection wipe lands
     *  AFTER the verdict settle (possible because both are queued via
     *  invokeLater from the completion thread). The re-selection of the same
     *  entry re-renders from the persisted record — the panel must still end
     *  settled, not blanked. */
    @Test
    void lateSelectionWipeStillRecoversViaHistory() throws Exception {
        AiAnalysisPanel panel = new AiAnalysisPanel(mockApi());

        ApiEntry entry = new ApiEntry("GET", "/api/x");
        entry.setDomain("example.com");

        SuspectedVuln suspected = new SuspectedVuln("SQL注入", "疑似注入", "reason",
                "curl ...", "MEDIUM", "", "' OR 1=1--");
        FinalVerdict verdict = new FinalVerdict("MEDIUM", List.of(), List.of(suspected),
                "summary", "recs", 1234);
        PipelineResult result = new PipelineResult(null, null, List.of(), List.of(),
                verdict, null, null, null);

        edt(() -> panel.resetPipelineProgress(true));
        edt(() -> panel.setAgentRunning(false));
        edt(panel::finishAgentProgress);
        edt(() -> panel.showFinalVerdict(verdict, null, "AGENT", List.of()));
        AnalysisRecord record = new AnalysisRecord("AGENT",
                new AnalysisResult(List.of(), "ok", AnalysisResult.RiskLevel.LOW, 10, 5, "", null))
                .withPipelineResult(result);
        entry.addAnalysisRecord(record);
        edt(() -> panel.setReportPath(Path.of("/tmp/x.html")));
        // LATE wipe: selection cleared after everything, then the row is
        // re-selected -> showEntryHistory(entry) re-renders from history.
        edt(() -> panel.showEntryHistory(null));
        edt(() -> panel.showEntryHistory(entry));
        // showEntryHistory -> showAnalysisRecord -> showFinalVerdict each nest
        // another invokeLater; drain the EDT queue so they all land.
        edt(() -> {});
        edt(() -> {});

        JProgressBar bar = (JProgressBar) field(panel, "progressBar");
        JLabel statusLabel = (JLabel) field(panel, "statusLabel");
        assertThat(bar.isVisible()).as("progress bar re-shown from history").isTrue();
        assertThat(bar.isIndeterminate()).isFalse();
        assertThat(statusLabel.getText()).contains("完成");
    }

    /** Regression for the real field report (2026-08-20 POST /api/reset-token):
     *  an Agent run that never called analyze_traffic persists a record with
     *  result()==null but a full PipelineResult. Row re-selection re-renders
     *  via showAnalysisRecord — the old result()==null early-return blanked the
     *  panel to "等待分析" and left it stuck. It must render the verdict. */
    @Test
    void recordWithNullStage1ResultStillRendersVerdict() throws Exception {
        AiAnalysisPanel panel = new AiAnalysisPanel(mockApi());

        ApiEntry entry = new ApiEntry("POST", "/api/reset-token");
        entry.setDomain("example.com");

        SuspectedVuln suspected = new SuspectedVuln("可预测随机数", "Token 使用 java.util.Random",
                "reason", "curl ...", "MEDIUM", "", "");
        FinalVerdict verdict = new FinalVerdict("MEDIUM", List.of(), List.of(suspected),
                "summary", "recs", 148135);
        PipelineResult result = new PipelineResult(null, "// source", List.of(), List.of(),
                verdict, null, null, null);

        // record with NULL AnalysisResult (no analyze_traffic) + a PipelineResult
        AnalysisRecord record = new AnalysisRecord("AGENT",
                (com.flechazo.apisentinel.ai.analysis.AnalysisResult) null)
                .withPipelineResult(result);
        entry.addAnalysisRecord(record);

        edt(() -> panel.resetPipelineProgress(true));
        edt(() -> panel.setAgentRunning(false));
        // user re-selects the row -> showEntryHistory -> showAnalysisRecord
        edt(() -> panel.showEntryHistory(entry));
        edt(() -> {}); // drain nested invokeLater (showAnalysisRecord -> showFinalVerdict)
        edt(() -> {});

        JProgressBar bar = (JProgressBar) field(panel, "progressBar");
        JLabel statusLabel = (JLabel) field(panel, "statusLabel");
        JLabel riskLabel = (JLabel) field(panel, "riskLabel");
        assertThat(statusLabel.getText()).as("settled, not 等待分析").contains("完成");
        assertThat(riskLabel.getText()).as("risk rendered").isEqualTo("MEDIUM");
        assertThat(bar.isVisible()).isTrue();
        assertThat(bar.isIndeterminate()).isFalse();
    }

    /** Same sequence WITHOUT the selection-clear event (row stays selected
     *  through the refresh) — covers the other real-world interleaving. */
    @Test
    void agentCompletionSequenceWithoutSelectionClear() throws Exception {
        AiAnalysisPanel panel = new AiAnalysisPanel(mockApi());

        ApiEntry entry = new ApiEntry("GET", "/api/x");
        entry.setDomain("example.com");

        SuspectedVuln suspected = new SuspectedVuln("SQL注入", "疑似注入", "reason",
                "curl ...", "MEDIUM", "", "' OR 1=1--");
        FinalVerdict verdict = new FinalVerdict("MEDIUM", List.of(), List.of(suspected),
                "summary", "recs", 1234);
        PipelineResult result = new PipelineResult(null, null, List.of(), List.of(),
                verdict, null, null, null);

        edt(() -> panel.resetPipelineProgress(true));
        edt(() -> panel.setAgentRunning(false));
        edt(panel::finishAgentProgress);
        edt(() -> panel.showFinalVerdict(verdict, null, "AGENT", List.of()));
        AnalysisRecord record = new AnalysisRecord("AGENT",
                new AnalysisResult(List.of(), "ok", AnalysisResult.RiskLevel.LOW, 10, 5, "", null))
                .withPipelineResult(result);
        entry.addAnalysisRecord(record);
        edt(() -> panel.refreshHistoryForEntry(entry));
        edt(() -> panel.setJsonReportPath(Path.of("/tmp/x.json")));
        edt(() -> panel.setReportPath(Path.of("/tmp/x.html")));

        JButton viewReportBtn = (JButton) field(panel, "viewReportBtn");
        JProgressBar bar = (JProgressBar) field(panel, "progressBar");

        assertThat(viewReportBtn.isVisible()).as("HTML report button visible").isTrue();
        assertThat(bar.isVisible()).as("progress bar visible").isTrue();
        assertThat(bar.isIndeterminate()).as("progress bar determinate").isFalse();
        // Completion text is a ProgressQuips line now; assert settled, not running.
        assertThat(bar.getString()).isNotBlank().doesNotContain("运行中");
    }
}
