package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.queue.AnalysisTask;
import com.flechazo.apisentinel.ai.queue.AnalysisTask.AnalysisMode;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.ai.rules.LearnedRuleEngine;
import com.flechazo.apisentinel.event.AiAnalysisCompleteEvent;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiEntryTableModel;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.flechazo.apisentinel.testgen.TestCaseService;
import com.flechazo.apisentinel.testgen.model.TestCase;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Batch concurrency control (select N rows -> "AI 分析") + the lighter-weight
 * "simple queue" analysis path (onAiAnalyze / AnalysisTaskQueue / EventBus)
 * that's neither Pipeline nor Agent mode.
 *
 * Deliberately doesn't know Pipeline/Agent/Agent-mode-routing exists — it
 * only knows "how to run one entry" via the injected EntryExecutor, which
 * AiPresenter wires to its routeAndExecute (the one place that decides
 * Pipeline vs Agent). This keeps PipelineFacade/AgentFacade from needing to
 * know batch state exists at all.
 */
class BatchOrchestrator {

    @FunctionalInterface
    interface EntryExecutor {
        void execute(ApiEntry entry, LlmProvider provider, Runnable onDone);
    }

    private final ApiEntryTableModel tableModel;
    private final AnalysisTaskQueue analysisQueue;
    private final LlmProviderFactory providerFactory;
    private final AnalysisContextLookup contextLookup;
    private final LeveledLogger logger;
    private final EntryExecutor entryExecutor;
    /** Repository for detached-entry attribution (cascade siblings); may be
     *  null in tests — the attribution step simply doesn't run. */
    private final ApiRepository repository;

    private ApiSentinelTab view;
    private LearnedRuleEngine learnedRuleEngine;

    private final AtomicInteger batchTotal = new AtomicInteger(0);
    private final AtomicInteger batchDone = new AtomicInteger(0);
    /** Cap concurrent in-flight pipeline/agent analyses so a 50-entry batch
     * doesn't launch 50 simultaneous LLM call streams. */
    private final java.util.concurrent.Semaphore batchSlots = new java.util.concurrent.Semaphore(2);
    private final java.util.concurrent.ConcurrentLinkedDeque<ApiEntry> batchPending = new java.util.concurrent.ConcurrentLinkedDeque<>();
    private LlmProvider batchProvider;

    BatchOrchestrator(ApiEntryTableModel tableModel, AnalysisTaskQueue analysisQueue,
                      LlmProviderFactory providerFactory, AnalysisContextLookup contextLookup,
                      LeveledLogger logger, EntryExecutor entryExecutor) {
        this(tableModel, analysisQueue, providerFactory, contextLookup, logger, entryExecutor, null);
    }

    BatchOrchestrator(ApiEntryTableModel tableModel, AnalysisTaskQueue analysisQueue,
                      LlmProviderFactory providerFactory, AnalysisContextLookup contextLookup,
                      LeveledLogger logger, EntryExecutor entryExecutor, ApiRepository repository) {
        this.tableModel = tableModel;
        this.analysisQueue = analysisQueue;
        this.providerFactory = providerFactory;
        this.contextLookup = contextLookup;
        this.logger = logger;
        this.entryExecutor = entryExecutor;
        this.repository = repository;
    }

    void setView(ApiSentinelTab view) { this.view = view; }
    void setLearnedRuleEngine(LearnedRuleEngine engine) { this.learnedRuleEngine = engine; }

    // ======================== Simple queue analysis (TRAFFIC_ONLY etc.) ========================

    public void onAiAnalyze(int[] selectedRows) {
        onAiAnalyze(selectedRows, AnalysisMode.TRAFFIC_ONLY);
    }

    public void onAiAnalyze(int[] selectedRows, AnalysisMode mode) {
        if (selectedRows == null || selectedRows.length == 0) {
            logger.warn("请先选择要分析的API");
            return;
        }
        if (view != null) {
            view.getAiAnalysisPanel().setAnalyzing();
            // Chat no longer occupies detailTabs slot 0 — the analysis
            // progress lives on the analysis-result panel.
            view.switchToAnalysisResult();
        }

        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry == null) continue;

            String sourceCode = "";
            if (mode == AnalysisMode.WITH_CODE || mode == AnalysisMode.COMPREHENSIVE) {
                sourceCode = contextLookup.lookupSourceCode(entry.getApiPath(), entry.getDomain());
                if (sourceCode.isEmpty()) {
                    logger.warn("未找到 %s 的关联源码（请先在「代码仓库」Tab 索引仓库）", entry.getApiPath());
                } else {
                    logger.info("已关联源码: %s", entry.getApiPath());
                }
            }

            String historyContext = "";
            if (mode == AnalysisMode.WITH_HISTORY || mode == AnalysisMode.COMPREHENSIVE) {
                historyContext = contextLookup.gatherHistoryContext(entry);
            }

            String realRequest = entry.getLastRawRequest();
            String realResponse = entry.getLastRawResponse();
            String effectiveUrl = entry.getLastUrl().isEmpty() ? entry.getApiPath() : entry.getLastUrl();
            int effectiveStatusCode = entry.getLastStatusCode() > 0 ? entry.getLastStatusCode() : 0;

            String enrichedRequest;
            String enrichedResponse;

            if (entry.hasTrafficData()) {
                enrichedRequest = realRequest;
                enrichedResponse = realResponse;
                if (!historyContext.isEmpty()) {
                    enrichedResponse += "\n\n## Historical Traffic Patterns\n" + historyContext;
                }
            } else {
                enrichedRequest = entry.getHttpMethod() + " " + entry.getApiPath();
                enrichedResponse = "";
                if (!historyContext.isEmpty()) {
                    enrichedResponse = "## Historical Traffic Patterns\n" + historyContext;
                }
            }

            AnalysisTask task = new AnalysisTask(
                    entry, entry.getHttpMethod(), effectiveUrl,
                    entry.getDomain(), enrichedRequest, effectiveStatusCode, enrichedResponse,
                    sourceCode, AnalysisTask.AnalysisScope.STANDARD, mode);

            if (!analysisQueue.submit(task)) {
                logger.warn("AI 分析队列已满或预算耗尽");
            }
        }
    }

    void onAiAnalysisComplete(AiAnalysisCompleteEvent event) {
        ApiEntry entry = event.entry();
        AnalysisResult result = event.result();

        AnalysisRecord record = new AnalysisRecord("TRAFFIC_ONLY", result);
        entry.addAnalysisRecord(record);
        tableModel.markRepositoryDirty();

        // Detached entries (cascade siblings synthesized by AgentController)
        // with real HIGH/MEDIUM findings get their own table row — the vuln
        // must land on the endpoint it was found on, not stay invisible.
        // Fruitless siblings stay out of the table (no noise).
        if (repository != null && result.isSuccess()
                && hasHighMediumRisk(result)
                && repository.findByPath(entry.getApiPath()).isEmpty()) {
            entry.updateStatus(ApiStatus.VULNERABLE, null,
                    "级联狩猎发现 " + result.findings().size() + " 个问题（高危/中危 "
                            + countHighMedium(result) + "）");
            repository.add(entry);
        }

        if (view != null) {
            view.getAiAnalysisPanel().updateResult(result);
            view.getAiAnalysisPanel().refreshHistoryForEntry(entry);
        }
        incrementBatchProgress();

        if (result.isSuccess() && !result.findings().isEmpty()) {
            // Risk and findings shown in dedicated table columns — note is user's space
            tableModel.refreshFromRepository();

            triggerTestCaseGeneration(entry, record);
            PipelineFacade.showHighRiskAlert(view, entry, result.overallRisk() == AnalysisResult.RiskLevel.HIGH ? "HIGH" : "");

            if (learnedRuleEngine != null) {
                learnedRuleEngine.learnFromAnalysis(entry.getApiPath(), result);
            }
        }
    }

    private static boolean hasHighMediumRisk(AnalysisResult result) {
        return countHighMedium(result) > 0;
    }

    private static int countHighMedium(AnalysisResult result) {
        int n = 0;
        for (var f : result.findings()) {
            if ("HIGH".equalsIgnoreCase(f.risk()) || "MEDIUM".equalsIgnoreCase(f.risk())) n++;
        }
        return n;
    }

    private void triggerTestCaseGeneration(ApiEntry entry, AnalysisRecord record) {
        com.flechazo.apisentinel.util.SharedTaskPool.submitInteractive(() -> {
            try {
                LlmProvider provider = providerFactory.getFirstAvailable();
                if (provider == null) return;

                TestCaseService testCaseService = new TestCaseService(provider, logger);
                List<TestCase> cases = testCaseService.generate(
                        entry.getHttpMethod(), entry.getApiPath(),
                        entry.getDomain(), "", ""
                ).get(60, TimeUnit.SECONDS);

                if (!cases.isEmpty()) {
                    AnalysisRecord updated = record.withTestCases(cases);
                    entry.updateLatestAnalysisRecord(updated);
                    logger.info("自动生成 %d 个测试用例: %s", cases.size(), entry.getApiPath());

                    if (view != null) {
                        SwingUtilities.invokeLater(() -> {
                            // Entry-switch guard: the Repeater panel is shared
                            // and may now show a DIFFERENT entry than the one
                            // these cases were generated for — don't clobber it.
                            // (The record update above is entry-scoped and safe.)
                            if (view.getRepeaterPanel().isShowingEntry(entry.getApiPath())) {
                                view.getRepeaterPanel().setSchemeFromUrl(entry.getLastUrl());
                                view.getRepeaterPanel().loadTestCases(cases, entry.getDomain());
                            }
                            view.getAiAnalysisPanel().refreshHistoryForEntry(entry);
                        });
                    }
                }
            } catch (Exception e) {
                logger.debug("测试用例自动生成失败: %s", e.getMessage());
            }
        });
    }

    // ======================== Batch Pipeline/Agent concurrency ========================

    public void onFullPipelineAnalyze(int[] selectedRows) {
        onFullPipelineAnalyze(selectedRows, AnalysisMode.TRAFFIC_ONLY);
    }

    public void onFullPipelineAnalyze(int[] selectedRows, AnalysisMode mode) {
        if (selectedRows == null || selectedRows.length == 0) {
            logger.warn("请先选择要分析的API");
            return;
        }

        LlmProvider provider = providerFactory.getFirstAvailable();
        if (provider == null) {
            logger.error("Pipeline 启动失败: 无可用的 AI Provider");
            if (view != null) view.getAiAnalysisPanel().showPipelineError("无可用的 AI Provider，请在设置中配置。");
            return;
        }

        // Pre-batch guard: confirm before launching a large batch so the user
        // doesn't accidentally overwhelm the LLM provider (and burn budget).
        if (selectedRows.length > 5 && view != null) {
            int estTokens = selectedRows.length * 5000;
            boolean goAhead = ThemedDialogs.confirm(view,
                    String.format("即将分析 %d 个 API。\n预计消耗约 %d tokens（粗估），且会并发发起 LLM 请求。\n是否继续？",
                            selectedRows.length, estTokens),
                    "批量分析确认");
            if (!goAhead) return;
        }

        if (view != null) {
            view.getAiAnalysisPanel().resetPipelineProgress();
            // Chat no longer occupies detailTabs slot 0 — the progress bar
            // lives on the analysis-result panel (the conversation, including
            // live step cards, is in the floating chat window).
            view.switchToAnalysisResult();
            // Single-entry run: keep the analyzed row in sight — with large
            // tables users otherwise lose track of which endpoint the ⚙ badge
            // (and the progress) belongs to. scrollRectToVisible needs the EDT.
            if (selectedRows.length == 1) {
                SwingUtilities.invokeLater(() ->
                        view.getTablePanel().selectAndScrollTo(selectedRows[0]));
            }
        }
        // Initialize batch progress counters
        batchTotal.set(selectedRows.length);
        batchDone.set(0);
        if (view != null) view.getAiAnalysisPanel().setBatchProgress(0, selectedRows.length);

        // Queue entries and launch up to batchSlots concurrently; the rest are
        // launched as slots free on completion.
        batchProvider = provider;
        batchPending.clear();
        for (int row : selectedRows) {
            ApiEntry entry = tableModel.getEntryAt(row);
            if (entry != null) batchPending.add(entry);
        }
        drainBatch();
    }

    private void drainBatch() {
        while (batchSlots.tryAcquire()) {
            ApiEntry entry = batchPending.poll();
            if (entry == null) {
                batchSlots.release();
                return;
            }
            final ApiEntry toRun = entry;
            SwingUtilities.invokeLater(() -> entryExecutor.execute(toRun, batchProvider,
                    () -> { incrementBatchProgress(); onBatchEntryFinished(); }));
        }
    }

    private void onBatchEntryFinished() {
        batchSlots.release();
        drainBatch();
    }

    private void incrementBatchProgress() {
        int done = batchDone.incrementAndGet();
        int total = batchTotal.get();
        if (view != null && total > 1) {
            SwingUtilities.invokeLater(() -> view.getAiAnalysisPanel().setBatchProgress(done, total));
        }
    }
}
