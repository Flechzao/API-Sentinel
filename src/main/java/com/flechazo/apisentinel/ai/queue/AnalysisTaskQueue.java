package com.flechazo.apisentinel.ai.queue;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnerabilityAnalyzer;
import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.event.AiAnalysisCompleteEvent;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 分析任务队列——轻量单次分析的自动调度引擎。含 Worker 线程池、重试、预算检查、
 * 任务记录淘汰（最近 500 条）。与 Agent/Pipeline 模式共享。
 */
public class AnalysisTaskQueue {

    private static final int MAX_RETRIES = 2;
    /** Cap on retained task records to bound memory in long sessions. */
    private static final int MAX_RECORDS = 500;

    private final BlockingQueue<AnalysisTask> queue = new LinkedBlockingQueue<>(200);
    private final ExecutorService workers;
    private final LlmProviderFactory providerFactory;
    private final TokenBudgetManager budgetManager;
    private final EventBus eventBus;
    private final LeveledLogger logger;
    /** P2-1: learned-rule engine for pre-LLM triage. When non-null, the
     *  worker loop checks learned rules BEFORE making an LLM call. A
     *  high-confidence rule match produces a SAFE verdict without
     *  spending any tokens — the LLM is only called for endpoints
     *  that don't match any learned rule. */
    private com.flechazo.apisentinel.ai.rules.LearnedRuleEngine learnedRuleEngine;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private volatile String activeProviderId = "ollama";

    // --- Task record tracking ---
    private final List<TaskRecord> taskRecords = new CopyOnWriteArrayList<>();
    private final Map<String, TaskRecord> taskRecordMap = new ConcurrentHashMap<>();
    private final Map<String, AnalysisTask> taskById = new ConcurrentHashMap<>();
    private final AtomicInteger taskIdCounter = new AtomicInteger(0);

    public AnalysisTaskQueue(LlmProviderFactory providerFactory,
                             TokenBudgetManager budgetManager,
                             EventBus eventBus,
                             LeveledLogger logger,
                             int workerCount) {
        this.providerFactory = providerFactory;
        this.budgetManager = budgetManager;
        this.eventBus = eventBus;
        this.logger = logger;
        this.workers = Executors.newFixedThreadPool(workerCount, r -> {
            Thread t = new Thread(r, "api-sentinel-ai-worker");
            t.setDaemon(true);
            return t;
        });

        for (int i = 0; i < workerCount; i++) {
            workers.submit(this::workerLoop);
        }
    }

    public boolean submit(AnalysisTask task) {
        if (!running.get()) return false;
        if (!budgetManager.canProceed()) {
            logger.warn("AI 分析被限制: 预算已耗尽");
            return false;
        }

        // Create and track a TaskRecord
        String recordId = String.valueOf(taskIdCounter.incrementAndGet());
        String modeName = task.analysisMode() != null ? task.analysisMode().getDisplayName() : "标准分析";
        TaskRecord record = new TaskRecord(recordId, task.entry().getApiPath(), modeName);
        taskRecords.add(record);
        taskRecordMap.put(task.entry().getApiPath() + "#" + recordId, record);

        boolean offered = queue.offer(task);
        if (!offered) {
            record.markFailed("队列已满");
        } else {
            taskById.put(recordId, task);
        }
        evictOldRecords();
        return offered;
    }

    /** Cancel a queued task by record id (no-op if already running/completed). */
    public boolean cancel(String recordId) {
        TaskRecord rec = findRecordById(recordId);
        if (rec == null) return false;
        if (rec.getStatus() == TaskRecord.TaskStatus.QUEUED) {
            rec.markCancelled();
            taskById.remove(recordId);
            return true;
        }
        return false;
    }

    /** Re-queue a previously-failed task by record id. */
    public boolean retry(String recordId) {
        TaskRecord rec = findRecordById(recordId);
        if (rec == null || rec.getStatus() != TaskRecord.TaskStatus.FAILED) return false;
        AnalysisTask task = taskById.get(recordId);
        if (task == null) return false;
        rec.requeue();
        return queue.offer(task);
    }

    /** Remove a single finished task record (COMPLETED/FAILED/CANCELLED) by
     *  id. Queued/in-progress records must be cancelled first via cancel() —
     *  this deliberately won't rip an active task out of the queue/table. */
    public boolean removeRecord(String recordId) {
        TaskRecord rec = findRecordById(recordId);
        if (rec == null) return false;
        TaskRecord.TaskStatus status = rec.getStatus();
        if (status == TaskRecord.TaskStatus.QUEUED || status == TaskRecord.TaskStatus.IN_PROGRESS) {
            return false;
        }
        taskRecords.remove(rec);
        taskById.remove(recordId);
        return true;
    }


    private TaskRecord findRecordById(String recordId) {
        if (recordId == null) return null;
        for (TaskRecord r : taskRecords) {
            if (recordId.equals(r.getId())) return r;
        }
        return null;
    }

    public void setActiveProvider(String providerId) {
        this.activeProviderId = providerId;
    }

    /** P2-1: set the learned-rule engine for pre-LLM triage. When set,
     *  the worker loop checks learned rules BEFORE making an LLM call.
     *  High-confidence rule matches produce a SAFE verdict without
     *  spending any tokens. */
    public void setLearnedRuleEngine(com.flechazo.apisentinel.ai.rules.LearnedRuleEngine engine) {
        this.learnedRuleEngine = engine;
    }

    public int getPendingCount() {
        return queue.size();
    }

    public void setPaused(boolean paused) {
        this.paused.set(paused);
    }

    public boolean isPaused() {
        return paused.get();
    }

    /**
     * Get all task records (for display in TaskQueuePanel).
     */
    public List<TaskRecord> getTaskRecords() {
        return new ArrayList<>(taskRecords);
    }

    /**
     * Clear completed (and failed) task records from the list.
     */
    public void clearCompletedRecords() {
        taskRecords.removeIf(r ->
                r.getStatus() == TaskRecord.TaskStatus.COMPLETED ||
                r.getStatus() == TaskRecord.TaskStatus.FAILED);
    }

    /**
     * Register an external task record (e.g. Pipeline analysis) for display in the queue panel.
     * Returns the record so the caller can update its status via markInProgress/markCompleted/markFailed.
     */
    public TaskRecord addExternalRecord(String apiPath, String mode) {
        String recordId = String.valueOf(taskIdCounter.incrementAndGet());
        TaskRecord record = new TaskRecord(recordId, apiPath, mode);
        record.markInProgress();
        taskRecords.add(record);
        evictOldRecords();
        return record;
    }

    /**
     * Bound the retained records list. Prefers evicting completed/failed records
     * (oldest first); only drops an in-flight record if none are finished.
     *
     * Single-pass snapshot + atomic {@code removeIf} — the old loop of
     * CopyOnWriteArrayList.remove(i) re-copied the whole array per removal,
     * i.e. O(n²) when trimming a large backlog.
     */
    private void evictOldRecords() {
        int excess = taskRecords.size() - MAX_RECORDS;
        if (excess <= 0) return;

        List<TaskRecord> snapshot = new ArrayList<>(taskRecords);
        Set<String> dropIds = new HashSet<>();
        int marked = 0;
        for (TaskRecord r : snapshot) {
            if (marked >= excess) break;
            TaskRecord.TaskStatus s = r.getStatus();
            if (s == TaskRecord.TaskStatus.COMPLETED || s == TaskRecord.TaskStatus.FAILED) {
                dropIds.add(r.getId());
                marked++;
            }
        }
        for (TaskRecord r : snapshot) {
            if (marked >= excess) break;
            if (!dropIds.contains(r.getId())) {
                dropIds.add(r.getId());
                marked++;
            }
        }

        taskRecords.removeIf(r -> dropIds.contains(r.getId()));
        // Also evict the bookkeeping-map entries (old code leaked them).
        for (TaskRecord r : snapshot) {
            if (dropIds.contains(r.getId())) {
                taskRecordMap.remove(r.getApiPath() + "#" + r.getId());
            }
        }
    }

    private TaskRecord findRecord(AnalysisTask task) {
        // Find the most recent QUEUED record for this API path
        for (int i = taskRecords.size() - 1; i >= 0; i--) {
            TaskRecord r = taskRecords.get(i);
            if (r.getApiPath().equals(task.entry().getApiPath())
                    && r.getStatus() == TaskRecord.TaskStatus.QUEUED) {
                return r;
            }
        }
        return null;
    }

    private void workerLoop() {
        while (running.get()) {
            AnalysisTask task = null;
            TaskRecord record = null;
            try {
                // Respect pause
                while (paused.get() && running.get()) {
                    Thread.sleep(500);
                }

                task = queue.poll(1, TimeUnit.SECONDS);
                if (task == null) continue;

                record = findRecord(task);
                if (record != null) {
                    if (record.getStatus() == TaskRecord.TaskStatus.CANCELLED) {
                        taskById.remove(record.getId());
                        continue;
                    }
                    record.markInProgress();
                }

                LlmProvider provider = providerFactory.get(activeProviderId);
                if (provider == null || !provider.isAvailable()) {
                    logger.warn("AI Provider '%s' 不可用，跳过分析", activeProviderId);
                    if (record != null) record.markFailed("Provider 不可用");
                    continue;
                }

                VulnerabilityAnalyzer analyzer = new VulnerabilityAnalyzer(provider, logger);
                String params = extractParameters(task.requestBody(), task.url());

                // P2-1: pre-LLM triage via learned rules. If a high-confidence
                // rule matches, produce a SAFE verdict WITHOUT calling the LLM.
                // This saves ~$0.05/endpoint for known-safe patterns (e.g.
                // "this API always returns 404 for non-existent IDs").
                AnalysisResult result = null;
                if (learnedRuleEngine != null && learnedRuleEngine.getRuleCount() > 0) {
                    try {
                        var matched = learnedRuleEngine.checkRules(
                                task.requestBody(), task.responseBody());
                        if (!matched.isEmpty()) {
                            // Only auto-SAFE when ALL matched rules say "safe"
                            // (some rules might be "always vulnerable" — those
                            // should still go to the LLM for full analysis).
                            boolean allSafe = matched.stream()
                                    .allMatch(r -> "SAFE".equalsIgnoreCase(r.getRiskLevel()));
                            if (allSafe) {
                                result = new AnalysisResult(
                                        List.of(),
                                        "Learned rule matched (safe): "
                                                + matched.stream().map(r -> r.getName())
                                                        .reduce((a, b) -> a + ", " + b).orElse(""),
                                        AnalysisResult.RiskLevel.NONE, 0, 0, "", null);
                                logger.info("[Queue] 跳过 LLM 调用（learned rule 命中 SAFE）: %s",
                                        task.entry().getApiPath());
                            }
                        }
                    } catch (Exception e) {
                        // Rule check failure is non-fatal — fall through to LLM.
                        logger.warn("[Queue] learned rule check 异常: %s", e.getMessage());
                    }
                }

                Exception failure = null;
                if (result == null) {
                // Retry transient failures (timeouts, network blips) inline so the
                // TaskRecord stays continuous. Budget-exhaustion is checked at
                // submit time and is not retried.
                for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
                    try {
                        if (attempt > 0) {
                            long backoff = Math.min(2000L * (1L << (attempt - 1)), 8000L);
                            Thread.sleep(backoff);
                            logger.info("AI 分析重试 #%d: %s", attempt, task.entry().getApiPath());
                        }
                        result = analyzer.analyze(
                                task.method(), task.url(), task.host(),
                                task.requestBody(), task.statusCode(),
                                task.responseBody(), task.entry().getApiPath(),
                                params, task.sourceCode(), ""
                        ).get(120, TimeUnit.SECONDS);
                        failure = null;
                        break;
                    } catch (TimeoutException te) {
                        failure = te;
                    } catch (Exception ex) {
                        failure = ex;
                    }
                }
                } // end if (result == null)

                if (result != null) {
                    budgetManager.recordUsage(activeProviderId, result.tokensUsed());
                    if (record != null) {
                        record.markCompleted(result.findings().size());
                    }
                    eventBus.publish(new AiAnalysisCompleteEvent(task.entry(), result, task.method()));
                    logger.info("AI 分析完成: %s [%s] %d findings, %d tokens",
                            task.entry().getApiPath(), result.overallRisk(),
                            result.findings().size(), result.tokensUsed());
                } else {
                    String errMsg = failure != null ? failure.getMessage() : "未知错误";
                    logger.error("AI 分析失败（已重试 %d 次）: %s", MAX_RETRIES, errMsg);
                    if (record != null) record.markFailed(errMsg);
                    eventBus.publish(new AiAnalysisCompleteEvent(task.entry(),
                            AnalysisResult.failed("分析失败（已重试 " + MAX_RETRIES + " 次）: " + errMsg),
                            task.method()));
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("AI Worker 异常: %s", e.getMessage());
                if (record != null) record.markFailed(e.getMessage());
                if (task != null) {
                    eventBus.publish(new AiAnalysisCompleteEvent(task.entry(),
                            AnalysisResult.failed("分析异常: " + e.getMessage())));
                }
            }
        }
    }

    private String extractParameters(String body, String url) {
        StringBuilder params = new StringBuilder();
        int queryIdx = url.indexOf('?');
        if (queryIdx > 0) {
            params.append("Query: ").append(url.substring(queryIdx + 1));
        }
        if (body != null && !body.isEmpty() && body.length() < 500) {
            if (params.length() > 0) params.append("; ");
            params.append("Body: ").append(body);
        }
        return params.toString();
    }

    public void shutdown() {
        running.set(false);
        workers.shutdownNow();
        try {
            workers.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
