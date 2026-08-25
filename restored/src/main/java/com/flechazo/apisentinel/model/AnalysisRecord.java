package com.flechazo.apisentinel.model;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.flechazo.apisentinel.ui.TimelineEvent;

import java.util.List;
import java.util.UUID;

/**
 * Immutable record of one AI analysis run for an API entry.
 * Stores analysis result + generated test cases + optional pipeline result
 * + the call-chain timeline (so the 调用链 view can be re-rendered later).
 */
public record AnalysisRecord(
    String id,
    long timestamp,
    String mode,
    AnalysisResult result,
    List<TestCase> testCases,
    PipelineResult pipelineResult,
    List<TimelineEvent> timeline
) {
    /** Legacy constructor (no pipeline result, no timeline). */
    public AnalysisRecord(String mode, AnalysisResult result) {
        this(UUID.randomUUID().toString().substring(0, 8),
             System.currentTimeMillis(),
             mode,
             result,
             List.of(),
             null,
             List.of());
    }

    public AnalysisRecord withTestCases(List<TestCase> cases) {
        return new AnalysisRecord(id, timestamp, mode, result, cases, pipelineResult, timeline);
    }

    public AnalysisRecord withPipelineResult(PipelineResult pipeline) {
        return new AnalysisRecord(id, timestamp, mode, result, testCases, pipeline, timeline);
    }

    public AnalysisRecord withTimeline(List<TimelineEvent> events) {
        return new AnalysisRecord(id, timestamp, mode, result, testCases, pipelineResult,
                events != null ? events : List.of());
    }

    public boolean hasPipelineResult() {
        return pipelineResult != null;
    }
}
