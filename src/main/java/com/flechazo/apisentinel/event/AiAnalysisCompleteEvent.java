package com.flechazo.apisentinel.event;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.model.ApiEntry;

/**
 * @param method the HTTP method of the request that was analyzed (used by the
 *               agent controller for method-scoped deduplication); may be empty
 *               for analyses not initiated via the agent path.
 */
public record AiAnalysisCompleteEvent(
    ApiEntry entry,
    AnalysisResult result,
    String method
) {
    /** Backward-compatible constructor (method unknown). */
    public AiAnalysisCompleteEvent(ApiEntry entry, AnalysisResult result) {
        this(entry, result, "");
    }
}
