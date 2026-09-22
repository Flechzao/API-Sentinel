package com.flechazo.apisentinel.ai.agent.tool;

/**
 * Interface for updating individual security findings during chat follow-up conversations.
 *
 * <p>Allows the Agent to promote a "suspected" finding to "confirmed" (or dismiss it)
 * without re-running the full submit_report flow. This enables precise, incremental
 * updates to the findings table during follow-up verification conversations.
 *
 * <p>Implemented by {@code AiAnalysisPanel} which holds the current verdict state.
 */
public interface FindingUpdater {

    /**
     * Update a single finding's status.
     *
     * @param findingIndex 0-based index in the findings list (confirmed first, then suspected)
     * @param newStatus    "confirmed", "suspected", or "dismissed"
     * @param evidence     updated evidence text (null = keep existing)
     * @param payloadUsed  the payload that verified this finding (null = keep existing)
     * @param response     the response that confirmed this finding (null = keep existing)
     * @return true if the update was applied, false if the index was invalid
     */
    boolean updateFinding(int findingIndex, String newStatus,
                          String evidence, String payloadUsed, String response);

    /**
     * Get the current finding titles for the Agent to reference.
     *
     * @return array of finding descriptions (index → description)
     */
    String[] getFindingSummaries();
}
