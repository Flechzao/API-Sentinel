package com.flechazo.apisentinel.ai.budget;

/**
 * Budget enforcement mode.
 *
 * <ul>
 *   <li>{@link #ENFORCE} — block LLM calls when daily budget exceeded (default).</li>
 *   <li>{@link #MONITOR_ONLY} — record usage but never block. Use when the LLM
 *       provider has unlimited quota (e.g. internal models). Usage is still
 *       tracked and visible in UI/reports.</li>
 * </ul>
 */
public enum BudgetMode {
    ENFORCE,
    MONITOR_ONLY
}
