package com.flechazo.apisentinel.ai.agent;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Goal state for the Agent auto-pilot's Controller-level cascade hunting
 * ("confirmed vuln A on one endpoint → auto-queue its sibling endpoints for
 * the same lightweight analysis"). Part of the cluster-hunting upgrade —
 * distilled from CCB's blocked-consecutive-turns circuit breaker (see
 * docs/THIRD-PARTY.md).
 *
 * <p>Guards so one confirmation against a large indexed repo cannot turn
 * into an unbounded analysis storm:
 * <ul>
 *   <li><b>Session budget</b> — at most {@link #MAX_TOTAL_CASCADE} cascaded
 *       endpoints queued across the whole session;</li>
 *   <li><b>Blocked breaker</b> — {@link #BLOCKED_STREAK_THRESHOLD} consecutive
 *       cascaded endpoints that produce ZERO new HIGH/MEDIUM findings trips
 *       the breaker; further cascades stop for the session. Any new finding
 *       resets the streak. This is the "quit while you're ahead — and while
 *       you're behind" discipline: a repo with no repeating flaw shouldn't be
 *       ground through endpoint by endpoint forever.</li>
 * </ul>
 *
 * <p>Thread-safety: AgentController touches this from the EventBus executor
 * (analysis-complete / cluster-hunt-trigger handlers) and the pending-queue
 * scheduler concurrently — all state is atomic.
 */
public final class GoalState {

    /** Consecutive fruitless cascaded analyses before the breaker trips. */
    public static final int BLOCKED_STREAK_THRESHOLD = 3;
    /** Total cascaded endpoints allowed per session. */
    public static final int MAX_TOTAL_CASCADE = 50;

    private final AtomicInteger totalQueued = new AtomicInteger(0);
    private final AtomicInteger blockedStreak = new AtomicInteger(0);
    private final AtomicBoolean blocked = new AtomicBoolean(false);

    /** True while cascading is allowed: not tripped and budget remaining. */
    public boolean shouldCascade() {
        return !blocked.get() && totalQueued.get() < MAX_TOTAL_CASCADE;
    }

    /**
     * Shrinks a requested batch to what the session budget still allows and
     * consumes it. Returns 0 (queue nothing) once blocked or exhausted.
     */
    public int grantQuota(int requested) {
        if (requested <= 0 || blocked.get()) return 0;
        while (true) {
            int current = totalQueued.get();
            int remaining = MAX_TOTAL_CASCADE - current;
            if (remaining <= 0) return 0;
            int granted = Math.min(requested, remaining);
            if (totalQueued.compareAndSet(current, current + granted)) {
                return granted;
            }
        }
    }

    /**
     * Records the outcome of one cascaded endpoint's analysis.
     *
     * @param foundNewVuln true when it produced at least one new HIGH/MEDIUM
     *                     finding — resets the blocked streak.
     * @return true iff this call just tripped the breaker (caller publishes
     *         the "cascade blocked" progress event exactly once).
     */
    public boolean recordCascadeOutcome(boolean foundNewVuln) {
        if (foundNewVuln) {
            blockedStreak.set(0);
            return false;
        }
        int streak = blockedStreak.incrementAndGet();
        if (streak >= BLOCKED_STREAK_THRESHOLD && blocked.compareAndSet(false, true)) {
            return true;
        }
        return false;
    }

    public boolean isBlocked() { return blocked.get(); }

    public int getTotalQueued() { return totalQueued.get(); }

    public int getBlockedStreak() { return blockedStreak.get(); }

    /** One-line status for logs / UI. */
    public String describe() {
        if (blocked.get()) {
            return String.format("级联已熔断（连续 %d 轮无新发现），本轮级联不再扩散",
                    BLOCKED_STREAK_THRESHOLD);
        }
        return String.format("级联状态: 已入队 %d/%d，连续无新发现 %d/%d",
                totalQueued.get(), MAX_TOTAL_CASCADE,
                blockedStreak.get(), BLOCKED_STREAK_THRESHOLD);
    }
}
