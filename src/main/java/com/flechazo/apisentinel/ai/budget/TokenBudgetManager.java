package com.flechazo.apisentinel.ai.budget;

import java.time.LocalDate;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tracks daily token usage against a budget. The date and the counter are held
 * together in an immutable {@link DayBucket} swapped via CAS, so the new-day
 * reset and the usage accounting are atomic.
 *
 * <p>Supports two enforcement modes:
 * <ul>
 *   <li>{@link BudgetMode#ENFORCE} — block LLM calls when daily budget is
 *       exceeded (default, original behavior).</li>
 *   <li>{@link BudgetMode#MONITOR_ONLY} — record usage but never block;
 *       Agent can see how much it spent but calls always proceed. Use this
 *       when the LLM provider has unlimited quota (internal models).</li>
 * </ul>
 */
public class TokenBudgetManager {

    private volatile int dailyBudgetTokens;
    private volatile int perRequestMaxTokens;
    private volatile BudgetMode budgetMode = BudgetMode.MONITOR_ONLY;
    private final AtomicReference<DayBucket> bucket = new AtomicReference<>(
            new DayBucket(LocalDate.now(), 0));

    public TokenBudgetManager() {
        this.dailyBudgetTokens = 500_000;
        this.perRequestMaxTokens = 50_000;
    }

    public TokenBudgetManager(int dailyBudgetTokens, int perRequestMaxTokens) {
        this.dailyBudgetTokens = dailyBudgetTokens;
        this.perRequestMaxTokens = perRequestMaxTokens;
    }

    /**
     * Returns the current bucket, atomically resetting it when the calendar day
     * has rolled over.
     */
    private DayBucket current() {
        LocalDate today = LocalDate.now();
        while (true) {
            DayBucket b = bucket.get();
            if (b.date.equals(today)) return b;
            DayBucket fresh = new DayBucket(today, 0);
            if (bucket.compareAndSet(b, fresh)) return fresh;
        }
    }

    public boolean canProceed() {
        if (budgetMode == BudgetMode.MONITOR_ONLY) return true;
        return current().used < dailyBudgetTokens;
    }

    public boolean canProceed(int estimatedTokens) {
        if (budgetMode == BudgetMode.MONITOR_ONLY) return true;
        if (estimatedTokens > perRequestMaxTokens) return false;
        while (true) {
            DayBucket b = current();
            if ((long) b.used + estimatedTokens > dailyBudgetTokens) return false;
            DayBucket next = new DayBucket(b.date, b.used + estimatedTokens);
            if (bucket.compareAndSet(b, next)) return true;
        }
    }

    public void recordUsage(String provider, int tokensUsed) {
        if (tokensUsed <= 0) return;
        while (true) {
            DayBucket b = current();
            DayBucket next = new DayBucket(b.date, b.used + tokensUsed);
            if (bucket.compareAndSet(b, next)) return;
        }
    }

    public int getTodayUsed() {
        return current().used;
    }

    public int getDailyBudget() {
        return dailyBudgetTokens;
    }

    public double getUsagePercent() {
        if (dailyBudgetTokens <= 0) return 0;
        return (double) getTodayUsed() / dailyBudgetTokens * 100;
    }

    public void setDailyBudget(int tokens) {
        this.dailyBudgetTokens = tokens;
    }

    public void setPerRequestMax(int tokens) {
        this.perRequestMaxTokens = tokens;
    }

    public BudgetMode getBudgetMode() {
        return budgetMode;
    }

    public void setBudgetMode(BudgetMode mode) {
        this.budgetMode = mode;
    }

    private record DayBucket(LocalDate date, int used) {}
}
