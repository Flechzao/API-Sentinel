package com.flechazo.apisentinel.ai.budget;

import java.time.LocalDate;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tracks daily token usage against a budget. The date and the counter are held
 * together in an immutable {@link DayBucket} swapped via CAS, so the new-day
 * reset and the usage accounting are atomic — previously they were split across
 * a separate AtomicInteger and AtomicReference, allowing the daily reset to
 * zero out tokens that had just been recorded (TOCTOU) and the budget check to
 * pass for concurrent callers whose combined usage exceeded the budget.
 */
public class TokenBudgetManager {

    private volatile int dailyBudgetTokens;
    private volatile int perRequestMaxTokens;
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
            // New day: swap the whole bucket (date + counter together)
            DayBucket fresh = new DayBucket(today, 0);
            if (bucket.compareAndSet(b, fresh)) return fresh;
            // Lost the race; re-read (another thread already reset, or day advanced)
        }
    }

    public boolean canProceed() {
        return current().used < dailyBudgetTokens;
    }

    public boolean canProceed(int estimatedTokens) {
        if (estimatedTokens > perRequestMaxTokens) return false;
        // CAS loop: atomically verify headroom and reserve the tokens so two
        // concurrent callers can't both pass while exceeding the budget.
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

    private record DayBucket(LocalDate date, int used) {}
}
