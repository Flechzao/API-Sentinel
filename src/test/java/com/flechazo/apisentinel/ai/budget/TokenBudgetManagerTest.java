package com.flechazo.apisentinel.ai.budget;

import org.junit.jupiter.api.Test;
import com.flechazo.apisentinel.ai.budget.BudgetMode;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class TokenBudgetManagerTest {

    @Test
    void canProceedWithReservation_isAtomic() throws InterruptedException {
        // Budget = 1000, 10 threads each reserve 150 concurrently. Without
        // atomic reservation, several would pass while combined usage > budget.
        TokenBudgetManager mgr = new TokenBudgetManager(1000, 1000);
        mgr.setBudgetMode(BudgetMode.ENFORCE);
        int threads = 10;
        int perReservation = 150;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger granted = new AtomicInteger(0);

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (mgr.canProceed(perReservation)) {
                        granted.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

        // 1000 / 150 = 6 full reservations fit (6*150=900), the 7th would be 1050>1000.
        // So at most 6 threads can be granted atomically.
        assertTrue(granted.get() <= 6,
                "at most 6 reservations of 150 fit in budget 1000, got " + granted.get());
        assertTrue(granted.get() >= 5,
                "should grant at least 5, got " + granted.get());
    }

    @Test
    void recordUsage_thenCanProceedRespectsAccumulated() {
        TokenBudgetManager mgr = new TokenBudgetManager(1000, 1000);
        mgr.setBudgetMode(BudgetMode.ENFORCE);
        mgr.recordUsage("claude", 600);
        assertFalse(mgr.canProceed(500), "600+500 > 1000, should be denied");
        assertTrue(mgr.canProceed(400), "600+400 = 1000, should pass");
    }

    @Test
    void perRequestMax_capsSingleReservation() {
        TokenBudgetManager mgr = new TokenBudgetManager(100_000, 1000);
        mgr.setBudgetMode(BudgetMode.ENFORCE);
        assertFalse(mgr.canProceed(1001));
        assertTrue(mgr.canProceed(1000));
    }
}
