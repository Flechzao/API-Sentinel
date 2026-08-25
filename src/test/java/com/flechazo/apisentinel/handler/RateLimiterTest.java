package com.flechazo.apisentinel.handler;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    @Test
    void basicAcquire_respectsLimit() {
        RateLimiter limiter = new RateLimiter(5);

        int acquired = 0;
        for (int i = 0; i < 10; i++) {
            if (limiter.tryAcquire()) acquired++;
        }

        assertEquals(5, acquired, "should grant exactly permitsPerSecond");
    }

    @Test
    void refill_afterOneSecond() throws InterruptedException {
        RateLimiter limiter = new RateLimiter(3);

        // Exhaust permits
        for (int i = 0; i < 3; i++) assertTrue(limiter.tryAcquire());
        assertFalse(limiter.tryAcquire(), "should be exhausted");

        // Wait for refill
        Thread.sleep(1100);

        int acquired = 0;
        for (int i = 0; i < 5; i++) {
            if (limiter.tryAcquire()) acquired++;
        }

        assertEquals(3, acquired, "should have 3 permits after refill");
    }

    @Test
    void concurrent_doesNotOverGrant() throws InterruptedException {
        int permitsPerSecond = 10;
        RateLimiter limiter = new RateLimiter(permitsPerSecond);
        int threads = 20;
        AtomicInteger totalAcquired = new AtomicInteger(0);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < 5; j++) {
                        if (limiter.tryAcquire()) {
                            totalAcquired.incrementAndGet();
                        }
                    }
                } catch (InterruptedException ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(5, TimeUnit.SECONDS));
        executor.shutdown();

        // Without a refill, total acquired should not exceed permitsPerSecond
        assertTrue(totalAcquired.get() <= permitsPerSecond + 1,
                "should not significantly over-grant: got " + totalAcquired.get());
    }

    @Test
    void timestampDrift_usesLastPlusInterval() throws InterruptedException {
        RateLimiter limiter = new RateLimiter(5);

        // Exhaust
        for (int i = 0; i < 5; i++) limiter.tryAcquire();

        // Wait 1.5 seconds - with the fix, refill uses last+1s, not now
        Thread.sleep(1500);

        int acquired = 0;
        for (int i = 0; i < 10; i++) {
            if (limiter.tryAcquire()) acquired++;
        }

        // Should get exactly 5 (one refill cycle)
        assertEquals(5, acquired, "should refill exactly once even after 1.5s delay");
    }
}
