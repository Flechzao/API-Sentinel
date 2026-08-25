package com.flechazo.apisentinel.handler;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class RateLimiter {

    private final int permitsPerSecond;
    private final AtomicLong lastRefillNanos = new AtomicLong(System.nanoTime());
    private final AtomicInteger availablePermits;

    public RateLimiter(int permitsPerSecond) {
        this.permitsPerSecond = permitsPerSecond;
        this.availablePermits = new AtomicInteger(permitsPerSecond);
    }

    public boolean tryAcquire() {
        refillIfNeeded();
        int current;
        do {
            current = availablePermits.get();
            if (current <= 0) return false;
        } while (!availablePermits.compareAndSet(current, current - 1));
        return true;
    }

    private void refillIfNeeded() {
        long now = System.nanoTime();
        long last = lastRefillNanos.get();
        if (now - last >= 1_000_000_000L) {
            if (lastRefillNanos.compareAndSet(last, last + 1_000_000_000L)) {
                // Atomic add-and-cap: the previous addAndGet + single CAS left a
                // window where a concurrent tryAcquire could make the cap CAS fail
                // and permits accumulated beyond the limit. updateAndGet applies
                // both operations atomically.
                availablePermits.updateAndGet(curr -> Math.min(curr + permitsPerSecond, permitsPerSecond));
            }
        }
    }

    public int getPermitsPerSecond() {
        return permitsPerSecond;
    }
}
