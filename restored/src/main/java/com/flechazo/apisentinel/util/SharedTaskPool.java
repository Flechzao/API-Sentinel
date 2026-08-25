package com.flechazo.apisentinel.util;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared background pools replacing the ad-hoc {@code new Thread(...).start()}
 * calls that used to be scattered across UI presenters/dialogs (22 sites at
 * last count — IMPROVEMENT_PLAN_4 Phase 2.2).
 *
 * Two pools, deliberately separate:
 *  - {@link #interactive()}: short user-facing jobs (source lookup, chat LLM
 *    calls, repeater sends, history scans). Four threads keep several panels
 *    responsive at once.
 *  - {@link #indexer()}: long-running repo indexing, serialized on ONE thread
 *    so two user-triggered index actions can't race each other (previously
 *    each click spawned its own thread).
 *
 * Static on purpose: Burp gives every extension (re)load a fresh ClassLoader,
 * so these are re-created per load; {@link #shutdown()} is wired into the
 * extension unload sequence so no threads outlive the extension.
 */
public final class SharedTaskPool {

    private static final AtomicInteger WORKER_SEQ = new AtomicInteger();

    private static final ExecutorService INTERACTIVE = Executors.newFixedThreadPool(4, r -> {
        Thread t = new Thread(r, "api-sentinel-worker-" + WORKER_SEQ.incrementAndGet());
        t.setDaemon(true);
        return t;
    });

    private static final ExecutorService INDEXER = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "api-sentinel-indexer");
        t.setDaemon(true);
        return t;
    });

    private SharedTaskPool() {}

    public static ExecutorService interactive() {
        return INTERACTIVE;
    }

    public static ExecutorService indexer() {
        return INDEXER;
    }

    /** Submit a short interactive job (never blocks the caller). */
    public static void submitInteractive(Runnable task) {
        INTERACTIVE.execute(task);
    }

    /** Queue a long-running indexing job (serialized with other index jobs). */
    public static void submitIndexer(Runnable task) {
        INDEXER.execute(task);
    }

    /** Extension unload: stop accepting work and interrupt running jobs. */
    public static void shutdown() {
        INTERACTIVE.shutdownNow();
        INDEXER.shutdownNow();
        try {
            INTERACTIVE.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            INDEXER.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
