package com.flechazo.apisentinel.event;

import javax.swing.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class UiEventBus {

    private final AtomicBoolean updatePending = new AtomicBoolean(false);
    private final ScheduledExecutorService debouncer;
    private volatile Runnable tableRefreshAction;

    public UiEventBus() {
        this.debouncer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-ui-debouncer");
            t.setDaemon(true);
            return t;
        });
    }

    public void setTableRefreshAction(Runnable action) {
        this.tableRefreshAction = action;
    }

    public void postTableRefresh() {
        if (updatePending.compareAndSet(false, true)) {
            debouncer.schedule(() -> {
                updatePending.set(false);
                Runnable action = tableRefreshAction;
                if (action != null) {
                    SwingUtilities.invokeLater(action);
                }
            }, 200, TimeUnit.MILLISECONDS);
        }
    }

    public void postImmediateRefresh() {
        Runnable action = tableRefreshAction;
        if (action != null) {
            SwingUtilities.invokeLater(action);
        }
    }

    public void shutdown() {
        debouncer.shutdownNow();
        try {
            debouncer.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
