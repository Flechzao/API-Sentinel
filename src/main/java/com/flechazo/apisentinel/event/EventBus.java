package com.flechazo.apisentinel.event;

import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * 异步事件总线——组件间解耦通信。API 匹配、分析完成、级联触发等事件通过此分发。
 * 有界线程池 + CallerRunsPolicy 背压。
 */
public class EventBus {

    private final Map<Class<?>, List<Consumer<?>>> listeners = new ConcurrentHashMap<>();
    private final ExecutorService executor;
    private volatile LeveledLogger logger;

    public EventBus() {
        // Bounded pool: a slow handler on one event type no longer blocks
        // delivery of all other event types (the old single-thread executor
        // serialized everything behind one stuck listener). CallerRunsPolicy
        // provides backpressure instead of dropping events on queue overflow.
        this.executor = new ThreadPoolExecutor(
                2, 4,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(256),
                r -> {
                    Thread t = new Thread(r, "api-sentinel-eventbus");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.CallerRunsPolicy());
    }

    public void setLogger(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Subscribe a handler. Returns a handle whose {@link Subscription#unsubscribe()}
     * removes the handler — call it from a panel's dispose to avoid listener leaks
     * and duplicate event processing across rebuilds.
     */
    @SuppressWarnings("unchecked")
    public <T> Subscription subscribe(Class<T> eventType, Consumer<T> handler) {
        listeners.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>())
                .add(handler);
        return new Subscription(() -> {
            List<Consumer<?>> list = listeners.get(eventType);
            if (list != null) list.remove(handler);
                });
    }

    /** Explicit unsubscribe (e.g. when the handle was not retained). */
    @SuppressWarnings("unchecked")
    public <T> void unsubscribe(Class<T> eventType, Consumer<T> handler) {
        List<Consumer<?>> list = listeners.get(eventType);
        if (list != null) list.remove(handler);
    }

    @SuppressWarnings("unchecked")
    public <T> void publish(T event) {
        List<Consumer<?>> handlers = listeners.get(event.getClass());
        if (handlers == null || handlers.isEmpty()) return;
        executor.submit(() -> {
            for (Consumer<?> handler : handlers) {
                try {
                    ((Consumer<T>) handler).accept(event);
                } catch (Exception e) {
                    if (logger != null) {
                        logger.error("[EventBus] Handler exception: %s", e.getMessage());
                    } else {
                        System.err.println("[EventBus] Handler exception: " + e.getMessage());
                    }
                    // A single failing handler must not stop sibling handlers
                }
            }
        });
    }

    public void shutdown() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Handle returned by {@link #subscribe} for later removal. */
    public static final class Subscription {
        private final Runnable unsubscribe;

        Subscription(Runnable unsubscribe) {
            this.unsubscribe = unsubscribe;
        }

        public void unsubscribe() {
            unsubscribe.run();
        }
    }
}
