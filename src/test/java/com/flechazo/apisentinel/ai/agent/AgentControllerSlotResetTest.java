package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.queue.AnalysisTask;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.event.ApiMatchedEvent;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for the concurrency-slot leak that used to make
 * {@link AgentController} permanently "full" after a failed run, blocking
 * every subsequent auto-analysis until extension restart.
 *
 * <p>Root cause (pre-2026-09-06):
 * <ol>
 *   <li>{@code AgentFacade.onAgentError} never called
 *       {@code taskRecord.markFailed(...)}, so right-click "Agent analyze"
 *       whose loop died mid-run left its TaskRecord stuck IN_PROGRESS and
 *       the corresponding UI row unremovable.</li>
 *   <li>{@code AgentController.onAnalysisComplete} has an early-return
 *       {@code if (!enabled && !isCascadeOrigin) return} that drops the
 *       {@code activeAnalyses.decrementAndGet()} call. Combined with (1)
 *       (which also skips the {@code AiAnalysisCompleteEvent} that would
 *       normally drive the decrement), the counter leaked.</li>
 *   <li>{@code setEnabled(false)} did not reset the counter, so once
 *       leaked, the slot stayed occupied for the rest of the session.</li>
 * </ol>
 *
 * <p>Fix (documented at the two call sites): {@code onAgentError} + the
 * {@code exceptionally} safety net now call {@code taskRecord.markFailed}
 * for (1); {@code setEnabled(false)} and {@code shutdown()} now reset
 * {@code activeAnalyses} to 0 for (3), as a defensive belt-and-braces
 * layer on top of the (still-imperfect) (2).
 */
class AgentControllerSlotResetTest {

    /** Recording queue — tests only care about the counter behavior. */
    static class RecordingQueue extends AnalysisTaskQueue {
        final List<AnalysisTask> submitted = new CopyOnWriteArrayList<>();
        RecordingQueue(LeveledLogger logger) {
            super(null, null, null, logger, 1);
        }
        @Override public boolean submit(AnalysisTask task) {
            submitted.add(task);
            return true;
        }
    }

    /** Read the private activeAnalyses counter via reflection — the leak is
     *  internal state with no public accessor, and exposing one would widen
     *  the surface area of a field we want to keep implementation-private. */
    private static int readActiveAnalyses(AgentController controller) throws Exception {
        Field f = AgentController.class.getDeclaredField("activeAnalyses");
        f.setAccessible(true);
        return ((AtomicInteger) f.get(controller)).get();
    }

    private static ApiEntry entry(String method, String path) {
        ApiEntry e = new ApiEntry(method, path);
        e.setDomain("test");
        e.setLastUrl("http://test" + path);
        return e;
    }

    @Test
    void setEnabledFalseResetsLeakedSlotCounter() throws Exception {
        EventBus bus = new EventBus();
        RecordingQueue queue = new RecordingQueue(new LeveledLogger(null));
        AgentController controller = new AgentController(
                queue, bus, null, null, new LeveledLogger(null));
        try {
            controller.setEnabled(true);

            // Fire a plain event → the scheduler picks it up, increments
            // activeAnalyses, and submits to the recording queue.
            bus.publish(new ApiMatchedEvent(entry("GET", "/api/x"),
                    "http://test/api/x", "GET", "", "", 200,
                    "GET /api/x HTTP/1.1\r\nHost: test\r\n\r\n", ""));

            // Wait until the scheduler has incremented (submit happened).
            long deadline = System.currentTimeMillis() + 6000;
            while (System.currentTimeMillis() < deadline
                    && (queue.submitted.isEmpty() || readActiveAnalyses(controller) == 0)) {
                Thread.sleep(50);
            }
            assertThat(queue.submitted).as("event picked up").isNotEmpty();
            assertThat(readActiveAnalyses(controller))
                    .as("activeAnalyses incremented by processPendingQueue")
                    .isGreaterThanOrEqualTo(1);

            // The user gesture that used to leave the leaked slot in place.
            controller.setEnabled(false);

            assertThat(readActiveAnalyses(controller))
                    .as("setEnabled(false) must defensively zero the slot counter "
                            + "so a leaked slot cannot permanently block future auto-analyses")
                    .isZero();
        } finally {
            controller.shutdown();
        }
    }

    @Test
    void shutdownResetsSlotCounter() throws Exception {
        EventBus bus = new EventBus();
        RecordingQueue queue = new RecordingQueue(new LeveledLogger(null));
        AgentController controller = new AgentController(
                queue, bus, null, null, new LeveledLogger(null));
        controller.setEnabled(true);
        bus.publish(new ApiMatchedEvent(entry("GET", "/api/y"),
                "http://test/api/y", "GET", "", "", 200,
                "GET /api/y HTTP/1.1\r\nHost: test\r\n\r\n", ""));
        long deadline = System.currentTimeMillis() + 6000;
        while (System.currentTimeMillis() < deadline
                && (queue.submitted.isEmpty() || readActiveAnalyses(controller) == 0)) {
            Thread.sleep(50);
        }
        assertThat(readActiveAnalyses(controller)).isGreaterThanOrEqualTo(1);

        controller.shutdown();

        assertThat(readActiveAnalyses(controller))
                .as("shutdown must zero the slot counter so a hot-reload "
                        + "of the extension cannot inherit a leaked value")
                .isZero();
    }
}
