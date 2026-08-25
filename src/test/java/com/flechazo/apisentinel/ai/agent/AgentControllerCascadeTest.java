package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.queue.AnalysisTask;
import com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.event.ApiMatchedEvent;
import com.flechazo.apisentinel.event.ClusterHuntTriggerEvent;
import com.flechazo.apisentinel.event.EventBus;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for the cascade/auto-mode decoupling: cascading follows
 * its OWN sub-switch and works with auto mode OFF (manual analyses cascade
 * too), while passive traffic pickup stays strictly behind the auto-mode
 * gate. Also pins the cascade-off behavior.
 *
 * <p>Uses a REAL indexed Spring controller (same fixture style as
 * {@link SiblingRouteResolverTest}) and a recording AnalysisTaskQueue, so
 * the assertions cover the full event chain: trigger → sibling resolution →
 * pending queue → scheduler consumption → analysis submit.
 */
class AgentControllerCascadeTest {

    @TempDir
    Path tempDir;

    /** Records submits instead of executing them — the tests only care that
     *  a cascaded sibling reaches the analysis queue. */
    static class RecordingQueue extends AnalysisTaskQueue {
        final List<AnalysisTask> submitted = new CopyOnWriteArrayList<>();

        RecordingQueue(LeveledLogger logger) {
            super(null, null, null, logger, 1); // idle worker; submit() overridden
        }

        @Override
        public boolean submit(AnalysisTask task) {
            submitted.add(task);
            return true;
        }
    }

    private CodeIndexService indexUserController() throws IOException {
        Path javaFile = tempDir.resolve("UserController.java");
        Files.writeString(javaFile, """
                package com.demo.vulnapp.controller;

                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/api/users")
                public class UserController {

                    @GetMapping("/{id}")
                    public String getUser(@PathVariable Long id) { return "user"; }

                    @PutMapping("/{id}")
                    public String updateUser(@PathVariable Long id) { return "updated"; }

                    @DeleteMapping("/{id}")
                    public String deleteUser(@PathVariable Long id) { return "deleted"; }

                    @GetMapping("/me")
                    public String me() { return "me"; }
                }
                """);
        CodeIndexService svc = new CodeIndexService(new LeveledLogger(null));
        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        svc.indexRepo(repo, false);
        return svc;
    }

    private static ClusterHuntTriggerEvent triggerFor(ApiEntry source) {
        ConfirmedVuln vuln = new ConfirmedVuln("IDOR", "IDOR read", "ev", "p", "r", "cmd");
        return new ClusterHuntTriggerEvent(source, source.getHttpMethod(),
                new FinalVerdict("HIGH", List.of(vuln), List.of(), "s", "r", 0));
    }

    private static ApiEntry entry(String method, String path) {
        ApiEntry e = new ApiEntry(method, path);
        e.setLastUrl("http://test" + path);
        e.setLastRawRequest(method + " " + path + " HTTP/1.1\r\nHost: test\r\n\r\n");
        return e;
    }

    /** Busy-wait until cond is true or the deadline passes. */
    private static boolean await(long timeoutMs, java.util.function.BooleanSupplier cond)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (cond.getAsBoolean()) return true;
            Thread.sleep(100);
        }
        return cond.getAsBoolean();
    }

    @Test
    void cascadeQueuesSiblingsEvenWithAutoModeOff() throws Exception {
        EventBus bus = new EventBus();
        RecordingQueue queue = new RecordingQueue(new LeveledLogger(null));
        AgentController controller = new AgentController(
                queue, bus, null, indexUserController(), new LeveledLogger(null));
        try {
            // The whole point of the fix: auto mode OFF, cascade still fires.
            assertThat(controller.isEnabled()).isFalse();
            assertThat(controller.isCascadeEnabled()).isTrue();

            bus.publish(triggerFor(entry("GET", "/api/users/1001")));

            assertThat(await(6000, () -> !queue.submitted.isEmpty())).isTrue();
            AnalysisTask task = queue.submitted.get(0);

            // A sibling, not the source — method-scoped: the very first target
            // is the IDOR read→write escalation (PUT same path), so compare
            // method+path, not path alone. Write-first.
            assertThat(task.method() + " " + task.entry().getApiPath())
                    .isNotEqualTo("GET /api/users/1001");
            assertThat(task.method()).isIn("PUT", "DELETE", "POST");
        } finally {
            controller.shutdown();
        }
    }

    @Test
    void autoModeOffPlainTrafficBypassedEntirely() throws Exception {
        EventBus bus = new EventBus();
        RecordingQueue queue = new RecordingQueue(new LeveledLogger(null));
        AgentController controller = new AgentController(
                queue, bus, null, indexUserController(), new LeveledLogger(null));
        try {
            assertThat(controller.isEnabled()).isFalse();

            bus.publish(new ApiMatchedEvent(entry("GET", "/api/orders/9"),
                    "http://test/api/orders/9", "GET", "", "", 200,
                    "GET /api/orders/9 HTTP/1.1\r\nHost: test\r\n\r\n", ""));

            // Past two scheduler ticks: a submit would mean the auto-mode gate
            // broke. New traffic is dropped at onApiMatched's entrance (never
            // queued) — the decoupling must not also open this gate.
            assertThat(await(2500, () -> !queue.submitted.isEmpty())).isFalse();
            assertThat(queue.submitted).isEmpty();
            assertThat(controller.getPendingCount()).isZero();
        } finally {
            controller.shutdown();
        }
    }

    @Test
    void cascadeIsNotStarvedBehindStalePlainHeadWithAutoModeOff() throws Exception {
        EventBus bus = new EventBus();
        RecordingQueue queue = new RecordingQueue(new LeveledLogger(null));
        AgentController controller = new AgentController(
                queue, bus, null, indexUserController(), new LeveledLogger(null));
        try {
            // Queue a plain traffic event while auto mode is on, then flip
            // auto mode OFF before the scheduler's first tick consumes it.
            // The plain event becomes a stale head that the gate refuses to
            // touch — the cascade siblings queued right after it must NOT
            // starve behind it (the head-of-line blocking regression).
            controller.setEnabled(true);
            bus.publish(new ApiMatchedEvent(entry("GET", "/api/orders/9"),
                    "http://test/api/orders/9", "GET", "", "", 200,
                    "GET /api/orders/9 HTTP/1.1\r\nHost: test\r\n\r\n", ""));
            // The EventBus dispatches asynchronously — wait until the plain
            // event is actually queued before flipping auto mode off, or the
            // handler may still see enabled==false and drop it at the
            // entrance, robbing the test of its stale head.
            assertThat(await(3000, () -> controller.getPendingCount() == 1)).isTrue();
            controller.setEnabled(false);

            bus.publish(triggerFor(entry("GET", "/api/users/1001")));
            assertThat(await(3000, () -> controller.getPendingCount() >= 2)).isTrue();

            // The cascade sibling gets consumed despite the stale plain head.
            assertThat(await(6000, () -> !queue.submitted.isEmpty())).isTrue();
            AnalysisTask task = queue.submitted.get(0);
            assertThat(task.entry().getApiPath()).isNotEqualTo("/api/orders/9");
            assertThat(task.method() + " " + task.entry().getApiPath())
                    .isNotEqualTo("GET /api/users/1001"); // a sibling, not the source

            // Nothing submitted is ever the plain event while auto mode is off.
            assertThat(controller.getPendingCount()).isGreaterThanOrEqualTo(1);
            assertThat(queue.submitted)
                    .noneMatch(t -> "/api/orders/9".equals(t.entry().getApiPath()));

            // Proof the plain event survived (skipped, not dropped): re-enable
            // auto mode — as the queue head it must be the next thing
            // processed once the rate limit allows.
            controller.setEnabled(true);
            assertThat(await(10000, () -> queue.submitted.stream()
                    .anyMatch(t -> "/api/orders/9".equals(t.entry().getApiPath())))).isTrue();
        } finally {
            controller.shutdown();
        }
    }

    @Test
    void cascadeSwitchOffBlocksEvenWithAutoModeOn() throws Exception {
        EventBus bus = new EventBus();
        RecordingQueue queue = new RecordingQueue(new LeveledLogger(null));
        AgentController controller = new AgentController(
                queue, bus, null, indexUserController(), new LeveledLogger(null));
        try {
            controller.setEnabled(true);
            controller.setCascadeEnabled(false);

            bus.publish(triggerFor(entry("GET", "/api/users/1001")));

            assertThat(await(2500, () -> !queue.submitted.isEmpty())).isFalse();
            assertThat(queue.submitted).isEmpty();
        } finally {
            controller.shutdown();
        }
    }
}
