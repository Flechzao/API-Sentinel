package com.flechazo.apisentinel.ai.queue;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard: {@link TaskRecord} must be transitionable to FAILED
 * exactly once, and the error message must be preserved. The Agent-facade
 * zombie-record bug (pre-2026-09-06) relied on this method being callable
 * from the error-path callback — if this method ever gets stricter
 * (e.g. refuses already-IN_PROGRESS records, or silently ignores the call),
 * the bug returns.
 */
class TaskRecordMarkFailedTest {

    @Test
    void markFailedFromInProgressRecordsErrorAndTerminalStatus() {
        TaskRecord record = new TaskRecord("id-1", "GET /api/x", "Agent");
        record.markInProgress();

        record.markFailed("provider timeout");

        assertThat(record.getStatus())
                .as("TaskRecord must reach FAILED from IN_PROGRESS — "
                        + "otherwise an Agent loop that dies mid-run leaves its row "
                        + "stuck in the UI forever")
                .isEqualTo(TaskRecord.TaskStatus.FAILED);
        assertThat(record.getError()).isEqualTo("provider timeout");
        assertThat(record.getEndTime()).isGreaterThan(0);
    }

    @Test
    void markFailedIsIdempotentAcrossRepeatedCalls() {
        TaskRecord record = new TaskRecord("id-2", "POST /api/y", "Agent");
        record.markInProgress();
        record.markFailed("first failure");
        record.markFailed("second failure");
        // The record must end in FAILED regardless of how many error-path
        // callbacks fire. The last message is fine either way.
        assertThat(record.getStatus()).isEqualTo(TaskRecord.TaskStatus.FAILED);
    }

    @Test
    void markFailedFromQueuedAlsoWorks() {
        // Defensive: some error paths may fire before the record is
        // marked in-progress (e.g. submit() itself rejects). The record
        // must still be reachable to FAILED.
        TaskRecord record = new TaskRecord("id-3", "GET /api/z", "Agent");
        assertThat(record.getStatus()).isEqualTo(TaskRecord.TaskStatus.QUEUED);
        record.markFailed("queue full");
        assertThat(record.getStatus()).isEqualTo(TaskRecord.TaskStatus.FAILED);
        assertThat(record.getError()).isEqualTo("queue full");
    }

    @Test
    void markFailedFromCompletedIsAllowed() {
        // Belt-and-braces: a late-arriving error callback on an already-
        // completed record must not throw. The current impl just overwrites.
        TaskRecord record = new TaskRecord("id-4", "GET /api/w", "Agent");
        record.markCompleted(3);
        record.markFailed("late error");
        assertThat(record.getStatus()).isEqualTo(TaskRecord.TaskStatus.FAILED);
    }
}
