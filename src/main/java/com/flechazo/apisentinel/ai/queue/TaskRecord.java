package com.flechazo.apisentinel.ai.queue;

/**
 * Record of a single analysis task's lifecycle, for display in the task queue panel.
 */
public class TaskRecord {

    public enum TaskStatus {
        QUEUED("排队中"),
        IN_PROGRESS("进行中"),
        COMPLETED("已完成"),
        FAILED("失败"),
        CANCELLED("已取消");

        private final String displayName;

        TaskStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    private final String id;
    private final String apiPath;
    private final String mode;
    private volatile TaskStatus status;
    private volatile long submitTime;
    private volatile long startTime;
    private volatile long endTime;
    private volatile int findingsCount;
    private volatile String error;

    public TaskRecord(String id, String apiPath, String mode) {
        this.id = id;
        this.apiPath = apiPath;
        this.mode = mode;
        this.status = TaskStatus.QUEUED;
        this.submitTime = System.currentTimeMillis();
        this.startTime = 0;
        this.endTime = 0;
        this.findingsCount = 0;
        this.error = null;
    }

    public String getId() { return id; }
    public String getApiPath() { return apiPath; }
    public String getMode() { return mode; }
    public TaskStatus getStatus() { return status; }
    public long getSubmitTime() { return submitTime; }
    public long getStartTime() { return startTime; }
    public long getEndTime() { return endTime; }
    public int getFindingsCount() { return findingsCount; }
    public String getError() { return error; }

    public void markInProgress() {
        this.status = TaskStatus.IN_PROGRESS;
        this.startTime = System.currentTimeMillis();
    }

    public void markCompleted(int findingsCount) {
        this.status = TaskStatus.COMPLETED;
        this.endTime = System.currentTimeMillis();
        this.findingsCount = findingsCount;
    }

    public void markFailed(String error) {
        this.status = TaskStatus.FAILED;
        this.endTime = System.currentTimeMillis();
        this.error = error;
    }

    public void markCancelled() {
        this.status = TaskStatus.CANCELLED;
        this.endTime = System.currentTimeMillis();
    }

    public void requeue() {
        this.status = TaskStatus.QUEUED;
        this.startTime = 0;
        this.endTime = 0;
        this.error = null;
        this.submitTime = System.currentTimeMillis();
    }

    /**
     * Get elapsed time in seconds. Returns elapsed so far if still running, total if done.
     */
    public String getElapsedDisplay() {
        if (startTime == 0) return "-";
        long end = endTime > 0 ? endTime : System.currentTimeMillis();
        long elapsed = (end - startTime) / 1000;
        if (elapsed < 60) return elapsed + "s";
        return (elapsed / 60) + "m " + (elapsed % 60) + "s";
    }
}
