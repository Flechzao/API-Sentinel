package com.flechazo.apisentinel.model;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

public class ApiEntry {
    private final String id;
    private String httpMethod;
    private final String apiPath;
    private final List<AnalysisRecord> analysisHistory = new CopyOnWriteArrayList<>();
    /** Local passive-detection findings (zero-AI layer). Separate from
     *  analysisHistory (AI output) by design — see PassiveFinding. */
    private final List<PassiveFinding> passiveFindings = new CopyOnWriteArrayList<>();
    private ApiStatus status;
    private VulnType vulnType;
    private String result;
    private String note;
    /** Manual risk override (HIGH/MEDIUM/LOW/SAFE); null = use AI verdict. */
    private String manualRisk;
    private String domain;
    private long lastSeenTimestamp;

    private String lastRawRequest = "";
    private String lastRawResponse = "";
    private String lastUrl = "";
    private int lastStatusCode = 0;

    public ApiEntry(String httpMethod, String apiPath) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.httpMethod = httpMethod != null ? httpMethod : "";
        this.apiPath = apiPath;
        this.status = ApiStatus.UNTESTED;
        this.vulnType = null;
        this.result = "";
        this.note = "";
        this.domain = "";
        this.lastSeenTimestamp = 0;
    }

    public ApiEntry(String id, String httpMethod, String apiPath, ApiStatus status,
                    VulnType vulnType, String result, String note, String domain, long lastSeenTimestamp) {
        this.id = id;
        this.httpMethod = httpMethod != null ? httpMethod : "";
        this.apiPath = apiPath;
        this.status = status;
        this.vulnType = vulnType;
        this.result = result != null ? result : "";
        this.note = note != null ? note : "";
        this.domain = domain != null ? domain : "";
        this.lastSeenTimestamp = lastSeenTimestamp;
    }

    /** Copy all fields (incl. analysis history + traffic data) with a new path.
     *  Used when editing the path column — path is the entry's identity key. */
    public ApiEntry(ApiEntry src, String newApiPath) {
        this.id = src.id;
        this.httpMethod = src.httpMethod;
        this.apiPath = newApiPath;
        this.status = src.status;
        this.vulnType = src.vulnType;
        this.result = src.result;
        this.note = src.note;
        this.domain = src.domain;
        this.lastSeenTimestamp = src.lastSeenTimestamp;
        this.lastRawRequest = src.lastRawRequest;
        this.lastRawResponse = src.lastRawResponse;
        this.lastUrl = src.lastUrl;
        this.lastStatusCode = src.lastStatusCode;
        this.manualRisk = src.manualRisk;
        this.analysisHistory.addAll(src.analysisHistory);
        this.passiveFindings.addAll(src.passiveFindings);
    }

    public String getId() { return id; }
    public String getApiPath() { return apiPath; }

    public synchronized String getHttpMethod() { return httpMethod; }
    public synchronized void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public synchronized void appendHttpMethod(String method) {
        if (method == null || method.isEmpty() || "OPTIONS".equals(method)) return;
        if (httpMethod == null || httpMethod.isEmpty()) {
            httpMethod = method;
            return;
        }
        String[] existing = httpMethod.split("/");
        for (String m : existing) {
            if (m.equals(method)) return;
        }
        httpMethod = httpMethod + "/" + method;
    }

    public synchronized ApiStatus getStatus() { return status; }
    public synchronized VulnType getVulnType() { return vulnType; }
    public synchronized String getResult() { return result; }

    public synchronized void updateStatus(ApiStatus status, VulnType vulnType, String result) {
        this.status = status;
        this.vulnType = vulnType;
        this.result = result != null ? result : "";
    }

    public synchronized String getNote() { return note; }
    public synchronized void setNote(String note) { this.note = note != null ? note : ""; }

    public synchronized String getDomain() { return domain; }
    public synchronized void setDomain(String domain) { this.domain = domain != null ? domain : ""; }

    public synchronized long getLastSeenTimestamp() { return lastSeenTimestamp; }
    public synchronized void setLastSeenTimestamp(long ts) { this.lastSeenTimestamp = ts; }

    public synchronized String getLastRawRequest() { return lastRawRequest; }
    public synchronized void setLastRawRequest(String req) { this.lastRawRequest = req != null ? req : ""; }

    public synchronized String getLastRawResponse() { return lastRawResponse; }
    public synchronized void setLastRawResponse(String resp) { this.lastRawResponse = resp != null ? resp : ""; }

    public synchronized String getLastUrl() { return lastUrl; }
    public synchronized void setLastUrl(String url) { this.lastUrl = url != null ? url : ""; }

    public synchronized int getLastStatusCode() { return lastStatusCode; }
    public synchronized void setLastStatusCode(int code) { this.lastStatusCode = code; }

    public synchronized boolean hasTrafficData() {
        return !lastRawRequest.isEmpty();
    }

    public synchronized boolean isTested() {
        return status != ApiStatus.UNTESTED && status != ApiStatus.UNDER_TEST;
    }

    public synchronized void cycleTestStatus() {
        switch (status) {
            case UNTESTED, UNDER_TEST -> updateStatus(ApiStatus.PENDING_REVIEW, null, ApiStatus.PENDING_REVIEW.getDisplayName());
            case PENDING_REVIEW -> updateStatus(ApiStatus.PASSED, null, ApiStatus.PASSED.getDisplayName());
            case PASSED -> updateStatus(ApiStatus.VULNERABLE, VulnType.GENERIC, VulnType.GENERIC.getDisplayName());
            case VULNERABLE -> updateStatus(ApiStatus.UNTESTED, null, "");
        }
    }

    public synchronized void cycleVulnType() {
        if (vulnType == null) {
            updateStatus(ApiStatus.VULNERABLE, VulnType.GENERIC, VulnType.GENERIC.getDisplayName());
        } else {
            VulnType[] types = VulnType.values();
            int nextIdx = (vulnType.ordinal() + 1) % types.length;
            VulnType next = types[nextIdx];
            updateStatus(ApiStatus.VULNERABLE, next, next.getDisplayName());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ApiEntry that)) return false;
        return apiPath.equals(that.apiPath);
    }

    @Override
    public int hashCode() {
        return apiPath.hashCode();
    }

    @Override
    public synchronized String toString() {
        return String.format("ApiEntry{%s %s [%s]}", httpMethod, apiPath, status);
    }

    // --- Analysis history methods ---

    public List<AnalysisRecord> getAnalysisHistory() {
        return analysisHistory;
    }

    public void addAnalysisRecord(AnalysisRecord record) {
        analysisHistory.add(record);
    }

    /** Remove a specific analysis record (e.g. user deletes a run). Returns true
     *  if the record was present and removed. */
    public boolean removeAnalysisRecord(AnalysisRecord record) {
        if (record == null) return false;
        return analysisHistory.removeIf(r -> r != null && r.id() != null && r.id().equals(record.id()));
    }

    public synchronized AnalysisRecord getLatestAnalysisRecord() {
        if (analysisHistory.isEmpty()) return null;
        return analysisHistory.get(analysisHistory.size() - 1);
    }

    public synchronized void updateLatestAnalysisRecord(AnalysisRecord updated) {
        if (!analysisHistory.isEmpty()) {
            analysisHistory.set(analysisHistory.size() - 1, updated);
        }
    }

    // --- Passive findings methods (local zero-AI detections) ---

    public List<PassiveFinding> getPassiveFindings() {
        return passiveFindings;
    }

    public synchronized boolean hasPassiveFindings() {
        return !passiveFindings.isEmpty();
    }

    /** De-dup by (source, title); returns whether the finding was actually
     *  added. Replaces the old note.contains(marker) string de-duplication. */
    public synchronized boolean addPassiveFindingIfAbsent(PassiveFinding f) {
        for (PassiveFinding existing : passiveFindings) {
            if (existing.source() == f.source() && existing.title().equals(f.title())) {
                return false;
            }
        }
        passiveFindings.add(f);
        return true;
    }

    public synchronized void removePassiveFinding(String id) {
        passiveFindings.removeIf(f -> f.id().equals(id));
    }

    /** Table "被动" column: single-line summary. ≤2 titles shown as-is,
     *  otherwise first two + "+N". */
    public synchronized String getDisplayPassiveSummary() {
        if (passiveFindings.isEmpty()) return "--";
        LinkedHashSet<String> titles = new LinkedHashSet<>();
        for (PassiveFinding f : passiveFindings) titles.add(f.title());
        List<String> list = new ArrayList<>(titles);
        if (list.size() <= 2) return String.join(" · ", list);
        return list.get(0) + " · " + list.get(1) + " +" + (list.size() - 2);
    }

    /** Tooltip: one line per finding — [risk] category / title. */
    public synchronized String getDisplayPassiveTooltip() {
        if (passiveFindings.isEmpty()) return null;
        StringBuilder sb = new StringBuilder();
        for (PassiveFinding f : passiveFindings) {
            sb.append("[").append(f.risk()).append("] ")
              .append(f.category()).append(" / ").append(f.title()).append("\n");
        }
        return sb.toString().trim();
    }

    /** Full text for AI context / report export. */
    public synchronized String buildPassiveFindingsText() {
        if (passiveFindings.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (PassiveFinding f : passiveFindings) {
            sb.append("- [").append(f.source()).append("][").append(f.risk()).append("] ")
              .append(f.category()).append(" / ").append(f.title());
            if (f.evidence() != null && !f.evidence().isEmpty()) {
                sb.append(" — ").append(f.evidence());
            }
            sb.append("\n");
        }
        return sb.toString().trim();
    }

    /** Highest risk level across all findings (for column coloring). */
    public synchronized String getMaxPassiveRisk() {
        int rank = 0; // 0=none 1=INFO 2=LOW 3=MEDIUM 4=HIGH
        for (PassiveFinding f : passiveFindings) {
            rank = Math.max(rank, switch (f.risk()) {
                case "HIGH" -> 4; case "MEDIUM" -> 3; case "LOW" -> 2; default -> 1; });
        }
        return switch (rank) {
            case 4 -> "HIGH"; case 3 -> "MEDIUM"; case 2 -> "LOW"; case 1 -> "INFO"; default -> ""; };
    }

    // --- Derived display helpers (for table columns) ---

    /** Overall risk: manual override > Pipeline verdict > simple analysis > "--". */
    public synchronized String getDisplayRisk() {
        if (manualRisk != null && !manualRisk.isEmpty()) return manualRisk;
        AnalysisRecord latest = getLatestAnalysisRecord();
        if (latest == null) return "--";
        if (latest.hasPipelineResult()) return latest.pipelineResult().verdict().overallRisk();
        if (latest.result() != null && latest.result().isSuccess()) return latest.result().overallRisk().name();
        return "--";
    }

    public synchronized String getManualRisk() { return manualRisk; }
    public synchronized void setManualRisk(String risk) {
        this.manualRisk = (risk == null || risk.isEmpty() || "自动".equals(risk)) ? null : risk.toUpperCase();
    }

    /** Findings summary: vulnerability type names from confirmed (falls back to
     *  suspected types, then to the raw "confirmed/suspected" counts). */
    public synchronized String getDisplayFindings() {
        AnalysisRecord latest = getLatestAnalysisRecord();
        if (latest == null) return "--";
        if (latest.hasPipelineResult()) {
            FinalVerdict v = latest.pipelineResult().verdict();
            List<ConfirmedVuln> confirmed = v.confirmedVulns();
            List<SuspectedVuln> suspected = v.suspectedVulns();

            // Union of confirmed + suspected types — a prior version only
            // fell back to suspected types when confirmed was completely
            // empty, which meant a single confirmed "信息泄露" finding could
            // silently hide an equally-real suspected "SQL注入" (e.g. demoted
            // by VerdictValidator) from this column entirely.
            LinkedHashSet<String> types = new LinkedHashSet<>();
            for (ConfirmedVuln cv : confirmed) {
                if (cv.type() != null && !cv.type().isEmpty()) types.add(cv.type());
            }
            for (SuspectedVuln sv : suspected) {
                if (sv.type() != null && !sv.type().isEmpty() && !types.contains(sv.type())) {
                    types.add("疑似: " + sv.type());
                }
            }
            if (types.isEmpty()) return confirmed.size() + "/" + suspected.size();

            // One type per line — the table renders this column with a
            // wrapping multi-line cell (same approach as the 备注 column),
            // so no need to truncate/comma-join onto a single line.
            return String.join("\n", types);
        }
        if (latest.result() != null && latest.result().isSuccess()) {
            return String.valueOf(latest.result().findings().size());
        }
        return "--";
    }

    /** Full tooltip for the findings column: all types + confirmed/suspected counts. */
    public synchronized String getDisplayFindingsTooltip() {
        AnalysisRecord latest = getLatestAnalysisRecord();
        if (latest == null || !latest.hasPipelineResult()) return null;
        FinalVerdict v = latest.pipelineResult().verdict();
        LinkedHashSet<String> types = new LinkedHashSet<>();
        for (ConfirmedVuln cv : v.confirmedVulns()) {
            if (cv.type() != null && !cv.type().isEmpty()) types.add(cv.type());
        }
        for (SuspectedVuln sv : v.suspectedVulns()) {
            if (sv.type() != null && !sv.type().isEmpty()) types.add(sv.type());
        }
        if (types.isEmpty()) return null;
        return String.format("%s (确认:%d / 疑似:%d)",
                String.join(", ", types), v.confirmedVulns().size(), v.suspectedVulns().size());
    }
}
