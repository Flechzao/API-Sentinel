package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.model.VulnType;

public class DetectionResult {

    private final boolean detected;
    private final String summary;
    private final VulnType vulnType;
    private final boolean sendToRepeater;

    private DetectionResult(boolean detected, String summary, VulnType vulnType, boolean sendToRepeater) {
        this.detected = detected;
        this.summary = summary;
        this.vulnType = vulnType;
        this.sendToRepeater = sendToRepeater;
    }

    public static DetectionResult found(String summary, VulnType vulnType, boolean sendToRepeater) {
        return new DetectionResult(true, summary, vulnType, sendToRepeater);
    }

    public static DetectionResult notFound() {
        return new DetectionResult(false, "", null, false);
    }

    public static DetectionResult skipped(String reason) {
        return new DetectionResult(false, reason, null, false);
    }

    public boolean isDetected() { return detected; }
    public String getSummary() { return summary; }
    public VulnType getVulnType() { return vulnType; }
    public boolean isSendToRepeater() { return sendToRepeater; }
}
