package com.flechazo.apisentinel.ui;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared rendering logic for a FinalVerdict's findings table rows and detail
 * text — extracted so AiAnalysisPanel's embedded results panel and
 * FindingsDetailDialog's standalone popup don't duplicate the same
 * formatting. Pure functions, no Swing state.
 */
final class FindingsRenderer {

    private FindingsRenderer() {}

    /** Row shape: [type, severity, status, title, payload]. */
    static List<Object[]> buildFindingsRows(FinalVerdict verdict) {
        List<Object[]> rows = new ArrayList<>();
        boolean isSafe = "SAFE".equalsIgnoreCase(verdict.overallRisk());

        for (ConfirmedVuln cv : verdict.confirmedVulns()) {
            rows.add(new Object[]{cv.type(), "HIGH", I18n.get("findings_confirmed"), cv.title(), cv.payloadUsed()});
        }
        for (SuspectedVuln sv : verdict.suspectedVulns()) {
            String displayRisk = isSafe ? "INFO" : "MEDIUM";
            String displayConf = isSafe ? I18n.get("findings_not_reproduced") : switch (sv.confidence()) {
                case "HIGH" -> I18n.get("findings_high_suspected");
                case "LOW" -> I18n.get("findings_low_suspected");
                default -> I18n.get("findings_med_suspected");
            };
            rows.add(new Object[]{sv.type(), displayRisk, displayConf, sv.title(), ""});
        }
        return rows;
    }

    /**
     * Detail text for exactly one row of buildFindingsRows()'s output — rows
     * 0..confirmedCount-1 are confirmed vulns, the rest are suspected, in the
     * same order buildFindingsRows() emits them.
     */
    static String buildSingleFindingDetailText(FinalVerdict verdict, int rowIndex) {
        int confirmedCount = verdict.confirmedVulns().size();
        StringBuilder sb = new StringBuilder();
        if (rowIndex >= 0 && rowIndex < confirmedCount) {
            ConfirmedVuln cv = verdict.confirmedVulns().get(rowIndex);
            sb.append(I18n.get("findings_status_confirmed"));
            sb.append(I18n.get("findings_type")).append(cv.type()).append("\n");
            sb.append(I18n.get("findings_title")).append(cv.title()).append("\n\n");
            sb.append(I18n.get("findings_evidence")).append(nullToDash(cv.evidence())).append("\n\n");
            sb.append(I18n.get("findings_payload")).append(nullToDash(cv.payloadUsed())).append("\n\n");
            sb.append(I18n.get("findings_response")).append(nullToDash(cv.response())).append("\n");
            if (cv.verifyCommand() != null && !cv.verifyCommand().isEmpty()) {
                sb.append(I18n.get("findings_verify_cmd")).append(cv.verifyCommand()).append("\n");
            }
        } else {
            int idx = rowIndex - confirmedCount;
            List<SuspectedVuln> suspected = verdict.suspectedVulns();
            if (idx >= 0 && idx < suspected.size()) {
                SuspectedVuln sv = suspected.get(idx);
                sb.append("Status: Suspected (not validated / not tested, no payload)\n\n");
                sb.append(I18n.get("findings_type")).append(sv.type()).append("\n");
                sb.append(I18n.get("findings_title")).append(sv.title()).append("\n\n");
                sb.append(I18n.get("findings_reason")).append(nullToDash(sv.reason())).append("\n");
                if (sv.escalationPath() != null && !sv.escalationPath().isBlank()) {
                    sb.append(I18n.get("findings_escalation")).append(sv.escalationPath()).append("\n");
                }
                if (sv.verifyCommand() != null && !sv.verifyCommand().isEmpty()) {
                    sb.append(I18n.get("findings_verify_cmd")).append(sv.verifyCommand()).append("\n");
                }
            } else {
                sb.append(I18n.get("findings_not_found"));
            }
        }
        return sb.toString();
    }

    /** Summary + recommendations — global to the verdict, shown regardless
     *  of which finding row is selected. */
    static String buildSummaryText(FinalVerdict verdict) {
        StringBuilder sb = new StringBuilder();
        if (verdict.summary() != null && !verdict.summary().isEmpty()) {
            sb.append(verdict.summary());
        }
        if (verdict.recommendations() != null && !verdict.recommendations().isEmpty()) {
            if (sb.length() > 0) sb.append("\n\n");
            sb.append(I18n.get("findings_remediation")).append(verdict.recommendations());
        }
        return sb.toString();
    }

    private static String nullToDash(String s) {
        return (s == null || s.isEmpty()) ? I18n.get("findings_none") : s;
    }

    static String buildDetailText(FinalVerdict verdict, AnalysisResult trafficAnalysis) {
        boolean isSafe = "SAFE".equalsIgnoreCase(verdict.overallRisk());
        StringBuilder detail = new StringBuilder();
        detail.append(I18n.get("findings_report_title"));
        detail.append(I18n.get("findings_overall_risk")).append(verdict.overallRisk()).append("\n");

        if (isSafe && !verdict.suspectedVulns().isEmpty()) {
            detail.append("\n⚠ Risk Note: Stage 1 found potential risks, but Stage 4 payload verification could not reproduce. Final verdict: SAFE. Suspected items below are theoretical only.\n");
        }
        detail.append("\n");

        if (!verdict.confirmedVulns().isEmpty()) {
            detail.append(I18n.get("findings_confirmed_section")).append(verdict.confirmedVulns().size()).append(") ---\n\n");
            for (int i = 0; i < verdict.confirmedVulns().size(); i++) {
                ConfirmedVuln cv = verdict.confirmedVulns().get(i);
                detail.append(String.format("%d. [%s] %s\n", i + 1, cv.type(), cv.title()));
                detail.append(I18n.get("findings_evidence_label")).append(cv.evidence()).append("\n");
                detail.append(I18n.get("findings_payload_label")).append(cv.payloadUsed()).append("\n");
                detail.append(I18n.get("findings_response_label")).append(cv.response()).append("\n");
                if (cv.verifyCommand() != null && !cv.verifyCommand().isEmpty()) {
                    detail.append(I18n.get("findings_verify_label")).append(cv.verifyCommand()).append("\n");
                }
                detail.append("\n");
            }
        }

        if (!verdict.suspectedVulns().isEmpty()) {
            detail.append(I18n.get("findings_suspected_section")).append(verdict.suspectedVulns().size()).append(") ---\n\n");
            for (int i = 0; i < verdict.suspectedVulns().size(); i++) {
                SuspectedVuln sv = verdict.suspectedVulns().get(i);
                detail.append(String.format("%d. [%s] %s\n", i + 1, sv.type(), sv.title()));
                detail.append(I18n.get("findings_reason_label")).append(sv.reason()).append("\n");
                if (sv.escalationPath() != null && !sv.escalationPath().isBlank()) {
                    detail.append(I18n.get("findings_escalation_label")).append(sv.escalationPath()).append("\n");
                }
                if (sv.verifyCommand() != null && !sv.verifyCommand().isEmpty()) {
                    detail.append(I18n.get("findings_verify_label")).append(sv.verifyCommand()).append("\n");
                }
                detail.append("\n");
            }
        }

        if (trafficAnalysis != null && trafficAnalysis.findings() != null && !trafficAnalysis.findings().isEmpty()) {
            detail.append(I18n.get("findings_stage1_section")).append(trafficAnalysis.findings().size()).append(I18n.get("findings_items_suffix"));
            for (int i = 0; i < trafficAnalysis.findings().size(); i++) {
                VulnFinding f = trafficAnalysis.findings().get(i);
                detail.append(String.format("%d. [%s][%s] %s\n", i + 1, f.risk(), f.type(), f.title()));
                if (f.evidence() != null && !f.evidence().isEmpty()) {
                    detail.append(I18n.get("findings_evidence_label")).append(f.evidence()).append("\n");
                }
                detail.append("\n");
            }
        }

        if (verdict.recommendations() != null && !verdict.recommendations().isEmpty()) {
            detail.append(I18n.get("findings_remediation_section"));
            detail.append(verdict.recommendations()).append("\n");
        }

        return detail.toString();
    }
}
