package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.ai.prompt.SafetyRules;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Cross-validates LLM-claimed confirmed vulns against real PayloadResults so
 * hallucinated findings are downgraded to suspected, and overall_risk=HIGH is
 * only allowed with a surviving confirmed. Extracted from AnalysisPipeline so
 * Agent mode (SubmitReportTool via AgentLoop) can apply the same defense —
 * Pipeline previously had this and Agent mode didn't, which is why Agent
 * mode could report an untested "confirmed" vuln as fact.
 *
 * Pipeline's own PayloadResults carry a real testCase + a programmatic
 * anomalyDetected flag (from RequestExecutionEngine comparing against a
 * baseline), so it can require requireAnomaly=true. Agent mode's send_request
 * tool has no baseline comparison — its PayloadResults always have
 * testCase=null and anomalyDetected=false — so Agent mode uses
 * requireAnomaly=false: the lower bar of "was this payload actually sent"
 * still catches the case of a model claiming a vuln it never even tried.
 */
public final class VerdictValidator {

    private VerdictValidator() {}

    public static FinalVerdict validate(String overallRisk, List<ConfirmedVuln> confirmedVulns,
                                         List<SuspectedVuln> suspectedVulns, String summary,
                                         String recommendations, int totalTokensUsed,
                                         List<PayloadResult> payloadResults, boolean requireAnomaly) {
        return validate(overallRisk, confirmedVulns, suspectedVulns, summary, recommendations,
                totalTokensUsed, payloadResults, requireAnomaly, null);
    }

    /**
     * Full validation with identity audit. When authTestResult (Stage 5
     * programmatic auth test) is supplied, the audit also cross-checks the
     * LLM's auth-class confirms against it (missed-finding and SAFE-conflict
     * notes). All demotions/downgrades are recorded in rejectionReasons.
     */
    public static FinalVerdict validate(String overallRisk, List<ConfirmedVuln> confirmedVulns,
                                         List<SuspectedVuln> suspectedVulns, String summary,
                                         String recommendations, int totalTokensUsed,
                                         List<PayloadResult> payloadResults, boolean requireAnomaly,
                                         com.flechazo.apisentinel.auth.AuthTestResult authTestResult) {
        List<String> rejectionReasons = new ArrayList<>();
        List<ConfirmedVuln> survivingConfirmed = new ArrayList<>();
        List<SuspectedVuln> allSuspected = new ArrayList<>(suspectedVulns);

        List<ConfirmedVuln> demoted = new ArrayList<>();
        List<ConfirmedVuln> demotedWaf = new ArrayList<>();
        // Auth-class (越权/IDOR/未授权) findings are validated differently: their
        // "payload" is an identity credential (Cookie/header) and a successful
        // attack surfaces as a NORMAL 200 returning another account's data —
        // there is no error anomaly to detect and often no citable payload text
        // (payloadUsed is frequently blank). Requiring "payload text match +
        // anomaly" would wrongly demote genuinely-verified privilege escalation.
        // Their gate is instead: at least one real (non-WAF-blocked) request was
        // sent, plus the identity audit below (identity_proof).
        boolean anyRealRequest = payloadResults != null
                && payloadResults.stream().anyMatch(pr -> !pr.isWafBlocked());
        for (ConfirmedVuln cv : confirmedVulns) {
            boolean passes;
            PayloadResult match = null;
            if (isAuthClass(cv.type())) {
                passes = anyRealRequest;
            } else {
                match = findPayloadResult(payloadResults, cv.payloadUsed());
                passes = requireAnomaly
                        ? (match != null && match.anomalyDetected())
                        : (match != null);
            }
            // A WAF-blocked payload never reached the backend — any "anomaly"
            // was most likely the block page itself, so it cannot back a
            // confirmed finding (distilled from bughunter's validate-gate idea).
            if (passes && match != null && match.isWafBlocked()) {
                passes = false;
                demotedWaf.add(cv);
            } else if (!passes) {
                demoted.add(cv);
            }
            if (passes) {
                survivingConfirmed.add(cv);
            }
        }
        for (ConfirmedVuln cv : demoted) {
            allSuspected.add(new SuspectedVuln(
                    cv.type(), cv.title(),
                    "LLM 标记为已确认但未通过程序化校验（payload 未发送或未触发异常），已降级为疑似: "
                            + (cv.evidence() == null ? "" : cv.evidence()),
                    cv.verifyCommand(), "MEDIUM", "",
                    cv.payloadUsed() == null ? "" : cv.payloadUsed()));
            rejectionReasons.add("payload 校验失败: '" + cv.title()
                    + "' 未匹配到真实发送且触发异常的 payload，confirmed 降级为疑似");
        }
        for (ConfirmedVuln cv : demotedWaf) {
            allSuspected.add(new SuspectedVuln(
                    cv.type(), cv.title(),
                    "payload 被 WAF 拦截（响应为拦截页而非后端真实响应），异常信号不可信，已降级为疑似: "
                            + (cv.evidence() == null ? "" : cv.evidence()),
                    cv.verifyCommand(), "MEDIUM", "",
                    cv.payloadUsed() == null ? "" : cv.payloadUsed()));
            rejectionReasons.add("WAF 拦截: '" + cv.title() + "' 的 payload 被 WAF 拦截，confirmed 降级为疑似");
        }

        // Knowledge-layer backstop (Phase 2): informational-only findings —
        // missing security headers, CORS-without-credentials, DNS-only SSRF,
        // error-echo-only SQLi, version/banner leaks, etc. — must not appear
        // in confirmed OR suspected, only in recommendations. Demote them
        // out of both lists and leave a trace in the summary so the finding
        // isn't silently lost. A finding carrying real exploit-chain evidence
        // (内网数据 / 凭证外带 / 行数据 / metadata / ...) is exempted.
        List<String> removedInfo = new ArrayList<>();
        List<ConfirmedVuln> survivingAfterInfo = new ArrayList<>();
        for (ConfirmedVuln cv : survivingConfirmed) {
            if (SafetyRules.isInformationalType(cv.type())
                    && !SafetyRules.hasChainEvidence(cv.evidence())) {
                removedInfo.add(cv.type() + "/" + cv.title());
            } else {
                survivingAfterInfo.add(cv);
            }
        }
        List<SuspectedVuln> survivingSuspected = new ArrayList<>();
        for (SuspectedVuln sv : allSuspected) {
            // Suspected carries reason (closest to evidence), not a separate
            // evidence field — check both type and reason for the chain
            // exemption so a demoted-then-redeemed finding still survives.
            if (SafetyRules.isInformationalType(sv.type())
                    && !SafetyRules.hasChainEvidence(sv.reason())) {
                removedInfo.add(sv.type() + "/" + sv.title());
            } else {
                survivingSuspected.add(sv);
            }
        }
        survivingConfirmed = survivingAfterInfo;
        allSuspected = survivingSuspected;

        // ===== Identity audit (Phase 4): auth-class confirms must carry
        // explicit identity evidence — which session context was used, whether
        // anonymous access was tested, and how the returned data was confirmed
        // to belong to ANOTHER account. Blank answer → auto-demote
        // (distilled from bughunter's validate.py Identity Check). =====
        List<ConfirmedVuln> auditedConfirmed = new ArrayList<>();
        for (ConfirmedVuln cv : survivingConfirmed) {
            if (isAuthClass(cv.type()) && (cv.identityProof() == null || cv.identityProof().isBlank())) {
                allSuspected.add(new SuspectedVuln(
                        cv.type(), cv.title(),
                        "identity_not_proven: 越权类发现缺少身份证据（用的哪个会话上下文验证/是否测过匿名访问/"
                                + "如何确认返回数据属于他人账号 均未说明），已降级为疑似: "
                                + (cv.evidence() == null ? "" : cv.evidence()),
                        cv.verifyCommand(), "MEDIUM", "",
                        cv.payloadUsed() == null ? "" : cv.payloadUsed()));
                rejectionReasons.add("identity_not_proven: '" + cv.title() + "' 越权类 confirmed 缺少身份证据，降级为疑似");
            } else {
                auditedConfirmed.add(cv);
            }
        }
        survivingConfirmed = auditedConfirmed;

        // Cross-check against the Stage 5 programmatic auth test (when run).
        if (authTestResult != null) {
            boolean hasAuthConfirmed = survivingConfirmed.stream()
                    .anyMatch(cv -> isAuthClass(cv.type()));
            if (!hasAuthConfirmed
                    && authTestResult.verdict() == com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict.VULNERABLE) {
                rejectionReasons.add(String.format(
                        "漏报提醒: Stage 5 程序化鉴权测试确认越权（%s，相似度 %.0f%%），但 verdict 未列出对应 confirmed",
                        authTestResult.vulnType(), authTestResult.maxSimilarity() * 100));
            }
            if (hasAuthConfirmed
                    && authTestResult.verdict() == com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict.SAFE) {
                rejectionReasons.add("软冲突: Stage 5 程序化鉴权测试结果为 SAFE，但 LLM 判定了越权类 confirmed，请人工复核其身份证据");
            }
        }

        String finalRisk = overallRisk;
        String riskNote = "";
        if ("HIGH".equalsIgnoreCase(overallRisk) && survivingConfirmed.isEmpty()) {
            finalRisk = allSuspected.isEmpty() ? "LOW" : "MEDIUM";
            riskNote = " [校验: LLM 声称 HIGH 但无通过校验的 confirmed，已降级为 " + finalRisk + "]";
            rejectionReasons.add("风险降级: LLM 声称 HIGH 但无通过校验的 confirmed，降为 " + finalRisk);
        }

        String infoNote = "";
        if (!removedInfo.isEmpty()) {
            infoNote = " [校验: " + removedInfo.size() + " 个信息级/加固类发现已从 confirmed/suspected 移除并建议归入加固项: "
                    + String.join("; ", removedInfo) + "]";
            rejectionReasons.add("信息级移除: " + String.join("; ", removedInfo));
        }

        String finalSummary = summary;
        if (!riskNote.isEmpty() || !infoNote.isEmpty()) {
            StringBuilder sb = new StringBuilder(summary == null ? "" : summary);
            if (!sb.isEmpty() && sb.charAt(sb.length() - 1) != ' ') sb.append(' ');
            if (!riskNote.isEmpty()) sb.append(riskNote.trim()).append(' ');
            if (!infoNote.isEmpty()) sb.append(infoNote.trim());
            finalSummary = sb.toString().trim();
        }

        return new FinalVerdict(finalRisk, survivingConfirmed, allSuspected,
                finalSummary, recommendations, totalTokensUsed, rejectionReasons);
    }

    /** Auth-class type check for the identity audit: IDOR / unauthorized /
     *  privilege escalation / auth bypass. */
    public static boolean isAuthClass(String type) {
        if (type == null) return false;
        String t = type.toLowerCase(java.util.Locale.ROOT);
        return t.contains("越权") || t.contains("未授权") || t.contains("授权")
                || t.contains("idor") || t.contains("bac") || t.contains("auth")
                || t.contains("access");
    }

    /** Convenience: validate an existing FinalVerdict. Defaults to Agent's
     *  lenient mode (requireAnomaly=false) since this overload exists for
     *  AgentLoop's use. */
    public static FinalVerdict validate(FinalVerdict verdict, List<PayloadResult> payloadResults) {
        return validate(verdict, payloadResults, false);
    }

    public static FinalVerdict validate(FinalVerdict verdict, List<PayloadResult> payloadResults,
                                         boolean requireAnomaly) {
        return validate(verdict, payloadResults, requireAnomaly, null);
    }

    /** Validate an existing FinalVerdict with access to the Stage 5 auth test
     *  result (Agent mode passes authTool.getLastResult()). */
    public static FinalVerdict validate(FinalVerdict verdict, List<PayloadResult> payloadResults,
                                         boolean requireAnomaly,
                                         com.flechazo.apisentinel.auth.AuthTestResult authTestResult) {
        return validate(verdict.overallRisk(), verdict.confirmedVulns(), verdict.suspectedVulns(),
                verdict.summary(), verdict.recommendations(), verdict.totalTokensUsed(),
                payloadResults, requireAnomaly, authTestResult);
    }

    /**
     * Find a PayloadResult matching the cited payload. Tries the Pipeline-mode
     * shape first (testCase().payload() text match), then falls back to
     * Agent-mode shape (testCase is null; match against the raw sentRequest
     * text instead, since SendRequestTool doesn't attach a TestCase).
     *
     * Both the literal and URL-decoded forms of sentRequest are checked: the
     * LLM typically cites a payload in human-readable form (e.g. "' OR
     * '1'='1"), but the actual raw HTTP request may have it percent-encoded
     * (e.g. "%27%20OR%20%271%27%3D%271") — a literal-only substring check
     * would miss this and wrongly demote a genuinely-verified finding.
     */
    public static PayloadResult findPayloadResult(List<PayloadResult> results, String citedPayload) {
        if (citedPayload == null || citedPayload.isBlank() || results == null) return null;
        String cited = citedPayload.trim();

        for (PayloadResult pr : results) {
            if (pr.testCase() != null && pr.testCase().payload() != null
                    && !pr.testCase().payload().isBlank()) {
                String tcPayload = pr.testCase().payload();
                if (tcPayload.equals(cited) || tcPayload.contains(cited) || cited.contains(tcPayload)) {
                    return pr;
                }
            }
        }
        for (PayloadResult pr : results) {
            if (pr.sentRequest() == null) continue;
            if (pr.sentRequest().contains(cited)) return pr;
            String decodedRequest = tryUrlDecode(pr.sentRequest());
            if (decodedRequest != null && decodedRequest.contains(cited)) return pr;
        }
        return null;
    }

    /** Best-effort URL-decode; returns null on malformed input rather than throwing. */
    private static String tryUrlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Returns a copy of payloadResults where any entry matching a surviving
     * ConfirmedVuln's payloadUsed() has anomalyDetected forced to true.
     *
     * Agent mode's send_request tool has no baseline comparison (unlike
     * Pipeline's RequestExecutionEngine), so every PayloadResult it produces
     * has anomalyDetected=false regardless of outcome — the Repeater/任务中心
     * table's "验证结果" column reads that flag directly, so without this,
     * the exact payload the final verdict confirmed as a real vulnerability
     * still displayed "✓ 无风险". Call this AFTER validate() (verdict must
     * already be the post-cross-validation one) so a hallucinated "confirmed"
     * claim that got demoted to suspected doesn't incorrectly paint its row.
     *
     * PayloadResult is a record — the match is replaced with a new instance
     * (only anomalyDetected differs) rather than mutated in place.
     */
    public static List<PayloadResult> markConfirmedPayloads(FinalVerdict verdict, List<PayloadResult> payloadResults) {
        if (verdict == null || payloadResults == null || payloadResults.isEmpty()
                || verdict.confirmedVulns() == null || verdict.confirmedVulns().isEmpty()) {
            return payloadResults;
        }
        List<PayloadResult> marked = new ArrayList<>(payloadResults);
        for (ConfirmedVuln cv : verdict.confirmedVulns()) {
            PayloadResult match = findPayloadResult(marked, cv.payloadUsed());
            // Never force-mark a WAF-suspected response as anomaly: the
            // "signal" may be the block page. validate() already demotes
            // blocked confirms; this guards the needs-review band too.
            if (match != null && !match.anomalyDetected() && !match.isWafSuspected()) {
                int idx = marked.indexOf(match);
                marked.set(idx, new PayloadResult(match.testCase(), match.sentRequest(), match.receivedResponse(),
                        match.statusCode(), match.responseTimeMs(), true, match.sentAtMs(), match.executionIndex(),
                        match.wafVendor(), match.wafScore()));
            }
        }
        return marked;
    }
}
