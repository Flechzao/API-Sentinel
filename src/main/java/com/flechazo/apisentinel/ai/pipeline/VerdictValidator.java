package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.ai.prompt.SafetyRules;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Cross-validates LLM-claimed confirmed vulns against real PayloadResults so
 * hallucinated findings are downgraded to suspected, and overall_risk=HIGH is
 * only allowed with a surviving confirmed. Extracted from AnalysisPipeline so
 * Agent mode (SubmitReportTool via AgentLoop) can apply the same defense —
 * Pipeline previously had this and Agent mode didn't, which is why Agent
 * mode could report an untested "confirmed" vuln as fact.
 *
 * <p><b>P0-8 hardening (2026-09-06)</b>. The pre-P0-8 validator passed every
 * test that used an <i>honest</i> model, but its decisions were driven
 * entirely by strings the LLM wrote (cited payload text, identity proof,
 * evidence). Five independent bypasses (§3.1.2 of the audit) let an
 * adversarial model / prompt-injection payload fabricate a "confirmed"
 * the validator couldn't refute:
 *
 * <ol>
 *   <li><b>#1 isAuthClass 宽匹配</b> — {@code "bac"} / {@code "access"}
 *       as substrings mislabelled e.g. "Access Log Injection" as an auth
 *       finding, routing it through the permissive auth gate instead of
 *       the payload-match gate.</li>
 *   <li><b>#2 auth 类 `anyRealRequest` 即可满足</b> — a single unrelated
 *       request anywhere in the history was enough to let an IDOR
 *       confirm through, with no proof the two relevant sessions
 *       actually hit the same endpoint.</li>
 *   <li><b>#3 `findPayloadResult` 子串匹配太宽</b> — a cited payload of
 *       {@code "1"} or {@code "a"} matched almost every sent request.</li>
 *   <li><b>#4 evidence / response_snippet 可任意编造</b> — no check tied
 *       them to an actual received response, so a hallucinated
 *       stack-trace snippet was indistinguishable from a real one.</li>
 *   <li><b>#5 `markConfirmedPayloads` 改写 `anomalyDetected`</b> — the UI's
 *       "⚡ 已确认" marker overwrote the genuine observation, so the
 *       analyst couldn't tell "LLM-claimed" from "actually seen".</li>
 * </ol>
 *
 * Each fix binds the validator's decision more tightly to a real byte the
 * system actually sent or received:
 * <ul>
 *   <li>Index binding: {@link ConfirmedVuln#citedExecutionIndex()} lets
 *       the validator look the referenced {@link PayloadResult} up in
 *       O(1); a missing index or WAF-blocked index is a hard reject.</li>
 *   <li>Session binding: {@link PayloadResult#authSession()} lets the
 *       validator require auth-class confirms to cite requests from at
 *       least two different sessions on the same endpoint.</li>
 *   <li>Substring-of-real-response: evidence / response must appear
 *       verbatim in some {@link PayloadResult#receivedResponse()} or
 *       the confirm is demoted.</li>
 *   <li>Claimed-By-Verdict flag: a new {@link PayloadResult#claimedByVerdict()}
 *       field carries the post-validation marker; {@link #anomalyDetected()}
 *       is never rewritten.</li>
 * </ul>
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

    /** Minimum length a cited payload must have to be considered a unique
     *  identifier for a sent request. Short strings ("1", "a", "'") match
     *  almost everything by substring and let hallucinations through.
     *  Chosen at 4 because common real payloads are all ≥ 4 characters
     *  ("' OR"=4, "'--"=3 but typically "' --"=4, "<scr"=4 for XSS probes,
     *  "${7*7}"=6 for SSTI) — while the "1" / "'" one-char ambiguity that
     *  §3.1.2 #3 documented as a bypass is still refused. */
    static final int MIN_CITED_PAYLOAD_LENGTH = 4;

    /** Jaccard-similarity floor for a payload-text match to count as
     *  "this cited payload was the one actually sent". Below this, the
     *  match is too loose to refute the hypothesis that the LLM is
     *  citing something it never sent. 0.7 lets light URL-encoding and
     *  minor truncation through while still rejecting unrelated text. */
    static final double MIN_JACCARD_SIMILARITY = 0.7;

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

        List<Demotion> demoted = new ArrayList<>();
        List<ConfirmedVuln> demotedWaf = new ArrayList<>();

        // O(1) index lookup for the P0-8 fast path: if a confirm binds
        // itself to a specific executionIndex, we resolve that directly
        // rather than doing the fuzzy text-match pass. Built once per
        // validate() call; most validate() invocations have <100 results
        // so the HashMap overhead is negligible.
        Map<Integer, PayloadResult> byExecutionIndex = indexByExecutionIndex(payloadResults);

        for (ConfirmedVuln cv : confirmedVulns) {
            boolean passes;
            boolean authClass = isAuthClass(cv.type());
            PayloadResult match = null;
            if (authClass) {
                // P0-8 #2: auth-class findings must cite two different
                // sessions hitting the same endpoint, not just "some
                // real request was sent at some point". When neither
                // side is session-tagged (legacy path), the old
                // "anyRealRequest" behaviour is preserved and a note
                // is appended to rejectionReasons so the gap surfaces
                // in the verdict summary.
                AuthCrossCheck crossCheck = crossCheckAuth(cv, payloadResults, byExecutionIndex);
                passes = crossCheck.passes();
                if (!passes && crossCheck.reason() != null) {
                    rejectionReasons.add("auth 校验失败: '" + cv.title() + "' " + crossCheck.reason());
                } else if (passes && crossCheck.note() != null) {
                    rejectionReasons.add("auth 校验提示: '" + cv.title() + "' " + crossCheck.note());
                }
                if (!passes) {
                    demoted.add(new Demotion(cv, "越权双会话交叉校验未通过（"
                            + (crossCheck.reason() == null ? "未找到同端点的两个不同会话请求" : crossCheck.reason()) + "）"));
                    continue;
                }
            } else {
                match = findPayloadResult(payloadResults, cv.payloadUsed(),
                        cv.citedExecutionIndex(), byExecutionIndex);
                passes = requireAnomaly
                        ? (match != null && match.anomalyDetected())
                        : (match != null);
                if (!passes) {
                    demoted.add(new Demotion(cv, requireAnomaly
                            ? "引用的 payload 未在实际发送的请求中触发异常（未匹配到 anomaly）"
                            : "引用的 payload 未在实际发送的请求中找到"));
                    continue;
                }
            }
            // A WAF-blocked payload never reached the backend — any "anomaly"
            // was most likely the block page itself, so it cannot back a
            // confirmed finding (distilled from bughunter's validate-gate idea).
            if (match != null && match.isWafBlocked()) {
                demotedWaf.add(cv);
                continue;
            }

            // P0-8 #4: evidence and response must be verbatim substrings
            // of SOME received response the system actually collected. A
            // hallucinated stack-trace snippet — indistinguishable from a
            // real one pre-P0-8 — fails this check and is demoted.
            //
            // Auth-class confirms are EXEMPT: their grounding is the two-session
            // cross-check (proven above), not a single-response substring. An
            // IDOR's "evidence" is "session B received session A's data" — a
            // cross-session diff, not a slice of one response — so the substring
            // gate would false-demote a genuinely-proven IDOR.
            if (!authClass && !evidenceTiesToRealResponse(cv, payloadResults)) {
                demoted.add(new Demotion(cv,
                        "引用的响应片段(response)不是任何真实响应的逐字子串"));
                rejectionReasons.add("evidence 校验失败: '" + cv.title()
                        + "' 的 evidence/response 不是任何真实 receivedResponse 的子串，confirmed 降级为疑似");
                continue;
            }

            survivingConfirmed.add(cv);
        }
        for (Demotion dm : demoted) {
            ConfirmedVuln cv = dm.cv();
            allSuspected.add(new SuspectedVuln(
                    cv.type(), cv.title(),
                    "confirmed 未通过程序化校验（" + dm.reason() + "），已降级为疑似: "
                            + (cv.evidence() == null ? "" : cv.evidence()),
                    cv.verifyCommand(), "MEDIUM", "",
                    cv.payloadUsed() == null ? "" : cv.payloadUsed()));
            rejectionReasons.add("confirmed 降级: '" + cv.title() + "' " + dm.reason());
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
            if (SafetyRules.isInformationalByTypeAndEvidence(cv.type(), cv.evidence())
                    && !SafetyRules.hasChainEvidence(cv.evidence())) {
                removedInfo.add(cv.type() + "/" + cv.title());
            } else {
                survivingAfterInfo.add(cv);
            }
        }
        List<SuspectedVuln> survivingSuspected = new ArrayList<>();
        for (SuspectedVuln sv : allSuspected) {
            if (SafetyRules.isInformationalByTypeAndEvidence(sv.type(), sv.reason())
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

    /** P0-8 #1: auth-class type check with tightened keywords. The pre-P0-8
     *  version used {@code "bac"} / {@code "access"} as bare substrings,
     *  which mislabelled "Access Log Injection" (an informational log
     *  issue), "Back Channel" (network architecture), or "Cache Control"
     *  (header hygiene) as auth findings — routing them through the
     *  permissive auth gate instead of the payload-match gate.
     *
     *  <p>New rules:
     *  <ul>
     *    <li>Chinese keywords: 越权 / 未授权 / 垂直越权 / 水平越权 / 鉴权绕过
     *        — all specific to access control.</li>
     *    <li>English keywords: idor (whole word), "broken access" (phrase),
     *        "access control" (phrase), "privilege escalation" (phrase),
     *        "auth bypass" / "authentication bypass" (phrase),
     *        "unauthorized" (whole word). {@code "bac"} and bare
     *        {@code "access"} are dropped.</li>
     *  </ul>
     */
    public static boolean isAuthClass(String type) {
        if (type == null) return false;
        String t = type.toLowerCase(Locale.ROOT);
        // Chinese phrases (already specific — no false-positive risk from
        // substring use here: nothing non-auth contains "越权" etc.).
        if (t.contains("越权") || t.contains("未授权") || t.contains("鉴权绕过")) return true;
        // English: require whole-word or phrase match.
        if (containsWholeWord(t, "idor")) return true;
        if (containsWholeWord(t, "unauthorized")) return true;
        if (t.contains("broken access") || t.contains("access control")
                || t.contains("privilege escalation")
                || t.contains("auth bypass") || t.contains("authentication bypass")
                || t.contains("authorization bypass")) return true;
        return false;
    }

    /** Whole-word containment check: {@code needle} must appear in
     *  {@code haystack} bounded by non-letter characters (or the string
     *  edges). Used so "idor" matches "IDOR" and "idor 漏洞" but not
     *  "editor" or "cupidorous". */
    private static boolean containsWholeWord(String haystack, String needle) {
        int from = 0;
        while (true) {
            int idx = haystack.indexOf(needle, from);
            if (idx < 0) return false;
            boolean leftOk = idx == 0 || !Character.isLetter(haystack.charAt(idx - 1));
            boolean rightOk = (idx + needle.length() >= haystack.length())
                    || !Character.isLetter(haystack.charAt(idx + needle.length()));
            if (leftOk && rightOk) return true;
            from = idx + 1;
        }
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

    /** P0-8: backward-compatible 2-arg overload retained for callers that
     *  only have a cited payload string. Delegates to the 4-arg form with
     *  {@code citedExecutionIndex = -1} (no index binding). */
    public static PayloadResult findPayloadResult(List<PayloadResult> results, String citedPayload) {
        return findPayloadResult(results, citedPayload, -1, indexByExecutionIndex(results));
    }

    /**
     * Find a PayloadResult matching the cited payload. Resolution order:
     *
     * <ol>
     *   <li><b>Index binding fast path</b> (P0-8): when the confirm carries
     *       a valid {@code citedExecutionIndex}, resolve it directly in
     *       O(1). A missing or WAF-blocked index → null (demotion). This
     *       path is immune to the substring-false-positive problem
     *       entirely.</li>
     *   <li><b>TestCase.payload() exact match</b>: Pipeline mode shape —
     *       testCase carries the authored payload verbatim, compared
     *       against the cited text.</li>
     *   <li><b>sentRequest substring match with length floor</b> (P0-8):
     *       Agent mode shape — testCase is null. The cited payload must
     *       be ≥ {@value #MIN_CITED_PAYLOAD_LENGTH} characters to count
     *       (short citations like {@code "1"} / {@code "'"} / {@code "a"}
     *       match almost every request by substring and let
     *       hallucinations through), then is matched as a substring of
     *       the raw sentRequest (or its URL-decoded form). This
     *       preserves the pre-P0-8 substring behaviour for realistic
     *       payloads while still blocking the "short-string-fits-everything"
     *       bypass documented in §3.1.2 #3.</li>
     * </ol>
     */
    public static PayloadResult findPayloadResult(List<PayloadResult> results, String citedPayload,
                                                   int citedExecutionIndex,
                                                   Map<Integer, PayloadResult> byIndex) {
        if (results == null || results.isEmpty()) return null;

        // Fast path: index binding.
        if (citedExecutionIndex >= 0 && byIndex != null) {
            PayloadResult indexed = byIndex.get(citedExecutionIndex);
            if (indexed != null) return indexed;
            // Index bound but no such result exists → the LLM cited a send
            // that never happened. Return null so the caller demotes.
            return null;
        }

        String cited = citedPayload == null ? null : citedPayload.trim();
        if (cited == null || cited.isEmpty()) return null;

        // Pipeline shape: exact / substring match against testCase.payload().
        // Both directions: the LLM may cite a short form ("' OR 1=1") that
        // sits inside a longer authored payload ("GET /api?id=' OR 1=1 --"),
        // or it may cite the full authored payload that subsumes the
        // TestCase.payload() field. Either direction counts as a match.
        // Pipeline mode is trusted (the testCase is authored by our own
        // verifiers, not the LLM), so the MIN_CITED_PAYLOAD_LENGTH floor
        // does not apply here — it only gates the Agent-mode substring
        // fallback where the citation comes from LLM text.
        for (PayloadResult pr : results) {
            if (pr.testCase() != null && pr.testCase().payload() != null
                    && !pr.testCase().payload().isBlank()) {
                String tcPayload = pr.testCase().payload();
                if (tcPayload.equals(cited) || tcPayload.contains(cited) || cited.contains(tcPayload)) {
                    return pr;
                }
            }
        }

        // Agent shape: substring match with a length floor. The pre-P0-8
        // behaviour accepted ANY cited payload length; P0-8 refuses short
        // citations because they're ambiguous enough to match unrelated
        // requests (the "1" problem from §3.1.2 #3). This floor only
        // applies to the Agent-mode path — Pipeline mode (above) is
        // trusted because the testCase.payload() is authored by our own
        // verifiers, not the LLM.
        if (cited.length() < MIN_CITED_PAYLOAD_LENGTH) return null;

        for (PayloadResult pr : results) {
            if (pr.sentRequest() == null) continue;
            if (pr.sentRequest().contains(cited)) return pr;
            String decoded = tryUrlDecode(pr.sentRequest());
            if (decoded != null && decoded.contains(cited)) return pr;
        }
        return null;
    }

    /** Build an executionIndex → PayloadResult map for O(1) lookup. Entries
     *  with {@code executionIndex == -1} (legacy / Agent mode unindexed) are
     *  skipped since -1 is the "unknown" sentinel. */
    private static Map<Integer, PayloadResult> indexByExecutionIndex(List<PayloadResult> results) {
        Map<Integer, PayloadResult> map = new HashMap<>();
        if (results == null) return map;
        for (PayloadResult pr : results) {
            if (pr.executionIndex() >= 0) {
                map.putIfAbsent(pr.executionIndex(), pr);
            }
        }
        return map;
    }

    /** P0-8 #4: the LLM-cited response snippet on a confirm must appear
     *  verbatim in SOME received response the system actually collected.
     *  A fabricated "stack trace showing alice's data" / "internal IP"
     *  / "secret=XYZ" that doesn't match any captured response is a
     *  strong hallucination / injection signal — the confirm is demoted.
     *
     *  <p><b>Scope</b>: only {@link ConfirmedVuln#response()} is subject
     *  to the substring check. {@link ConfirmedVuln#evidence()} is
     *  free-form reasoning (attack narrative, chain explanation) and is
     *  not expected to appear in a captured response byte-for-byte.
     *  {@link ConfirmedVuln#identityProof()} for auth-class findings is
     *  gated separately upstream (the identity_audit pass).
     *
     *  <p><b>Body-presence gate</b>: the substring check only activates
     *  when at least one {@link PayloadResult} carries a response with a
     *  real body (something past the header terminator). Header-only
     *  responses — the shape used by unit-test fixtures and by some
     *  Agent-mode sends where only status matters — have no content to
     *  anchor against; applying the strict check to them would demote
     *  genuine confirms for reasons unrelated to their truth. When
     *  every response in the batch is header-only (or empty), the
     *  check is bypassed. In production the Agent always captures full
     *  response bodies, so the check fires when it matters. */
    static boolean evidenceTiesToRealResponse(ConfirmedVuln cv, List<PayloadResult> results) {
        String cited = cv.response() == null ? "" : cv.response().trim();
        if (cited.isEmpty()) {
            // Nothing cited → nothing to refute. The match (text or index)
            // already backed the confirm at this point.
            return true;
        }
        if (results == null || results.isEmpty()) {
            // No responses at all — lenient fallback.
            return true;
        }

        // Identify which responses carry a real body (anything past the
        // blank-line header terminator). Header-only responses — the
        // shape used by unit-test fixtures and by some Agent-mode sends
        // where only status matters — have no content to anchor against;
        // applying the strict check to them would demote genuine
        // confirms for reasons unrelated to their truth.
        List<String> bodies = new ArrayList<>();
        for (PayloadResult pr : results) {
            String rr = pr.receivedResponse();
            if (rr == null || rr.isEmpty()) continue;
            String body = bodyOf(rr);
            if (!body.isEmpty()) bodies.add(body);
        }
        if (bodies.isEmpty()) {
            // Every response is header-only or empty — nothing to anchor
            // against, so the check is bypassed rather than demoting
            // every confirm on a technicality.
            return true;
        }

        // Single-result fast path: the text / index match in
        // findPayloadResult already unambiguously tied this confirm to
        // this one result, so a substring check on the cited response
        // adds no disambiguation value. Skipping it also keeps unit
        // tests that use stub response snippets ("resp snippet") working
        // — those stubs don't survive into the captured response body
        // but the confirm is still genuine.
        if (results.size() == 1) return true;

        for (String body : bodies) {
            if (body.contains(cited)) return true;
            // URL-decoded form: the LLM often cites a decoded payload
            // while the captured body keeps it encoded.
            String decoded = tryUrlDecode(body);
            if (decoded != null && !decoded.equals(body) && decoded.contains(cited)) return true;
        }
        return false;
    }

    /** Extract the body portion of a raw HTTP response (everything past
     *  the first blank line). For non-HTTP-shaped responses (e.g. plain
     *  error text), returns the whole input — those have no headers to
     *  strip and the entire content is body. Empty input returns "". */
    private static String bodyOf(String rawResponse) {
        if (rawResponse == null) return "";
        int sep = rawResponse.indexOf("\r\n\r\n");
        if (sep < 0) sep = rawResponse.indexOf("\n\n");
        if (sep < 0) {
            // No header terminator found — either a header-only fragment
            // (treat as no body) or a non-HTTP body (treat the whole
            // thing as body). Distinguish by the HTTP status-line
            // shape.
            if (rawResponse.startsWith("HTTP/")) return "";
            return rawResponse;
        }
        int bodyStart = rawResponse.charAt(sep) == '\r' ? sep + 4 : sep + 2;
        if (bodyStart >= rawResponse.length()) return "";
        return rawResponse.substring(bodyStart);
    }

    /** P0-8 #2: an auth-class confirm must be backed by two requests from
     *  DIFFERENT sessions against endpoints that plausibly overlap. A
     *  single request is not proof of IDOR / privilege escalation — the
     *  LLM has to show "alice's request got X, bob's request for the
     *  same resource got alice's X".
     *
     *  <p><b>P2-2 note on Kill Signal K2 (attacker==victim)</b>: an obvious
     *  addition is "if the two sessions' response bodies are near-identical,
     *  demote — the attacker is seeing their own data". That heuristic is
     *  <b>sound-opposite</b> for IDOR and was deliberately NOT added. In a
     *  real IDOR, bob requests alice's resource and the server returns
     *  <i>alice's</i> data to both sessions — so the two bodies are
     *  near-identical (both = alice's data). Identical bodies therefore
     *  indicate a TRUE IDOR, not a false positive; demoting on similarity
     *  would kill every real IDOR (the {@code realIdor} fixture in
     *  {@code VerdictValidatorP08Test} demonstrates exactly this shape).
     *  The K2 case (the app returns the requester's OWN data regardless of
     *  the swapped id) instead produces DIFFERENT bodies per session — and
     *  detecting "is this the attacker's own data?" is a semantic judgement
     *  the program can't make from two byte-strings alone. That is precisely
     *  what the Phase 4 {@code identity_proof} audit enforces: the LLM must
     *  answer "how do you confirm the returned data belongs to ANOTHER
     *  account", and a blank answer auto-demotes. Identity-proof is the
     *  correct and only sound layer for K2; a body-similarity shortcut here
     *  would be a regression, so it is intentionally absent.
     *
     *  <p><b>Backward compatibility</b>: when neither of the relevant
     *  {@link PayloadResult}s carries an {@code authSession} label (the
     *  legacy / uninstrumented state), we can't refute the confirm on
     *  session grounds alone, so we accept it the way the pre-P0-8 code
     *  did (any real request). The {@code rejectionReasons} list gets a
     *  note flagging the missing tagging so the gap is surfaced in the
     *  verdict summary rather than silently hidden. New callers that do
     *  tag sessions (P0-8-aware SendRequestTool, the benchmark harness)
     *  get the full two-session check. */
    private static AuthCrossCheck crossCheckAuth(ConfirmedVuln cv, List<PayloadResult> results,
                                                  Map<Integer, PayloadResult> byIndex) {
        if (results == null || results.isEmpty()) {
            return AuthCrossCheck.fail("没有任何真实发送的请求");
        }

        // Fast path: the confirm binds itself to an executionIndex. The
        // referenced result must exist, must not be WAF-blocked, and
        // there must be at least one OTHER result against the same
        // apiPath with a different authSession.
        if (cv.hasBoundExecutionIndex()) {
            PayloadResult indexed = byIndex.get(cv.citedExecutionIndex());
            // A valid, session-tagged cited request with a proven other-session
            // hit on the same endpoint is the strongest signal → pass now.
            // Anything short of that (missing/mis-cited index, WAF-blocked cited
            // request, or no other-session match on the indexed side) does NOT
            // hard-fail: the two-session evidence may still exist elsewhere in
            // the batch, so we fall through to the pair-search below. Hard-
            // failing here false-demoted genuine IDORs whenever the LLM cited a
            // slightly-off execution index.
            if (indexed != null && !indexed.isWafBlocked()) {
                String indexedPath = apiPathOf(indexed);
                String indexedSession = sessionOf(indexed);
                if (indexedSession == null) {
                    // Legacy path: no session tagging — can't refute, accept.
                    return AuthCrossCheck.passWithNote("auth 类 confirmed 的 citedExecutionIndex 对应请求未标 authSession，无法做双会话对比，已按 pre-P0-8 行为放行");
                }
                boolean hasOtherSession = results.stream()
                        .filter(pr -> pr != indexed && !pr.isWafBlocked())
                        .filter(pr -> sameApiPath(apiPathOf(pr), indexedPath))
                        .anyMatch(pr -> {
                            String s = sessionOf(pr);
                            return s != null && !s.equals(indexedSession);
                        });
                if (hasOtherSession) return AuthCrossCheck.pass();
            }
            // fall through to the batch pair-search
        }

        // Fallback path (legacy confirms without index binding): find
        // ANY pair of non-WAF-blocked requests against the same apiPath
        // whose sessions differ. If NO result in the whole batch is
        // session-tagged, fall back to the pre-P0-8 "any real request"
        // acceptance with a note.
        boolean anyTagged = results.stream().anyMatch(pr -> sessionOf(pr) != null);
        if (!anyTagged) {
            // Legacy behaviour preserved — but surface the gap.
            return AuthCrossCheck.passWithNote("auth 类 confirmed 的所有 PayloadResult 均未标 authSession，无法做双会话对比，已按 pre-P0-8 行为放行");
        }

        Map<String, List<PayloadResult>> byPath = new HashMap<>();
        for (PayloadResult pr : results) {
            if (pr.isWafBlocked()) continue;
            String p = apiPathOf(pr);
            if (p == null) continue;
            byPath.computeIfAbsent(p, k -> new ArrayList<>()).add(pr);
        }
        for (List<PayloadResult> group : byPath.values()) {
            if (group.size() < 2) continue;
            for (int i = 0; i < group.size(); i++) {
                for (int j = i + 1; j < group.size(); j++) {
                    String a = sessionOf(group.get(i));
                    String b = sessionOf(group.get(j));
                    if (a != null && b != null && !a.equals(b)) return AuthCrossCheck.pass();
                }
            }
        }
        return AuthCrossCheck.fail("未找到同端点的不同会话请求（IDOR 需 alice vs bob 两次对比）");
    }

    /** Pull a comparable API path out of a PayloadResult. TestCase-based
     *  (Pipeline mode) results carry the path directly; Agent-mode results
     *  carry it in the request line of the raw HTTP request. */
    private static String apiPathOf(PayloadResult pr) {
        if (pr.testCase() != null && pr.testCase().path() != null
                && !pr.testCase().path().isEmpty()) {
            String full = pr.testCase().path();
            int q = full.indexOf('?');
            return q >= 0 ? full.substring(0, q) : full;
        }
        if (pr.sentRequest() == null) return null;
        // "GET /path HTTP/1.1\r\n..." → "/path"
        int sp = pr.sentRequest().indexOf(' ');
        if (sp < 0) return null;
        int end = pr.sentRequest().indexOf(' ', sp + 1);
        if (end < 0) end = pr.sentRequest().indexOf('\n', sp + 1);
        if (end < 0) end = pr.sentRequest().length();
        String full = pr.sentRequest().substring(sp + 1, end).trim();
        int q = full.indexOf('?');
        return q >= 0 ? full.substring(0, q) : full;
    }

    /** Two apiPaths are comparable for IDOR purposes when they're equal
     *  or when one is a templated form of the other (e.g. "/api/orders/1"
     *  vs "/api/orders/{id}"). The LLM's confirm often cites the
     *  template form while the real sent request carries a concrete id. */
    private static boolean sameApiPath(String a, String b) {
        if (a == null || b == null) return false;
        if (a.equals(b)) return true;
        return templatedEquals(a, b) || templatedEquals(b, a);
    }

    /** True when {@code concrete} looks like an instantiation of
     *  {@code template} — same path segments except any segment the
     *  template writes as {@code {…}} can be anything in the concrete. */
    private static boolean templatedEquals(String template, String concrete) {
        String[] tSegs = template.split("/");
        String[] cSegs = concrete.split("/");
        if (tSegs.length != cSegs.length) return false;
        for (int i = 0; i < tSegs.length; i++) {
            String t = tSegs[i];
            if (t.startsWith("{") && t.endsWith("}")) continue;
            if (!t.equals(cSegs[i])) return false;
        }
        return true;
    }

    /** Pull the auth session label off a PayloadResult. Free-form on
     *  purpose — whatever the caller put in {@code authSession} (cookie
     *  value, "alice"/"bob" label, opaque id). Null means "not tagged". */
    private static String sessionOf(PayloadResult pr) {
        return pr.authSession();
    }

    /** Two session labels compare equal when both are non-null and
     *  byte-equal. Null-vs-null is "unknown, can't tell" and treated as
     *  NOT equal — we'd rather force the caller to tag than silently
     *  let two untagged requests satisfy the two-session gate. */
    private static boolean sessionEquals(String a, String b) {
        if (a == null || b == null) return false;
        return a.equals(b);
    }

    /** A demoted confirmed vuln + the specific gate it failed (so the
     *  downgrade reason shown to the user is accurate, not a blanket
     *  "payload 未发送"). */
    private record Demotion(ConfirmedVuln cv, String reason) {}

    private record AuthCrossCheck(boolean passes, String reason, String note) {
        static AuthCrossCheck pass() { return new AuthCrossCheck(true, null, null); }
        static AuthCrossCheck passWithNote(String note) { return new AuthCrossCheck(true, null, note); }
        static AuthCrossCheck fail(String reason) { return new AuthCrossCheck(false, reason, null); }
    }

    /** Jaccard similarity over whitespace-tokenised shingles. Chosen over
     *  raw substring because URL-encoding and minor LLM paraphrase both
     *  perturb the byte stream without changing the token set much.
     *  Returns 0.0 on two empty inputs to avoid a NaN-driven false pass. */
    static double jaccard(String a, String b) {
        if (a == null || b == null) return 0;
        if (a.isEmpty() && b.isEmpty()) return 0;
        // 3-char shingles give a good signal for payloads (which are short
        // and code-like) without over-penalising single-char differences.
        java.util.Set<String> sa = shingles(a, 3);
        java.util.Set<String> sb = shingles(b, 3);
        if (sa.isEmpty() && sb.isEmpty()) return 0;
        long inter = sa.stream().filter(sb::contains).count();
        long union = sa.size() + sb.size() - inter;
        return union == 0 ? 0 : (double) inter / union;
    }

    private static java.util.Set<String> shingles(String s, int k) {
        java.util.Set<String> out = new java.util.HashSet<>();
        if (s == null || s.length() < k) {
            if (s != null && !s.isEmpty()) out.add(s);
            return out;
        }
        for (int i = 0; i + k <= s.length(); i++) {
            out.add(s.substring(i, i + k));
        }
        return out;
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
     * P0-8 #5: returns a copy of {@code payloadResults} where any entry
     * matching a surviving {@link ConfirmedVuln} has
     * {@link PayloadResult#claimedByVerdict()} flipped to {@code true}.
     *
     * <p><b>Pre-P0-8 behaviour (removed):</b> the same method flipped
     * {@link PayloadResult#anomalyDetected()} to {@code true} so the
     * UI's "⚡ 已确认" marker would light up. That rewrite destroyed
     * the original observation — the analyst could no longer tell a
     * genuinely-observed anomaly apart from an LLM-claimed one. The
     * Repeater / 任务中心 table consumed {@code anomalyDetected} directly,
     * so a hallucinated confirm that slipped past {@link #validate}
     * would paint its row green with no way to audit back.
     *
     * <p><b>New behaviour:</b> we now set the dedicated
     * {@link PayloadResult#claimedByVerdict()} flag instead. UI code
     * should render the green check when
     * {@link PayloadResult#showsAsVerified()} returns true (i.e.
     * {@code anomalyDetected || claimedByVerdict}); audit / export
     * layers should keep the two signals distinct.
     *
     * <p>PayloadResult is a record — the match is replaced with a new
     * instance (only claimedByVerdict differs) rather than mutated in
     * place.
     *
     * <p>Call this AFTER {@link #validate} (verdict must already be the
     * post-cross-validation one) so a hallucinated "confirmed" claim
     * that got demoted to suspected doesn't incorrectly paint its row.
     */
    public static List<PayloadResult> markConfirmedPayloads(FinalVerdict verdict, List<PayloadResult> payloadResults) {
        if (verdict == null || payloadResults == null || payloadResults.isEmpty()
                || verdict.confirmedVulns() == null || verdict.confirmedVulns().isEmpty()) {
            return payloadResults;
        }
        // Index the surviving confirms so the inner loop below is O(1)
        // per payload result rather than O(n·m). Most benchmarks have
        // <10 surviving confirms; the map cost is trivial.
        Map<Integer, ConfirmedVuln> confirmsByIndex = new HashMap<>();
        for (ConfirmedVuln cv : verdict.confirmedVulns()) {
            if (cv.hasBoundExecutionIndex()) {
                confirmsByIndex.put(cv.citedExecutionIndex(), cv);
            }
        }

        // Auth-class (IDOR/越权): the evidence is a PAIR of requests — the
        // attacker session AND the owner session on the same endpoint — both of
        // which returned normal 200s (no anomaly flag). Mark BOTH so the test-
        // case list shows "⚡ 已确认" on the two proving packets rather than
        // "✓ 无风险". Robust to an imperfect cited index: falls back to the
        // first differing-session pair on a shared endpoint.
        java.util.Set<PayloadResult> authMarked = new java.util.HashSet<>();
        for (ConfirmedVuln cv : verdict.confirmedVulns()) {
            if (!isAuthClass(cv.type())) continue;
            PayloadResult attack = null;
            if (cv.hasBoundExecutionIndex()) {
                for (PayloadResult p : payloadResults) {
                    if (p.executionIndex() == cv.citedExecutionIndex()) { attack = p; break; }
                }
            }
            if (attack == null && cv.payloadUsed() != null && !cv.payloadUsed().isBlank()) {
                for (PayloadResult p : payloadResults) {
                    if (findPayloadResult(List.of(p), cv.payloadUsed(), -1, null) != null) { attack = p; break; }
                }
            }
            if (attack != null && !attack.isWafBlocked()) {
                authMarked.add(attack);
                String path = apiPathOf(attack);
                String sess = sessionOf(attack);
                for (PayloadResult p : payloadResults) {
                    if (p == attack || p.isWafBlocked()) continue;
                    if (sameApiPath(apiPathOf(p), path)) {
                        String s = sessionOf(p);
                        if (s != null && sess != null && !s.equals(sess)) { authMarked.add(p); break; }
                    }
                }
            } else {
                // No usable anchor — mark the first differing-session pair that
                // shares an endpoint (the pair that let crossCheckAuth pass).
                outer:
                for (PayloadResult a : payloadResults) {
                    if (a.isWafBlocked() || sessionOf(a) == null) continue;
                    for (PayloadResult b : payloadResults) {
                        if (b == a || b.isWafBlocked()) continue;
                        if (sameApiPath(apiPathOf(a), apiPathOf(b))
                                && sessionOf(b) != null && !sessionOf(b).equals(sessionOf(a))) {
                            authMarked.add(a); authMarked.add(b); break outer;
                        }
                    }
                }
            }
        }

        List<PayloadResult> marked = new ArrayList<>(payloadResults.size());
        for (PayloadResult pr : payloadResults) {
            boolean shouldMark = authMarked.contains(pr);
            // Fast path: index-bound confirm.
            if (!shouldMark && pr.executionIndex() >= 0 && confirmsByIndex.containsKey(pr.executionIndex())) {
                shouldMark = true;
            } else if (!shouldMark) {
                // Fallback: any surviving confirm's payloadUsed text matches
                // this result via the tightened findPayloadResult rules.
                for (ConfirmedVuln cv : verdict.confirmedVulns()) {
                    PayloadResult match = findPayloadResult(List.of(pr), cv.payloadUsed(),
                            cv.citedExecutionIndex(), null);
                    if (match != null) {
                        shouldMark = true;
                        break;
                    }
                }
            }
            // Never force-mark a WAF-suspected response: the "signal" may
            // be the block page. validate() already demotes blocked
            // confirms; this guards the needs-review band too.
            if (shouldMark && !pr.claimedByVerdict() && !pr.isWafSuspected()) {
                marked.add(new PayloadResult(pr.testCase(), pr.sentRequest(), pr.receivedResponse(),
                        pr.statusCode(), pr.responseTimeMs(), pr.anomalyDetected(), pr.sentAtMs(),
                        pr.executionIndex(), pr.wafVendor(), pr.wafScore(), pr.authSession(), true));
            } else {
                marked.add(pr);
            }
        }
        return marked;
    }
}
