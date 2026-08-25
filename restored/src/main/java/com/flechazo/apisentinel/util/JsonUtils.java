package com.flechazo.apisentinel.util;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.pipeline.*;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.PassiveFinding;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.*;

public final class JsonUtils {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .registerTypeAdapter(ApiEntry.class, new ApiEntrySerializer())
            .registerTypeAdapter(ApiEntry.class, new ApiEntryDeserializer())
            .create();

    private JsonUtils() {}

    public static String toJson(List<ApiEntry> entries) {
        JsonObject root = new JsonObject();
        root.addProperty("version", "4.1.0");
        root.addProperty("exportTimestamp", java.time.Instant.now().toString());
        root.add("apis", GSON.toJsonTree(entries));
        return GSON.toJson(root);
    }

    public static List<ApiEntry> fromJson(String json) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonArray apis = root.getAsJsonArray("apis");
        Type listType = new TypeToken<List<ApiEntry>>() {}.getType();
        List<ApiEntry> result = GSON.fromJson(apis, listType);
        return result != null ? result : new ArrayList<>();
    }

    // ======================== Serializer ========================

    private static class ApiEntrySerializer implements JsonSerializer<ApiEntry> {
        @Override
        public JsonElement serialize(ApiEntry e, Type type, JsonSerializationContext ctx) {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", e.getId());
            obj.addProperty("httpMethod", e.getHttpMethod());
            obj.addProperty("apiPath", e.getApiPath());
            obj.addProperty("status", e.getStatus().name());
            obj.addProperty("vulnType", e.getVulnType() != null ? e.getVulnType().name() : null);
            obj.addProperty("result", e.getResult());
            obj.addProperty("note", e.getNote());
            obj.addProperty("domain", e.getDomain());
            obj.addProperty("lastSeenTimestamp", e.getLastSeenTimestamp());
            obj.addProperty("lastRawRequest", e.getLastRawRequest());
            obj.addProperty("lastRawResponse", e.getLastRawResponse());
            obj.addProperty("lastUrl", e.getLastUrl());
            obj.addProperty("lastStatusCode", e.getLastStatusCode());

            // Serialize analysis history
            JsonArray historyArr = new JsonArray();
            for (AnalysisRecord record : e.getAnalysisHistory()) {
                historyArr.add(serializeAnalysisRecord(record));
            }
            obj.add("analysisHistory", historyArr);

            // Serialize passive findings (local zero-AI detections)
            JsonArray pfArr = new JsonArray();
            for (PassiveFinding f : e.getPassiveFindings()) {
                JsonObject fo = new JsonObject();
                fo.addProperty("id", f.id());
                fo.addProperty("source", f.source().name());
                fo.addProperty("risk", f.risk());
                fo.addProperty("category", f.category());
                fo.addProperty("title", f.title());
                fo.addProperty("evidence", f.evidence());
                fo.addProperty("remediation", f.remediation());
                fo.addProperty("detectedAt", f.detectedAt());
                pfArr.add(fo);
            }
            obj.add("passiveFindings", pfArr);

            return obj;
        }

        private JsonObject serializeAnalysisRecord(AnalysisRecord record) {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", record.id());
            obj.addProperty("timestamp", record.timestamp());
            obj.addProperty("mode", record.mode());

            if (record.result() != null) {
                obj.add("result", serializeAnalysisResult(record.result()));
            }

            JsonArray tcArr = new JsonArray();
            if (record.testCases() != null) {
                for (TestCase tc : record.testCases()) {
                    tcArr.add(serializeTestCase(tc));
                }
            }
            obj.add("testCases", tcArr);

            if (record.pipelineResult() != null) {
                obj.add("pipelineResult", serializePipelineResult(record.pipelineResult()));
            }

            if (record.timeline() != null && !record.timeline().isEmpty()) {
                JsonArray tlArr = new JsonArray();
                for (com.flechazo.apisentinel.ui.TimelineEvent ev : record.timeline()) {
                    JsonObject eo = new JsonObject();
                    eo.addProperty("ts", ev.timestamp() != null ? ev.timestamp().toString() : "");
                    eo.addProperty("type", ev.type() != null ? ev.type().name() : "ITERATION");
                    eo.addProperty("summary", ev.summary());
                    eo.addProperty("detail", ev.detail());
                    eo.addProperty("cost", ev.cost());
                    eo.addProperty("colorHint", ev.colorHint() != null ? ev.colorHint().name() : "NEUTRAL");
                    tlArr.add(eo);
                }
                obj.add("timeline", tlArr);
            }

            return obj;
        }

        private JsonObject serializeAnalysisResult(AnalysisResult r) {
            JsonObject obj = new JsonObject();
            obj.addProperty("summary", r.summary());
            obj.addProperty("overallRisk", r.overallRisk().name());
            obj.addProperty("tokensUsed", r.tokensUsed());
            obj.addProperty("analysisTimeMs", r.analysisTimeMs());
            obj.addProperty("modelUsed", r.modelUsed());
            obj.addProperty("error", r.error());

            JsonArray findings = new JsonArray();
            if (r.findings() != null) {
                for (VulnFinding f : r.findings()) {
                    JsonObject fo = new JsonObject();
                    fo.addProperty("type", f.type());
                    fo.addProperty("risk", f.risk());
                    fo.addProperty("confidence", f.confidence());
                    fo.addProperty("title", f.title());
                    fo.addProperty("description", f.description());
                    fo.addProperty("evidence", f.evidence());
                    fo.addProperty("location", f.location());
                    fo.addProperty("remediation", f.remediation());
                    findings.add(fo);
                }
            }
            obj.add("findings", findings);
            return obj;
        }

        private JsonObject serializeTestCase(TestCase tc) {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", tc.name());
            obj.addProperty("category", tc.category());
            obj.addProperty("targetParam", tc.targetParam());
            obj.addProperty("payload", tc.payload());
            obj.addProperty("method", tc.method());
            obj.addProperty("path", tc.path());
            obj.addProperty("body", tc.body());
            obj.addProperty("description", tc.description());
            obj.addProperty("expectedIfVulnerable", tc.expectedIfVulnerable());
            obj.addProperty("riskIfConfirmed", tc.riskIfConfirmed());
            if (tc.headers() != null) {
                JsonObject headers = new JsonObject();
                tc.headers().forEach(headers::addProperty);
                obj.add("headers", headers);
            }
            return obj;
        }

        private JsonObject serializePipelineResult(PipelineResult pr) {
            JsonObject obj = new JsonObject();
            if (pr.trafficAnalysis() != null) {
                obj.add("trafficAnalysis", serializeAnalysisResult(pr.trafficAnalysis()));
            }
            obj.addProperty("sourceCode", pr.sourceCode());

            // Serialize payload results (Stage 4 execution data)
            JsonArray prArr = new JsonArray();
            if (pr.payloadResults() != null) {
                for (PayloadResult payloadResult : pr.payloadResults()) {
                    JsonObject pro = new JsonObject();
                    // Embed test case name/category for reference (full TestCase is in AnalysisRecord.testCases)
                    if (payloadResult.testCase() != null) {
                        pro.addProperty("testCaseName", payloadResult.testCase().name());
                        pro.addProperty("testCaseCategory", payloadResult.testCase().category());
                    }
                    pro.addProperty("sentRequest", payloadResult.sentRequest());
                    pro.addProperty("receivedResponse", payloadResult.receivedResponse());
                    pro.addProperty("statusCode", payloadResult.statusCode());
                    pro.addProperty("responseTimeMs", payloadResult.responseTimeMs());
                    pro.addProperty("anomalyDetected", payloadResult.anomalyDetected());
                    if (payloadResult.wafVendor() != null) {
                        pro.addProperty("wafVendor", payloadResult.wafVendor());
                    }
                    pro.addProperty("wafScore", payloadResult.wafScore());
                    prArr.add(pro);
                }
            }
            obj.add("payloadResults", prArr);

            if (pr.verdict() != null) {
                JsonObject v = new JsonObject();
                v.addProperty("overallRisk", pr.verdict().overallRisk());
                v.addProperty("summary", pr.verdict().summary());
                v.addProperty("recommendations", pr.verdict().recommendations());
                v.addProperty("totalTokensUsed", pr.verdict().totalTokensUsed());

                JsonArray confirmed = new JsonArray();
                if (pr.verdict().confirmedVulns() != null) {
                    for (ConfirmedVuln cv : pr.verdict().confirmedVulns()) {
                        JsonObject cvo = new JsonObject();
                        cvo.addProperty("type", cv.type());
                        cvo.addProperty("title", cv.title());
                        cvo.addProperty("evidence", cv.evidence());
                        cvo.addProperty("payloadUsed", cv.payloadUsed());
                        cvo.addProperty("response", cv.response());
                        cvo.addProperty("verifyCommand", cv.verifyCommand());
                        cvo.addProperty("identityProof", cv.identityProof());
                        cvo.addProperty("cvss", cv.cvss());
                        confirmed.add(cvo);
                    }
                }
                v.add("confirmedVulns", confirmed);

                JsonArray suspected = new JsonArray();
                if (pr.verdict().suspectedVulns() != null) {
                    for (SuspectedVuln sv : pr.verdict().suspectedVulns()) {
                        JsonObject svo = new JsonObject();
                        svo.addProperty("type", sv.type());
                        svo.addProperty("title", sv.title());
                        svo.addProperty("reason", sv.reason());
                        svo.addProperty("verifyCommand", sv.verifyCommand());
                        svo.addProperty("confidence", sv.confidence());
                        svo.addProperty("escalationPath", sv.escalationPath());
                        svo.addProperty("payloadUsed", sv.payloadUsed());
                        suspected.add(svo);
                    }
                }
                v.add("suspectedVulns", suspected);

                if (pr.verdict().rejectionReasons() != null && !pr.verdict().rejectionReasons().isEmpty()) {
                    JsonArray reasons = new JsonArray();
                    for (String r : pr.verdict().rejectionReasons()) reasons.add(r);
                    v.add("rejectionReasons", reasons);
                }
                obj.add("verdict", v);
            }

            JsonObject stageDesc = new JsonObject();
            if (pr.stageDescriptions() != null) {
                for (var e : pr.stageDescriptions().entrySet()) {
                    stageDesc.addProperty(String.valueOf(e.getKey()), e.getValue());
                }
            }
            obj.add("stageDescriptions", stageDesc);

            return obj;
        }
    }

    // ======================== Deserializer ========================

    private static class ApiEntryDeserializer implements JsonDeserializer<ApiEntry> {
        @Override
        public ApiEntry deserialize(JsonElement json, Type type, JsonDeserializationContext ctx) throws JsonParseException {
            JsonObject obj = json.getAsJsonObject();
            String id = getStr(obj, "id", "");
            String httpMethod = getStr(obj, "httpMethod", "");
            String apiPath = getStr(obj, "apiPath", "");
            ApiStatus status = safeEnum(ApiStatus.class, getStr(obj, "status", "UNTESTED"), ApiStatus.UNTESTED);
            String vulnTypeStr = getStr(obj, "vulnType", null);
            VulnType vulnType = vulnTypeStr != null ? safeEnum(VulnType.class, vulnTypeStr, null) : null;
            String result = getStr(obj, "result", "");
            String note = getStr(obj, "note", "");
            String domain = getStr(obj, "domain", "");
            long lastSeen = obj.has("lastSeenTimestamp") ? obj.get("lastSeenTimestamp").getAsLong() : 0;

            ApiEntry entry = new ApiEntry(id, httpMethod, apiPath, status, vulnType, result, note, domain, lastSeen);

            // Restore traffic fields
            entry.setLastRawRequest(getStr(obj, "lastRawRequest", ""));
            entry.setLastRawResponse(getStr(obj, "lastRawResponse", ""));
            entry.setLastUrl(getStr(obj, "lastUrl", ""));
            if (obj.has("lastStatusCode")) {
                entry.setLastStatusCode(obj.get("lastStatusCode").getAsInt());
            }

            // Restore analysis history
            if (obj.has("analysisHistory") && obj.get("analysisHistory").isJsonArray()) {
                for (JsonElement elem : obj.getAsJsonArray("analysisHistory")) {
                    if (!elem.isJsonObject()) continue;
                    AnalysisRecord record = deserializeAnalysisRecord(elem.getAsJsonObject());
                    if (record != null) {
                        entry.addAnalysisRecord(record);
                    }
                }
            }

            // Restore passive findings — or migrate them out of legacy notes
            // (pre-4.1 data kept machine detections inside the note field).
            if (obj.has("passiveFindings") && obj.get("passiveFindings").isJsonArray()) {
                for (JsonElement elem : obj.getAsJsonArray("passiveFindings")) {
                    if (!elem.isJsonObject()) continue;
                    PassiveFinding f = deserializePassiveFinding(elem.getAsJsonObject());
                    if (f != null) entry.addPassiveFindingIfAbsent(f);
                }
            } else if (note.contains("[Heuristic]") || note.contains("[敏感信息]") || note.contains("[越权]")) {
                try {
                    migrateLegacyNote(entry);
                } catch (Exception migrationEx) {
                    // Never lose user data: on any parse failure keep the note
                    // exactly as it was (machine markers included).
                    System.err.println("[API-Sentinel] legacy note migration failed, note kept as-is: "
                            + migrationEx.getMessage());
                }
            }

            return entry;
        }

        private PassiveFinding deserializePassiveFinding(JsonObject fo) {
            try {
                PassiveFinding.Source source;
                try {
                    source = PassiveFinding.Source.valueOf(getStr(fo, "source", "HEURISTIC"));
                } catch (IllegalArgumentException e) {
                    source = PassiveFinding.Source.HEURISTIC;
                }
                return new PassiveFinding(
                        getStr(fo, "id", PassiveFinding.newId()),
                        source,
                        getStr(fo, "risk", "INFO"),
                        getStr(fo, "category", ""),
                        getStr(fo, "title", ""),
                        getStr(fo, "evidence", ""),
                        getStr(fo, "remediation", ""),
                        fo.has("detectedAt") ? fo.get("detectedAt").getAsLong() : 0L);
            } catch (Exception e) {
                return null;
            }
        }

        /**
         * Best-effort migration of pre-4.1 notes that mixed machine detections
         * with user text. Lines starting with [敏感信息]/[Heuristic]/[越权]
         * become PassiveFindings; everything else is kept as the user note.
         * Any failure aborts cleanly and the caller keeps the original note.
         */
        private void migrateLegacyNote(ApiEntry entry) {
            String note = entry.getNote();
            String[] lines = note.split("\n");
            StringBuilder userNote = new StringBuilder();
            int i = 0;
            while (i < lines.length) {
                String line = lines[i];
                if (line.startsWith("[敏感信息] ")) {
                    String rest = line.substring("[敏感信息] ".length());
                    for (String rule : rest.split(", ")) {
                        if (!rule.isBlank()) {
                            entry.addPassiveFindingIfAbsent(new PassiveFinding(
                                    PassiveFinding.newId(), PassiveFinding.Source.SENSITIVE_INFO,
                                    "INFO", "敏感信息", rule.trim(), "", "",
                                    System.currentTimeMillis()));
                        }
                    }
                    i++;
                } else if (line.startsWith("[Heuristic] ")) {
                    // Block = first line (prefix stripped) plus following
                    // [RISK]-tagged continuation lines.
                    List<String> block = new ArrayList<>();
                    block.add(line.substring("[Heuristic] ".length()));
                    i++;
                    while (i < lines.length && isRiskTaggedLine(lines[i])) {
                        block.add(lines[i]);
                        i++;
                    }
                    for (String bl : block) {
                        String risk = "INFO";
                        String body = bl;
                        for (String tag : new String[]{"[HIGH] ", "[MEDIUM] ", "[LOW] ", "[INFO] "}) {
                            if (bl.startsWith(tag)) {
                                risk = tag.substring(1, tag.length() - 2);
                                body = bl.substring(tag.length());
                                break;
                            }
                        }
                        // Split on the FIRST ": " only — evidence itself may
                        // contain colons.
                        int sep = body.indexOf(": ");
                        String title = sep >= 0 ? body.substring(0, sep) : body;
                        String evidence = sep >= 0 ? body.substring(sep + 2) : "";
                        entry.addPassiveFindingIfAbsent(new PassiveFinding(
                                PassiveFinding.newId(), PassiveFinding.Source.HEURISTIC,
                                risk, "", title.trim(), evidence.trim(), "历史迁移",
                                System.currentTimeMillis()));
                    }
                } else if (line.startsWith("[越权] ")) {
                    StringBuilder block = new StringBuilder(line);
                    i++;
                    while (i < lines.length && !isMachineMarkerLine(lines[i])) {
                        block.append("\n").append(lines[i]);
                        i++;
                    }
                    entry.addPassiveFindingIfAbsent(new PassiveFinding(
                            PassiveFinding.newId(), PassiveFinding.Source.UNAUTHORIZED,
                            "MEDIUM", "越权", "未授权访问探测（待确认）",
                            block.toString(), "", System.currentTimeMillis()));
                } else {
                    if (userNote.length() > 0) userNote.append("\n");
                    userNote.append(line);
                    i++;
                }
            }
            entry.setNote(userNote.toString().trim());
        }

        private boolean isRiskTaggedLine(String line) {
            return line.startsWith("[HIGH] ") || line.startsWith("[MEDIUM] ")
                    || line.startsWith("[LOW] ") || line.startsWith("[INFO] ");
        }

        private boolean isMachineMarkerLine(String line) {
            return line.startsWith("[敏感信息] ") || line.startsWith("[Heuristic] ")
                    || line.startsWith("[越权] ");
        }

        private AnalysisRecord deserializeAnalysisRecord(JsonObject obj) {
            try {
                String id = getStr(obj, "id", UUID.randomUUID().toString().substring(0, 8));
                long timestamp = obj.has("timestamp") ? obj.get("timestamp").getAsLong() : 0;
                String mode = getStr(obj, "mode", "TRAFFIC_ONLY");

                AnalysisResult result = null;
                if (obj.has("result") && obj.get("result").isJsonObject()) {
                    result = deserializeAnalysisResult(obj.getAsJsonObject("result"));
                }

                List<TestCase> testCases = new ArrayList<>();
                if (obj.has("testCases") && obj.get("testCases").isJsonArray()) {
                    for (JsonElement elem : obj.getAsJsonArray("testCases")) {
                        if (!elem.isJsonObject()) continue;
                        TestCase tc = deserializeTestCase(elem.getAsJsonObject());
                        if (tc != null) testCases.add(tc);
                    }
                }

                PipelineResult pipelineResult = null;
                if (obj.has("pipelineResult") && obj.get("pipelineResult").isJsonObject()) {
                    pipelineResult = deserializePipelineResult(obj.getAsJsonObject("pipelineResult"));
                }

                List<com.flechazo.apisentinel.ui.TimelineEvent> timeline = new ArrayList<>();
                if (obj.has("timeline") && obj.get("timeline").isJsonArray()) {
                    for (JsonElement elem : obj.getAsJsonArray("timeline")) {
                        if (!elem.isJsonObject()) continue;
                        JsonObject eo = elem.getAsJsonObject();
                        try {
                            java.time.Instant ts = java.time.Instant.EPOCH;
                            String tsStr = getStr(eo, "ts", "");
                            if (!tsStr.isEmpty()) {
                                try { ts = java.time.Instant.parse(tsStr); } catch (Exception ignored) {}
                            }
                            var type = safeEnum(com.flechazo.apisentinel.ui.TimelineEvent.Type.class,
                                    getStr(eo, "type", "ITERATION"),
                                    com.flechazo.apisentinel.ui.TimelineEvent.Type.ITERATION);
                            var hint = safeEnum(com.flechazo.apisentinel.ui.TimelineEvent.ColorHint.class,
                                    getStr(eo, "colorHint", "NEUTRAL"),
                                    com.flechazo.apisentinel.ui.TimelineEvent.ColorHint.NEUTRAL);
                            timeline.add(new com.flechazo.apisentinel.ui.TimelineEvent(
                                    ts, type, getStr(eo, "summary", ""), getStr(eo, "detail", ""),
                                    getStr(eo, "cost", ""), hint));
                        } catch (Exception ignored) {}
                    }
                }

                return new AnalysisRecord(id, timestamp, mode, result, testCases, pipelineResult, timeline);
            } catch (Exception e) {
                return null;
            }
        }

        private AnalysisResult deserializeAnalysisResult(JsonObject obj) {
            String summary = getStr(obj, "summary", "");
            AnalysisResult.RiskLevel risk = safeEnum(AnalysisResult.RiskLevel.class,
                    getStr(obj, "overallRisk", "NONE"), AnalysisResult.RiskLevel.NONE);
            int tokensUsed = obj.has("tokensUsed") ? obj.get("tokensUsed").getAsInt() : 0;
            long analysisTimeMs = obj.has("analysisTimeMs") ? obj.get("analysisTimeMs").getAsLong() : 0;
            String modelUsed = getStr(obj, "modelUsed", "");
            String error = getStr(obj, "error", null);

            List<VulnFinding> findings = new ArrayList<>();
            if (obj.has("findings") && obj.get("findings").isJsonArray()) {
                for (JsonElement elem : obj.getAsJsonArray("findings")) {
                    if (!elem.isJsonObject()) continue;
                    JsonObject fo = elem.getAsJsonObject();
                    findings.add(new VulnFinding(
                            getStr(fo, "type", ""),
                            getStr(fo, "risk", "LOW"),
                            fo.has("confidence") ? fo.get("confidence").getAsDouble() : 0.0,
                            getStr(fo, "title", ""),
                            getStr(fo, "description", ""),
                            getStr(fo, "evidence", ""),
                            getStr(fo, "location", ""),
                            getStr(fo, "remediation", "")
                    ));
                }
            }

            return new AnalysisResult(findings, summary, risk, tokensUsed, analysisTimeMs, modelUsed, error);
        }

        private TestCase deserializeTestCase(JsonObject obj) {
            Map<String, String> headers = null;
            if (obj.has("headers") && obj.get("headers").isJsonObject()) {
                headers = new LinkedHashMap<>();
                for (Map.Entry<String, JsonElement> e : obj.getAsJsonObject("headers").entrySet()) {
                    if (!e.getValue().isJsonNull()) {
                        headers.put(e.getKey(), e.getValue().getAsString());
                    }
                }
            }
            return new TestCase(
                    getStr(obj, "name", ""),
                    getStr(obj, "category", ""),
                    getStr(obj, "targetParam", ""),
                    getStr(obj, "payload", ""),
                    getStr(obj, "method", ""),
                    getStr(obj, "path", ""),
                    headers,
                    getStr(obj, "body", ""),
                    getStr(obj, "description", ""),
                    getStr(obj, "expectedIfVulnerable", ""),
                    getStr(obj, "riskIfConfirmed", "")
            );
        }

        private PipelineResult deserializePipelineResult(JsonObject obj) {
            AnalysisResult trafficAnalysis = null;
            if (obj.has("trafficAnalysis") && obj.get("trafficAnalysis").isJsonObject()) {
                trafficAnalysis = deserializeAnalysisResult(obj.getAsJsonObject("trafficAnalysis"));
            }

            String sourceCode = getStr(obj, "sourceCode", "");

            FinalVerdict verdict = null;
            if (obj.has("verdict") && obj.get("verdict").isJsonObject()) {
                JsonObject v = obj.getAsJsonObject("verdict");
                String overallRisk = getStr(v, "overallRisk", "MEDIUM");
                String summary = getStr(v, "summary", "");
                String recommendations = getStr(v, "recommendations", "");
                int totalTokens = v.has("totalTokensUsed") ? v.get("totalTokensUsed").getAsInt() : 0;

                List<ConfirmedVuln> confirmed = new ArrayList<>();
                if (v.has("confirmedVulns") && v.get("confirmedVulns").isJsonArray()) {
                    for (JsonElement elem : v.getAsJsonArray("confirmedVulns")) {
                        if (!elem.isJsonObject()) continue;
                        JsonObject cvo = elem.getAsJsonObject();
                        confirmed.add(new ConfirmedVuln(
                                getStr(cvo, "type", ""),
                                getStr(cvo, "title", ""),
                                getStr(cvo, "evidence", ""),
                                getStr(cvo, "payloadUsed", ""),
                                getStr(cvo, "response", ""),
                                getStr(cvo, "verifyCommand", ""),
                                getStr(cvo, "identityProof", ""),
                                getStr(cvo, "cvss", "")
                        ));
                    }
                }

                List<SuspectedVuln> suspected = new ArrayList<>();
                if (v.has("suspectedVulns") && v.get("suspectedVulns").isJsonArray()) {
                    for (JsonElement elem : v.getAsJsonArray("suspectedVulns")) {
                        if (!elem.isJsonObject()) continue;
                        JsonObject svo = elem.getAsJsonObject();
                        suspected.add(new SuspectedVuln(
                                getStr(svo, "type", ""),
                                getStr(svo, "title", ""),
                                getStr(svo, "reason", ""),
                                getStr(svo, "verifyCommand", ""),
                                getStr(svo, "confidence", "MEDIUM"),
                                getStr(svo, "escalationPath", ""),
                                getStr(svo, "payloadUsed", "")
                        ));
                    }
                }

                List<String> rejectionReasons = new ArrayList<>();
                if (v.has("rejectionReasons") && v.get("rejectionReasons").isJsonArray()) {
                    for (JsonElement elem : v.getAsJsonArray("rejectionReasons")) {
                        if (elem.isJsonPrimitive()) rejectionReasons.add(elem.getAsString());
                    }
                }

                verdict = new FinalVerdict(overallRisk, confirmed, suspected, summary,
                        recommendations, totalTokens, rejectionReasons);
            }

            // Deserialize payload results
            List<PayloadResult> payloadResults = new ArrayList<>();
            if (obj.has("payloadResults") && obj.get("payloadResults").isJsonArray()) {
                // Need to match payload results back to test cases from AnalysisRecord
                // For now, create lightweight TestCase stubs with name/category
                for (JsonElement elem : obj.getAsJsonArray("payloadResults")) {
                    if (!elem.isJsonObject()) continue;
                    JsonObject pro = elem.getAsJsonObject();
                    TestCase stubTc = new TestCase(
                            getStr(pro, "testCaseName", ""),
                            getStr(pro, "testCaseCategory", ""),
                            "", "", "", "", null, "", "", "", ""
                    );
                    payloadResults.add(new PayloadResult(
                            stubTc,
                            getStr(pro, "sentRequest", ""),
                            getStr(pro, "receivedResponse", ""),
                            pro.has("statusCode") ? pro.get("statusCode").getAsInt() : 0,
                            pro.has("responseTimeMs") ? pro.get("responseTimeMs").getAsLong() : 0,
                            pro.has("anomalyDetected") && pro.get("anomalyDetected").getAsBoolean(),
                            0L, -1,
                            // WAF fields absent in pre-WAF data files — backfill defaults
                            pro.has("wafVendor") && !pro.get("wafVendor").isJsonNull()
                                    ? pro.get("wafVendor").getAsString() : null,
                            pro.has("wafScore") ? pro.get("wafScore").getAsInt() : 0
                    ));
                }
            }

            Map<Integer, String> stageDescriptions = new LinkedHashMap<>();
            if (obj.has("stageDescriptions") && obj.get("stageDescriptions").isJsonObject()) {
                for (Map.Entry<String, JsonElement> e : obj.getAsJsonObject("stageDescriptions").entrySet()) {
                    try {
                        stageDescriptions.put(Integer.parseInt(e.getKey()), e.getValue().getAsString());
                    } catch (Exception ignored) {}
                }
            }
            return new PipelineResult(trafficAnalysis, sourceCode, List.of(), payloadResults, verdict, stageDescriptions);
        }

        private String getStr(JsonObject obj, String key, String defaultVal) {
            if (obj.has(key) && !obj.get(key).isJsonNull()) {
                return obj.get(key).getAsString();
            }
            return defaultVal;
        }

        private static <E extends Enum<E>> E safeEnum(Class<E> enumClass, String value, E defaultVal) {
            if (value == null) return defaultVal;
            try {
                return Enum.valueOf(enumClass, value);
            } catch (IllegalArgumentException e) {
                return defaultVal;
            }
        }
    }
}
