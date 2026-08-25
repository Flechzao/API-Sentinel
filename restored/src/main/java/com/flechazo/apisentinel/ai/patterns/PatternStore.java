package com.flechazo.apisentinel.ai.patterns;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.config.AppPaths;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Success-pattern memory (P3 of the cluster-hunting upgrade, distilled from
 * claude-bug-bounty's "reuse what worked" discipline — see
 * payloads/chain-hunting.md, docs/THIRD-PARTY.md).
 *
 * <p>Every VERIFIED confirmed vuln (post-VerdictValidator — unverified
 * suspicions are never recorded) becomes a reusable pattern:
 * (vulnType, technique, payload preview, endpoint pattern, domain). Repeat
 * confirmations of the same technique on the same endpoint shape increment
 * {@code hits}, so genuinely recurring flaws rise to the top. At the start of
 * each new Agent analysis, the store's top patterns for that domain are
 * injected into the initial message (see AgentLoop.buildInitialUserMessage)
 * — the Agent starts a new endpoint already knowing which plays have paid
 * off nearby, instead of rediscovering them from scratch.
 *
 * <p>Persisted to {@code ~/.api-sentinel/patterns.json} (AppPaths root).
 * Path-injectable constructor for tests. All mutating methods are
 * synchronized — the store is touched from analysis-completion callbacks
 * (EventBus executor) and AgentLoop startup (agent threads), and the write
 * frequency (once per completed analysis at most) makes a direct
 * write-through simpler than a flush scheduler.
 */
public class PatternStore {

    /** Hard cap so a long-lived install can't grow the file unbounded. */
    static final int MAX_PATTERNS = 500;
    /** Payload preview length — enough to recognize the play, not the whole payload. */
    private static final int PREVIEW_LEN = 80;

    /** One remembered success. Aggregation key = vulnType|apiPattern|payloadPreview. */
    public record SuccessPattern(
            String vulnType,
            String technique,
            String payloadPreview,
            String apiPattern,
            String domain,
            int hits,
            long lastSeenMs
    ) {}

    private final Path file;
    private final LeveledLogger logger;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    /** Aggregation key -> pattern; LinkedHashMap keeps insertion order for stable eviction. */
    private final Map<String, SuccessPattern> patterns = new LinkedHashMap<>();

    public PatternStore(LeveledLogger logger) {
        this(AppPaths.resolve("patterns.json"), logger);
    }

    /** Test constructor: injects the storage file. */
    public PatternStore(Path file, LeveledLogger logger) {
        this.file = file;
        this.logger = logger;
        load();
    }

    /**
     * Records every verified confirmed vuln of a finished verdict. Call ONLY
     * with the post-VerdictValidator FinalVerdict (handlePipelineComplete),
     * never with raw LLM claims.
     */
    public synchronized void recordConfirmations(ApiEntry entry, FinalVerdict verdict) {
        if (entry == null || verdict == null || verdict.confirmedVulns() == null) return;
        boolean changed = false;
        for (ConfirmedVuln v : verdict.confirmedVulns()) {
            if (v == null || v.type() == null || v.type().isBlank()) continue;
            String payload = preview(v.payloadUsed());
            String key = v.type() + "|" + entry.getApiPath() + "|" + payload;
            SuccessPattern existing = patterns.get(key);
            if (existing != null) {
                patterns.put(key, new SuccessPattern(existing.vulnType(), existing.technique(),
                        existing.payloadPreview(), existing.apiPattern(), existing.domain(),
                        existing.hits() + 1, System.currentTimeMillis()));
            } else {
                // technique = the confirmed vuln's title, straight from the
                // LLM — strip markup (see stripMarkup) so the pattern table
                // and the injected prompt section stay clean text.
                patterns.put(key, new SuccessPattern(v.type(), stripMarkup(v.title()), payload,
                        entry.getApiPath(), safe(entry.getDomain()), 1, System.currentTimeMillis()));
            }
            changed = true;
        }
        if (changed) {
            evictIfNeeded();
            save();
        }
    }

    /** Top patterns for a domain: same-domain first (by hits), then
     *  cross-domain plays. Cross-domain entries are aggregated by
     *  (vulnType, payload) — "IDOR with payload-a worked twice on other
     *  domains" is the generalizable signal, even when the two hits landed
     *  on different endpoints — and only surface once the aggregate reaches
     *  hits >= 2 (a one-off from another domain is noise, not a pattern). */
    public synchronized List<SuccessPattern> topPatterns(String domain, int limit) {
        List<SuccessPattern> sameDomain = new ArrayList<>();
        Map<String, SuccessPattern> globalAgg = new LinkedHashMap<>();
        for (SuccessPattern p : patterns.values()) {
            if (domain != null && !domain.isBlank() && domain.equals(p.domain())) {
                sameDomain.add(p);
            } else {
                String key = p.vulnType() + "|" + p.payloadPreview();
                SuccessPattern cur = globalAgg.get(key);
                if (cur == null) {
                    globalAgg.put(key, p);
                } else {
                    globalAgg.put(key, new SuccessPattern(cur.vulnType(), cur.technique(),
                            cur.payloadPreview(), cur.apiPattern(), cur.domain(),
                            cur.hits() + p.hits(), Math.max(cur.lastSeenMs(), p.lastSeenMs())));
                }
            }
        }
        List<SuccessPattern> global = new ArrayList<>(globalAgg.values());
        global.removeIf(p -> p.hits() < 2);

        Comparator<SuccessPattern> byHits = Comparator.comparingInt(SuccessPattern::hits).reversed();
        sameDomain.sort(byHits);
        global.sort(byHits);
        List<SuccessPattern> out = new ArrayList<>(sameDomain);
        for (SuccessPattern p : global) {
            if (out.size() >= limit) break;
            out.add(p);
        }
        if (out.size() > limit) out = new ArrayList<>(out.subList(0, limit));
        return out;
    }

    /**
     * Prompt section for a new analysis's initial message: which plays have
     * already paid off on this domain. Empty string when there's nothing
     * useful to say (nothing injected).
     */
    public synchronized String buildPromptSection(ApiEntry entry, int limit) {
        List<SuccessPattern> top = topPatterns(safe(entry.getDomain()), limit);
        if (top.isEmpty()) return "";

        StringBuilder sb = new StringBuilder();
        sb.append("### 历史成功模式（同环境此前已验证确认的打法，优先在新端点上复测同类）\n");
        for (SuccessPattern p : top) {
            sb.append("- [").append(p.vulnType()).append("] ").append(safe(p.technique()));
            sb.append(" @ ").append(p.apiPattern());
            if (p.hits() > 1) sb.append("（命中 ").append(p.hits()).append(" 次）");
            if (p.payloadPreview() != null && !p.payloadPreview().isEmpty()) {
                sb.append("\n  payload 预览: ").append(p.payloadPreview());
            }
            sb.append("\n");
        }
        sb.append("\n这些是历史已确认的模式，不是本次的结论——新端点仍需独立取证验证。\n\n");
        return sb.toString();
    }

    public synchronized int size() { return patterns.size(); }

    /** All patterns, most-proven first — snapshot for the management UI. */
    public synchronized List<SuccessPattern> allPatterns() {
        List<SuccessPattern> out = new ArrayList<>(patterns.values());
        out.sort(Comparator.comparingInt(SuccessPattern::hits).reversed()
                .thenComparing(Comparator.comparingLong(SuccessPattern::lastSeenMs).reversed()));
        return out;
    }

    /** Wipes every remembered pattern (management UI "clear" action). */
    public synchronized void clear() {
        if (patterns.isEmpty()) return;
        patterns.clear();
        save();
    }

    private void evictIfNeeded() {
        if (patterns.size() <= MAX_PATTERNS) return;
        // Drop the least-proven patterns first (lowest hits, oldest lastSeen);
        // keep insertion order for the survivors.
        List<SuccessPattern> sorted = new ArrayList<>(patterns.values());
        sorted.sort(Comparator
                .comparingInt(SuccessPattern::hits)
                .thenComparingLong(SuccessPattern::lastSeenMs));
        int toDrop = patterns.size() - MAX_PATTERNS;
        for (int i = 0; i < toDrop; i++) {
            patterns.remove(sorted.get(i).vulnType() + "|" + sorted.get(i).apiPattern()
                    + "|" + sorted.get(i).payloadPreview());
        }
    }

    private void load() {
        try {
            if (Files.exists(file)) {
                JsonObject obj = gson.fromJson(Files.readString(file), JsonObject.class);
                if (obj != null && obj.has("patterns") && obj.get("patterns").isJsonArray()) {
                    List<SuccessPattern> loaded = gson.fromJson(obj.get("patterns"),
                            new TypeToken<List<SuccessPattern>>() {}.getType());
                    if (loaded != null) {
                        for (SuccessPattern p : loaded) {
                            if (p != null && p.vulnType() != null) {
                                patterns.put(p.vulnType() + "|" + p.apiPattern() + "|"
                                        + p.payloadPreview(), p);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            if (logger != null) logger.warn("[PatternStore] 加载 patterns.json 失败: %s", e.getMessage());
        }
    }

    private void save() {
        try {
            Path dir = file.getParent();
            if (dir != null) Files.createDirectories(dir);
            JsonObject obj = new JsonObject();
            obj.add("patterns", gson.toJsonTree(new ArrayList<>(patterns.values())));
            Files.writeString(file, gson.toJson(obj));
        } catch (Exception e) {
            if (logger != null) logger.warn("[PatternStore] 保存 patterns.json 失败: %s", e.getMessage());
        }
    }

    private static String preview(String payload) {
        if (payload == null) return "";
        String p = payload.strip();
        return p.length() <= PREVIEW_LEN ? p : p.substring(0, PREVIEW_LEN) + "...";
    }

    private static String safe(String s) { return s != null ? s : ""; }

    /** Strips HTML tags and markdown decoration the LLM likes to embed in
     *  vuln titles (e.g. an XSS title quoting a "&lt;script&gt;" payload,
     *  **bold** or `code` markers) — the pattern table renders plain text
     *  and the injected prompt section needs no decoration. Public so
     *  PatternPanel can also sanitize patterns persisted BEFORE this existed.
     *  Deliberately NOT applied to payload previews — for an XSS play the
     *  markup IS the payload. */
    public static String stripMarkup(String s) {
        if (s == null) return "";
        String out = s.replaceAll("<[^>]+>", "");
        out = out.replace("**", "").replace("`", "");
        return out.replaceAll("\\s+", " ").trim();
    }
}
