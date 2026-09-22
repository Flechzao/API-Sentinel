package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonObject;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 个人统计管理器 - 追踪漏洞发现数据
 */
public class StatsManager {
    private final ConfigManager configManager;
    private final LeveledLogger logger;

    private int totalFindings = 0;
    private int todayFindings = 0;
    private int bestDay = 0;
    private int consecutiveDays = 0;
    private String lastActiveDate = "";
    private final Map<String, Integer> typeCounts = new LinkedHashMap<>();
    private final Map<String, Integer> dailyFindings = new LinkedHashMap<>();

    public StatsManager(ConfigManager configManager, LeveledLogger logger) {
        this.configManager = configManager;
        this.logger = logger;
        load();
    }

    private void seedDemoData() {
        java.util.Random rng = new java.util.Random(42);
        String[] types = {"SQL注入", "越权/IDOR", "XSS", "路径穿越", "SSRF",
                          "SSTI", "XXE", "信息泄露", "CORS", "业务逻辑",
                          "认证绕过", "命令注入", "弱加密", "CSRF", "反序列化"};
        int[] weights = {89, 67, 34, 28, 18, 12, 10, 45, 8, 15, 22, 6, 11, 5, 4};
        for (int i = 0; i < types.length; i++) {
            typeCounts.put(types[i], weights[i]);
            totalFindings += weights[i];
        }

        // Generate daily data for last 30 days
        java.time.LocalDate today = java.time.LocalDate.now();
        int streak = 15;
        for (int d = 0; d < 30; d++) {
            String dateStr = today.minusDays(d).format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE);
            int count = d < streak ? 3 + rng.nextInt(12) : rng.nextInt(4);
            if (count > 0) dailyFindings.put(dateStr, count);
        }
        consecutiveDays = streak;
        todayFindings = dailyFindings.getOrDefault(
                today.format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE), 0);
        bestDay = dailyFindings.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        lastActiveDate = today.format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE);
        save();
        logger.info("[Fun] Stats seeded: %d total findings, %d day streak", totalFindings, streak);
    }

    public void recordFinding(String vulnType, String severity) {
        String today = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE);

        // Update daily tracking
        if (!today.equals(lastActiveDate)) {
            if (isYesterday(lastActiveDate)) {
                consecutiveDays++;
            } else {
                consecutiveDays = 1;
            }
            lastActiveDate = today;
            todayFindings = 0;
        }

        totalFindings++;
        todayFindings++;
        if (todayFindings > bestDay) bestDay = todayFindings;

        // Track by type
        typeCounts.merge(vulnType != null ? vulnType : "unknown", 1, Integer::sum);
        dailyFindings.merge(today, 1, Integer::sum);

        save();
    }

    private boolean isYesterday(String dateStr) {
        if (dateStr == null || dateStr.isEmpty()) return false;
        try {
            LocalDate date = LocalDate.parse(dateStr, DateTimeFormatter.ISO_LOCAL_DATE);
            return date.equals(LocalDate.now().minusDays(1));
        } catch (Exception e) {
            return false;
        }
    }

    public int getTotalFindings() { return totalFindings; }
    public int getTodayFindings() { return todayFindings; }
    public int getBestDay() { return bestDay; }
    public int getConsecutiveDays() { return consecutiveDays; }

    public Map<String, Integer> getTypeCounts() {
        return Collections.unmodifiableMap(typeCounts);
    }

    public String getBestType() {
        return typeCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(e -> e.getKey() + " (" + e.getValue() + ")")
                .orElse("无");
    }

    public Map<String, Integer> getDailyFindings() {
        return Collections.unmodifiableMap(dailyFindings);
    }

    public void reset() {
        totalFindings = 0;
        todayFindings = 0;
        bestDay = 0;
        consecutiveDays = 0;
        lastActiveDate = "";
        typeCounts.clear();
        dailyFindings.clear();
        save();
    }

    private void load() {
        try {
            JsonObject fun = configManager.getFunFeaturesConfig();
            if (fun != null && fun.has("stats")) {
                JsonObject s = fun.getAsJsonObject("stats");
                totalFindings = s.has("total") ? s.get("total").getAsInt() : 0;
                todayFindings = s.has("today") ? s.get("today").getAsInt() : 0;
                bestDay = s.has("bestDay") ? s.get("bestDay").getAsInt() : 0;
                consecutiveDays = s.has("consecutiveDays") ? s.get("consecutiveDays").getAsInt() : 0;
                lastActiveDate = s.has("lastActiveDate") ? s.get("lastActiveDate").getAsString() : "";

                if (s.has("typeCounts")) {
                    JsonObject tc = s.getAsJsonObject("typeCounts");
                    for (String key : tc.keySet()) {
                        typeCounts.put(key, tc.get(key).getAsInt());
                    }
                }
                if (s.has("dailyFindings")) {
                    JsonObject df = s.getAsJsonObject("dailyFindings");
                    for (String key : df.keySet()) {
                        dailyFindings.put(key, df.get(key).getAsInt());
                    }
                }

                // Reset today's count if it's a new day
                String today = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE);
                if (!today.equals(lastActiveDate)) {
                    todayFindings = 0;
                }
            }
        } catch (Exception e) {
            logger.warn("[Fun] Failed to load stats: %s", e.getMessage());
        }
    }

    private void save() {
        try {
            JsonObject fun = configManager.getFunFeaturesConfig();
            if (fun == null) fun = new JsonObject();

            JsonObject s = new JsonObject();
            s.addProperty("total", totalFindings);
            s.addProperty("today", todayFindings);
            s.addProperty("bestDay", bestDay);
            s.addProperty("consecutiveDays", consecutiveDays);
            s.addProperty("lastActiveDate", lastActiveDate);

            JsonObject tc = new JsonObject();
            for (Map.Entry<String, Integer> e : typeCounts.entrySet()) {
                tc.addProperty(e.getKey(), e.getValue());
            }
            s.add("typeCounts", tc);

            JsonObject df = new JsonObject();
            for (Map.Entry<String, Integer> e : dailyFindings.entrySet()) {
                df.addProperty(e.getKey(), e.getValue());
            }
            s.add("dailyFindings", df);

            fun.add("stats", s);
            configManager.setFunFeaturesConfig(fun);
        } catch (Exception e) {
            logger.warn("[Fun] Failed to save stats: %s", e.getMessage());
        }
    }
}
