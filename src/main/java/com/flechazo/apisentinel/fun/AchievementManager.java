package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 成就管理器
 */
public class AchievementManager {
    private final Map<String, Achievement> achievements = new LinkedHashMap<>();
    private final List<AchievementListener> listeners = new CopyOnWriteArrayList<>();
    private final ConfigManager configManager;
    private final LeveledLogger logger;

    public interface AchievementListener {
        void onAchievementUnlocked(Achievement achievement);
    }

    public AchievementManager(ConfigManager configManager, LeveledLogger logger) {
        this.configManager = configManager;
        this.logger = logger;
        initializeAchievements();
        loadAchievements();
    }

    private void initializeAchievements() {
        // 成就 1: 首次发现 XSS
        achievements.put("first_xss", new Achievement(
            "first_xss",
            "XSS 猎人",
            "首次发现跨站脚本漏洞",
            "[XSS]",
            Achievement.AchievementRarity.COMMON
        ));

        // 成就 2: 首次发现 SQL 注入
        achievements.put("first_sqli", new Achievement(
            "first_sqli",
            "注入大师",
            "首次发现 SQL 注入漏洞",
            "[SQLi]",
            Achievement.AchievementRarity.RARE
        ));

        // 成就 3: 发现 10 个漏洞
        achievements.put("ten_vulns", new Achievement(
            "ten_vulns",
            "漏洞猎人",
            "累计发现 10 个漏洞",
            "[10+ ]",
            Achievement.AchievementRarity.EPIC
        ));

        // 成就 4: 发现高危漏洞
        achievements.put("high_severity", new Achievement(
            "high_severity",
            "高危发现者",
            "首次发现高危或严重漏洞",
            "[HIGH]",
            Achievement.AchievementRarity.EPIC
        ));

        // 成就 5: 发现所有类型漏洞
        achievements.put("all_types", new Achievement(
            "all_types",
            "全能大师",
            "发现过所有类型的漏洞",
            "[ALL]",
            Achievement.AchievementRarity.LEGENDARY
        ));
    }

    private void seedDemoData() {
        long now = System.currentTimeMillis();
        int i = 0;
        for (Achievement ach : achievements.values()) {
            ach.unlock();
            try {
                java.lang.reflect.Field f = Achievement.class.getDeclaredField("unlockedTime");
                f.setAccessible(true);
                f.setLong(ach, now - (i * 3600000L));
            } catch (Exception ignored) {}
            i++;
        }
        saveAchievements();
        logger.info("[Fun] Achievements seeded: all %d unlocked", i);
    }

    private void loadAchievements() {
        try {
            com.google.gson.JsonObject funConfig = configManager.getFunFeaturesConfig();
            if (funConfig != null && funConfig.has("achievements")) {
                com.google.gson.JsonObject achObj = funConfig.getAsJsonObject("achievements");
                for (String id : achievements.keySet()) {
                    if (achObj.has(id)) {
                        com.google.gson.JsonObject achData = achObj.getAsJsonObject(id);
                        if (achData.has("unlocked") && achData.get("unlocked").getAsBoolean()) {
                            achievements.get(id).unlock();
                            if (achData.has("unlockedTime")) {
                                // 使用反射设置解锁时间（因为 unlock() 会设置当前时间）
                                Achievement ach = achievements.get(id);
                                java.lang.reflect.Field field = Achievement.class.getDeclaredField("unlockedTime");
                                field.setAccessible(true);
                                field.setLong(ach, achData.get("unlockedTime").getAsLong());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("[Fun] Failed to load achievements: %s", e.getMessage());
        }
    }

    private void saveAchievements() {
        try {
            com.google.gson.JsonObject funConfig = configManager.getFunFeaturesConfig();
            if (funConfig == null) {
                funConfig = new com.google.gson.JsonObject();
            }
            
            com.google.gson.JsonObject achObj = new com.google.gson.JsonObject();
            for (Achievement ach : achievements.values()) {
                com.google.gson.JsonObject achData = new com.google.gson.JsonObject();
                achData.addProperty("unlocked", ach.isUnlocked());
                achData.addProperty("unlockedTime", ach.getUnlockedTime());
                achObj.add(ach.getId(), achData);
            }
            funConfig.add("achievements", achObj);
            configManager.setFunFeaturesConfig(funConfig);
        } catch (Exception e) {
            logger.warn("[Fun] Failed to save achievements: %s", e.getMessage());
        }
    }

    public void addListener(AchievementListener listener) {
        listeners.add(listener);
    }

    public void removeListener(AchievementListener listener) {
        listeners.remove(listener);
    }

    public void tryUnlock(String achievementId) {
        Achievement achievement = achievements.get(achievementId);
        if (achievement != null && !achievement.isUnlocked()) {
            achievement.unlock();
            saveAchievements();
            logger.info("[Fun] Achievement unlocked: %s", achievement.getName());
            
            // 通知监听器
            for (AchievementListener listener : listeners) {
                try {
                    listener.onAchievementUnlocked(achievement);
                } catch (Exception e) {
                    logger.warn("[Fun] Achievement listener error: %s", e.getMessage());
                }
            }
        }
    }

    /** Set by ApiSentinelExtension so we can check pokedex completion for "all_types". */
    private VulnerabilityPokedex pokedex;
    public void setPokedex(VulnerabilityPokedex pokedex) { this.pokedex = pokedex; }

    public void checkVulnerabilityAchievements(String vulnType, String severity) {
        // 检查首次发现 XSS
        if (vulnType != null && vulnType.toUpperCase().contains("XSS")) {
            tryUnlock("first_xss");
        }

        // 检查首次发现 SQL 注入
        if (vulnType != null && vulnType.toUpperCase().contains("SQL")) {
            tryUnlock("first_sqli");
        }

        // 检查高危漏洞
        if (severity != null && (severity.equals("HIGH") || severity.equals("CRITICAL"))) {
            tryUnlock("high_severity");
        }

        // 统计总发现数（从 config 中读取）
        try {
            com.google.gson.JsonObject funConfig = configManager.getFunFeaturesConfig();
            int totalVulns = 0;
            if (funConfig != null && funConfig.has("totalVulnerabilities")) {
                totalVulns = funConfig.get("totalVulnerabilities").getAsInt();
            }
            totalVulns++;
            
            if (funConfig == null) {
                funConfig = new com.google.gson.JsonObject();
            }
            funConfig.addProperty("totalVulnerabilities", totalVulns);
            configManager.setFunFeaturesConfig(funConfig);

            // 检查 10 个漏洞成就
            if (totalVulns >= 10) {
                tryUnlock("ten_vulns");
            }

            // 检查全类型大师成就
            if (pokedex != null && pokedex.getDiscoveredCount() >= pokedex.getTotalCount()) {
                tryUnlock("all_types");
            }
        } catch (Exception e) {
            logger.warn("[Fun] Failed to update vulnerability count: %s", e.getMessage());
        }
    }

    public Collection<Achievement> getAllAchievements() {
        return achievements.values();
    }

    public Achievement getAchievement(String id) {
        return achievements.get(id);
    }

    public int getUnlockedCount() {
        return (int) achievements.values().stream().filter(Achievement::isUnlocked).count();
    }

    public int getTotalCount() {
        return achievements.size();
    }

    public void resetAll() {
        for (Achievement ach : achievements.values()) {
            ach.lock();
        }
        saveAchievements();
        logger.info("[Fun] All achievements reset");
    }
}
