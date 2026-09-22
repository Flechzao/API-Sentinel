package com.flechazo.apisentinel.fun;

import java.util.ArrayList;
import java.util.List;

/**
 * 成就定义
 */
public class Achievement {
    private final String id;
    private final String name;
    private final String description;
    private final String icon;
    private final AchievementRarity rarity;
    private boolean unlocked;
    private long unlockedTime;

    public enum AchievementRarity {
        COMMON("普通", "#808080"),
        RARE("稀有", "#4169E1"),
        EPIC("史诗", "#9370DB"),
        LEGENDARY("传说", "#FFD700");

        private final String displayName;
        private final String color;

        AchievementRarity(String displayName, String color) {
            this.displayName = displayName;
            this.color = color;
        }

        public String getDisplayName() { return displayName; }
        public String getColor() { return color; }
    }

    public Achievement(String id, String name, String description, String icon, AchievementRarity rarity) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.icon = icon;
        this.rarity = rarity;
        this.unlocked = false;
        this.unlockedTime = 0;
    }

    // Getters
    public String getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public String getIcon() { return icon; }
    public AchievementRarity getRarity() { return rarity; }
    public boolean isUnlocked() { return unlocked; }
    public long getUnlockedTime() { return unlockedTime; }

    public void unlock() {
        if (!unlocked) {
            this.unlocked = true;
            this.unlockedTime = System.currentTimeMillis();
        }
    }

    public void lock() {
        this.unlocked = false;
        this.unlockedTime = 0;
    }
}
