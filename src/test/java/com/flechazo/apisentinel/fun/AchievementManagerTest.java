package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AchievementManagerTest {

    private AchievementManager manager;
    private ConfigManager configManager;

    @BeforeEach
    void setUp() {
        configManager = mock(ConfigManager.class);
        when(configManager.getFunFeaturesConfig()).thenReturn(new com.google.gson.JsonObject());
        LeveledLogger logger = mock(LeveledLogger.class);
        manager = new AchievementManager(configManager, logger);
    }

    @Test
    void initiallyAllLocked() {
        assertEquals(0, manager.getUnlockedCount());
        assertEquals(5, manager.getTotalCount());
        for (Achievement a : manager.getAllAchievements()) {
            assertFalse(a.isUnlocked(), "Achievement should be locked: " + a.getName());
        }
    }

    @Test
    void unlockFirstXss() {
        manager.checkVulnerabilityAchievements("反射型 XSS", "MEDIUM");
        assertTrue(manager.getAchievement("first_xss").isUnlocked());
        assertEquals(1, manager.getUnlockedCount());
    }

    @Test
    void unlockFirstSqli() {
        manager.checkVulnerabilityAchievements("SQL注入", "HIGH");
        assertTrue(manager.getAchievement("first_sqli").isUnlocked());
    }

    @Test
    void unlockHighSeverity() {
        manager.checkVulnerabilityAchievements("路径穿越", "HIGH");
        assertTrue(manager.getAchievement("high_severity").isUnlocked());
    }

    @Test
    void criticalAlsoTriggersHighSeverity() {
        manager.checkVulnerabilityAchievements("命令注入", "CRITICAL");
        assertTrue(manager.getAchievement("high_severity").isUnlocked());
    }

    @Test
    void lowSeverityDoesNotTriggerHigh() {
        manager.checkVulnerabilityAchievements("信息泄露", "LOW");
        assertFalse(manager.getAchievement("high_severity").isUnlocked());
    }

    @Test
    void tenVulnsAchievement() {
        for (int i = 0; i < 10; i++) {
            manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        }
        assertTrue(manager.getAchievement("ten_vulns").isUnlocked());
    }

    @Test
    void nineVulnsNotEnough() {
        for (int i = 0; i < 9; i++) {
            manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        }
        assertFalse(manager.getAchievement("ten_vulns").isUnlocked());
    }

    @Test
    void allTypesAchievementWithPokedex() {
        VulnerabilityPokedex pokedex = mock(VulnerabilityPokedex.class);
        when(pokedex.getDiscoveredCount()).thenReturn(27);
        when(pokedex.getTotalCount()).thenReturn(27);
        manager.setPokedex(pokedex);

        manager.checkVulnerabilityAchievements("XSS", "LOW");
        assertTrue(manager.getAchievement("all_types").isUnlocked());
    }

    @Test
    void allTypesNotTriggeredWhenIncomplete() {
        VulnerabilityPokedex pokedex = mock(VulnerabilityPokedex.class);
        when(pokedex.getDiscoveredCount()).thenReturn(20);
        when(pokedex.getTotalCount()).thenReturn(27);
        manager.setPokedex(pokedex);

        manager.checkVulnerabilityAchievements("XSS", "LOW");
        assertFalse(manager.getAchievement("all_types").isUnlocked());
    }

    @Test
    void duplicateUnlockDoesNotIncrement() {
        manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        long firstTime = manager.getAchievement("first_xss").getUnlockedTime();
        manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        assertEquals(firstTime, manager.getAchievement("first_xss").getUnlockedTime());
        assertEquals(1, manager.getUnlockedCount());
    }

    @Test
    void resetClearsAll() {
        manager.checkVulnerabilityAchievements("XSS", "HIGH");
        manager.checkVulnerabilityAchievements("SQL注入", "HIGH");
        assertTrue(manager.getUnlockedCount() > 0);

        manager.resetAll();
        assertEquals(0, manager.getUnlockedCount());
    }

    @Test
    void listenerNotifiedOnUnlock() {
        AchievementManager.AchievementListener listener = mock(AchievementManager.AchievementListener.class);
        manager.addListener(listener);

        manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        verify(listener, times(1)).onAchievementUnlocked(any(Achievement.class));
    }

    @Test
    void listenerNotNotifiedOnDuplicate() {
        AchievementManager.AchievementListener listener = mock(AchievementManager.AchievementListener.class);
        manager.addListener(listener);

        manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        manager.checkVulnerabilityAchievements("XSS", "MEDIUM");
        verify(listener, times(1)).onAchievementUnlocked(any(Achievement.class));
    }

    @Test
    void nullVulnTypeDoesNotCrash() {
        assertDoesNotThrow(() -> manager.checkVulnerabilityAchievements(null, null));
    }

    @Test
    void emptyVulnTypeDoesNotCrash() {
        assertDoesNotThrow(() -> manager.checkVulnerabilityAchievements("", ""));
    }

    @Test
    void persistenceSavesToConfig() {
        manager.checkVulnerabilityAchievements("XSS", "HIGH");
        verify(configManager, atLeastOnce()).setFunFeaturesConfig(any());
    }
}
