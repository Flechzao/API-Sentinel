package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class StatsManagerTest {

    private StatsManager stats;
    private ConfigManager configManager;

    @BeforeEach
    void setUp() {
        configManager = mock(ConfigManager.class);
        when(configManager.getFunFeaturesConfig()).thenReturn(new com.google.gson.JsonObject());
        LeveledLogger logger = mock(LeveledLogger.class);
        stats = new StatsManager(configManager, logger);
    }

    @Test
    void initiallyZero() {
        assertEquals(0, stats.getTotalFindings());
        assertEquals(0, stats.getTodayFindings());
        assertEquals(0, stats.getConsecutiveDays());
        assertEquals(0, stats.getBestDay());
    }

    @Test
    void recordSingleFinding() {
        stats.recordFinding("SQL注入", "HIGH");
        assertEquals(1, stats.getTotalFindings());
        assertEquals(1, stats.getTodayFindings());
        assertEquals(1, stats.getConsecutiveDays());
    }

    @Test
    void recordMultipleFindings() {
        stats.recordFinding("SQL注入", "HIGH");
        stats.recordFinding("XSS", "MEDIUM");
        stats.recordFinding("IDOR", "HIGH");
        assertEquals(3, stats.getTotalFindings());
        assertEquals(3, stats.getTodayFindings());
    }

    @Test
    void typeCountsTracked() {
        stats.recordFinding("SQL注入", "HIGH");
        stats.recordFinding("SQL注入", "HIGH");
        stats.recordFinding("XSS", "MEDIUM");

        var counts = stats.getTypeCounts();
        assertEquals(2, counts.get("SQL注入"));
        assertEquals(1, counts.get("XSS"));
    }

    @Test
    void bestTypeReturnsMostCommon() {
        stats.recordFinding("SQL注入", "HIGH");
        stats.recordFinding("SQL注入", "HIGH");
        stats.recordFinding("XSS", "MEDIUM");

        String best = stats.getBestType();
        assertTrue(best.contains("SQL注入"));
        assertTrue(best.contains("2"));
    }

    @Test
    void bestDayTracksMaximum() {
        stats.recordFinding("XSS", "LOW");
        stats.recordFinding("XSS", "LOW");
        stats.recordFinding("XSS", "LOW");
        assertEquals(3, stats.getBestDay());
    }

    @Test
    void nullTypeDoesNotCrash() {
        assertDoesNotThrow(() -> stats.recordFinding(null, null));
        assertEquals(1, stats.getTotalFindings());
    }

    @Test
    void resetClearsAll() {
        stats.recordFinding("XSS", "HIGH");
        stats.recordFinding("SQL注入", "HIGH");
        assertTrue(stats.getTotalFindings() > 0);

        stats.reset();
        assertEquals(0, stats.getTotalFindings());
        assertEquals(0, stats.getTodayFindings());
        assertEquals(0, stats.getConsecutiveDays());
        assertTrue(stats.getTypeCounts().isEmpty());
    }

    @Test
    void dailyFindingsTracked() {
        stats.recordFinding("XSS", "LOW");
        var daily = stats.getDailyFindings();
        assertFalse(daily.isEmpty());
        // Today's entry should exist
        String today = java.time.LocalDate.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE);
        assertTrue(daily.containsKey(today));
        assertEquals(1, daily.get(today));
    }

    @Test
    void persistenceSavesToConfig() {
        stats.recordFinding("XSS", "HIGH");
        verify(configManager, atLeastOnce()).setFunFeaturesConfig(any());
    }
}
