package com.flechazo.apisentinel.fun;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EasterEggsTest {

    @Test
    void funnyErrorNeverNull() {
        for (int i = 0; i < 20; i++) {
            assertNotNull(EasterEggs.getFunnyError());
        }
    }

    @Test
    void funnyErrorVaries() {
        java.util.Set<String> errors = new java.util.HashSet<>();
        for (int i = 0; i < 30; i++) {
            errors.add(EasterEggs.getFunnyError());
        }
        assertTrue(errors.size() >= 3, "Funny errors should vary, got: " + errors.size());
    }

    @Test
    void funnyTipNeverNull() {
        for (int i = 0; i < 20; i++) {
            assertNotNull(EasterEggs.getFunnyTip());
        }
    }

    @Test
    void funnyTipVaries() {
        java.util.Set<String> tips = new java.util.HashSet<>();
        for (int i = 0; i < 30; i++) {
            tips.add(EasterEggs.getFunnyTip());
        }
        assertTrue(tips.size() >= 3, "Funny tips should vary, got: " + tips.size());
    }

    @Test
    void specialDateMessageReturnsNullOrString() {
        // Should not crash regardless of current date
        String msg = EasterEggs.getSpecialDateMessage();
        // On most days this returns null, on special dates returns a message
        // Just verify it doesn't throw
        assertDoesNotThrow(() -> EasterEggs.getSpecialDateMessage());
    }

    @Test
    void funnyErrorsContainChinese() {
        String error = EasterEggs.getFunnyError();
        // At least some characters should be Chinese
        boolean hasChinese = error.chars().anyMatch(c -> c >= 0x4E00 && c <= 0x9FFF);
        assertTrue(hasChinese, "Funny errors should contain Chinese: " + error);
    }

    @Test
    void funnyTipsContainUsefulContent() {
        String tip = EasterEggs.getFunnyTip();
        assertTrue(tip.length() > 10, "Tips should be substantive: " + tip);
    }
}
