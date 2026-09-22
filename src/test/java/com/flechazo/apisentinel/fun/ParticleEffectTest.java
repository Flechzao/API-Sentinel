package com.flechazo.apisentinel.fun;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * ParticleEffect 的逻辑测试（不涉及 Swing 渲染）
 */
class ParticleEffectTest {

    @Test
    void constructorDoesNotCrash() {
        assertDoesNotThrow(() -> new ParticleEffect());
    }

    @Test
    void emitDoesNotCrash() {
        ParticleEffect effect = new ParticleEffect();
        assertDoesNotThrow(() -> effect.emit(100, 100, "HIGH"));
        assertDoesNotThrow(() -> effect.emit(200, 200, "LOW"));
        assertDoesNotThrow(() -> effect.emit(300, 300, "CRITICAL"));
        assertDoesNotThrow(() -> effect.emit(400, 400, null));
        assertDoesNotThrow(() -> effect.emit(500, 500, "UNKNOWN"));
    }

    @Test
    void stopDoesNotCrash() {
        ParticleEffect effect = new ParticleEffect();
        effect.emit(100, 100, "HIGH");
        assertDoesNotThrow(() -> effect.stop());
    }

    @Test
    void stopWithoutEmitDoesNotCrash() {
        ParticleEffect effect = new ParticleEffect();
        assertDoesNotThrow(() -> effect.stop());
    }

    @Test
    void multipleEmitsDoNotCrash() {
        ParticleEffect effect = new ParticleEffect();
        for (int i = 0; i < 10; i++) {
            final int x = i * 50;
            assertDoesNotThrow(() -> effect.emit(x, x, "MEDIUM"));
        }
        effect.stop();
    }
}
