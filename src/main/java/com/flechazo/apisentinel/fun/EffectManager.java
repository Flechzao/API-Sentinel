package com.flechazo.apisentinel.fun;

import com.flechazo.apisentinel.logging.LeveledLogger;

import javax.swing.*;
import java.awt.*;

/**
 * 特效管理器 - 在 Burp 主窗口上显示特效
 */
public class EffectManager {
    private final LeveledLogger logger;
    private JLayeredPane layeredPane;
    private boolean enabled = true;

    public EffectManager(LeveledLogger logger) {
        this.logger = logger;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 初始化特效层
     */
    public void initialize(JFrame frame) {
        if (frame == null) {
            logger.warn("[Fun] Cannot initialize effects: frame is null");
            return;
        }

        try {
            layeredPane = frame.getLayeredPane();
            logger.debug("[Fun] Effect layer initialized");
        } catch (Exception e) {
            logger.warn("[Fun] Failed to initialize effect layer: %s", e.getMessage());
        }
    }

    /**
     * 在指定位置显示粒子特效
     */
    public void showParticleEffect(int x, int y, String severity) {
        if (!enabled || layeredPane == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                ParticleEffect effect = new ParticleEffect();
                effect.setBounds(0, 0, layeredPane.getWidth(), layeredPane.getHeight());
                
                layeredPane.add(effect, JLayeredPane.POPUP_LAYER);
                effect.emit(x, y, severity);
                
                logger.debug("[Fun] Particle effect shown at (%d, %d) for severity %s", x, y, severity);
            } catch (Exception e) {
                logger.debug("[Fun] Failed to show particle effect: %s", e.getMessage());
            }
        });
    }

    /**
     * 在屏幕中央显示粒子特效
     */
    public void showParticleEffectAtCenter(String severity) {
        if (layeredPane == null) {
            return;
        }

        int centerX = layeredPane.getWidth() / 2;
        int centerY = layeredPane.getHeight() / 2;
        showParticleEffect(centerX, centerY, severity);
    }

    /**
     * 在组件位置显示粒子特效
     */
    public void showParticleEffectAtComponent(Component component, String severity) {
        if (component == null || layeredPane == null) {
            return;
        }

        try {
            Point location = component.getLocationOnScreen();
            Point layeredPaneLocation = layeredPane.getLocationOnScreen();
            
            int relativeX = location.x - layeredPaneLocation.x + component.getWidth() / 2;
            int relativeY = location.y - layeredPaneLocation.y + component.getHeight() / 2;
            
            showParticleEffect(relativeX, relativeY, severity);
        } catch (Exception e) {
            // 如果无法获取组件位置，使用屏幕中央
            showParticleEffectAtCenter(severity);
        }
    }
}
