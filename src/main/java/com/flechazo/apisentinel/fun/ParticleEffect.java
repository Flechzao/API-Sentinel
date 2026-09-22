package com.flechazo.apisentinel.fun;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.geom.Ellipse2D;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 粒子特效面板
 */
public class ParticleEffect extends JPanel {
    private final List<Particle> particles = new ArrayList<>();
    private final Timer animationTimer;
    private final Random random = new Random();
    private long startTime;
    private final long duration = 2000; // 2 秒动画

    private static class Particle {
        double x, y;
        double vx, vy;
        double size;
        Color color;
        double alpha;
        double decay;

        Particle(double x, double y, double vx, double vy, double size, Color color, double decay) {
            this.x = x;
            this.y = y;
            this.vx = vx;
            this.vy = vy;
            this.size = size;
            this.color = color;
            this.alpha = 1.0;
            this.decay = decay;
        }

        void update() {
            x += vx;
            y += vy;
            vy += 0.2; // 重力
            alpha -= decay;
            size *= 0.98; // 缩小
        }

        boolean isAlive() {
            return alpha > 0 && size > 0.5;
        }
    }

    public ParticleEffect() {
        setOpaque(false);
        setLayout(null);
        
        animationTimer = new Timer(16, new ActionListener() { // 60 FPS
            @Override
            public void actionPerformed(ActionEvent e) {
                update();
                repaint();
                
                // 检查是否结束
                if (System.currentTimeMillis() - startTime > duration || particles.isEmpty()) {
                    animationTimer.stop();
                    if (getParent() != null) {
                        getParent().remove(ParticleEffect.this);
                        getParent().repaint();
                    }
                }
            }
        });
    }

    /**
     * 发射粒子
     */
    public void emit(int x, int y, String severity) {
        particles.clear();
        startTime = System.currentTimeMillis();

        Color baseColor = getColorForSeverity(severity);
        int particleCount = getParticleCountForSeverity(severity);

        for (int i = 0; i < particleCount; i++) {
            double angle = random.nextDouble() * Math.PI * 2;
            double speed = 2 + random.nextDouble() * 8;
            double vx = Math.cos(angle) * speed;
            double vy = Math.sin(angle) * speed - 3; // 向上偏移
            double size = 3 + random.nextDouble() * 8;
            double decay = 0.01 + random.nextDouble() * 0.02;

            // 添加颜色变化
            Color color = new Color(
                Math.min(255, Math.max(0, baseColor.getRed() + random.nextInt(60) - 30)),
                Math.min(255, Math.max(0, baseColor.getGreen() + random.nextInt(60) - 30)),
                Math.min(255, Math.max(0, baseColor.getBlue() + random.nextInt(60) - 30))
            );

            particles.add(new Particle(x, y, vx, vy, size, color, decay));
        }

        animationTimer.start();
    }

    private Color getColorForSeverity(String severity) {
        if (severity == null) {
            return new Color(0, 200, 0); // 绿色
        }

        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return new Color(255, 0, 0); // 红色
            case "HIGH":
                return new Color(255, 100, 0); // 橙色
            case "MEDIUM":
                return new Color(255, 200, 0); // 黄色
            case "LOW":
                return new Color(0, 200, 0); // 绿色
            case "INFO":
                return new Color(0, 150, 255); // 蓝色
            default:
                return new Color(0, 200, 0); // 绿色
        }
    }

    private int getParticleCountForSeverity(String severity) {
        if (severity == null) {
            return 30;
        }

        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return 80;
            case "HIGH":
                return 60;
            case "MEDIUM":
                return 40;
            case "LOW":
                return 25;
            case "INFO":
                return 15;
            default:
                return 30;
        }
    }

    private void update() {
        particles.removeIf(p -> !p.isAlive());
        for (Particle p : particles) {
            p.update();
        }
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        
        Graphics2D g2d = (Graphics2D) g.create();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        for (Particle p : particles) {
            if (p.isAlive()) {
                g2d.setColor(new Color(
                    p.color.getRed(),
                    p.color.getGreen(),
                    p.color.getBlue(),
                    (int) (p.alpha * 255)
                ));
                
                Ellipse2D.Double circle = new Ellipse2D.Double(
                    p.x - p.size / 2,
                    p.y - p.size / 2,
                    p.size,
                    p.size
                );
                g2d.fill(circle);
            }
        }

        g2d.dispose();
    }

    public void stop() {
        animationTimer.stop();
        particles.clear();
        if (getParent() != null) {
            getParent().remove(this);
            getParent().repaint();
        }
    }
}
