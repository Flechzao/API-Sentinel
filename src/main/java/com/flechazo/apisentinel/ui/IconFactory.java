package com.flechazo.apisentinel.ui;

import javax.swing.Icon;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.util.function.Consumer;

/**
 * 零依赖矢量图标工厂——用 {@link Graphics2D} 自绘、返回标准 {@link Icon}，
 * 取代此前散布在 UI 里的 emoji 字符（跨系统/字体渲染不一致、显廉价）。
 *
 * <p>设计要点：
 * <ul>
 *   <li>所有图形都在 24×24 的归一化坐标里绘制，paint 时再按目标尺寸整体缩放，
 *       因此任意大小都是矢量清晰、天然支持 HiDPI。</li>
 *   <li>颜色由调用方传入（通常来自 {@link BurpTheme}），从而明暗主题自适应。</li>
 *   <li>纯 {@code java.awt} / {@code javax.swing}，无新增运行时依赖。</li>
 * </ul>
 *
 * <p>两类风格：
 * <ul>
 *   <li><b>状态徽章</b>（{@code OK/WARN/FAIL/INFO/NEUTRAL/RUNNING}）——实心圆/三角 + 白色内嵌字形，
 *       语义色随传入颜色变化，用于替换 ✅ ⚠ ❌ ⬜ 等。</li>
 *   <li><b>功能线性图标</b>（{@code SHIELD/IMPORT/KEY/...}）——描边单色线条风，用于功能入口。</li>
 * </ul>
 */
public final class IconFactory {

    private IconFactory() {}

    /** 归一化画布边长——所有 painter 都在 24×24 坐标系里作图。 */
    private static final double UNIT = 24.0;

    public enum Kind {
        // 状态徽章（实心 + 白色字形）
        OK, WARN, FAIL, INFO, NEUTRAL, RUNNING,
        // 功能线性图标（描边）
        SHIELD, IMPORT, KEY, COOKIE, SEARCH, FOLDER, TOOLS, ROBOT, GLOBE, GEAR, RULES, SIGNAL
    }

    /**
     * 生成一个图标。
     *
     * @param kind  图标语义
     * @param size  目标像素边长（正方形）
     * @param color 主色；状态徽章用作底色（字形为白），线性图标用作线条色
     */
    public static Icon of(Kind kind, int size, Color color) {
        Color c = color != null ? color : Color.GRAY;
        return new VectorIcon(size, g2 -> paint(kind, g2, c));
    }

    /**
     * 双色状态徽章——{@code fill} 作圆/三角底色，{@code glyph} 作内嵌字形色。
     * 用于纯色背景（如 Toast）上反色渲染：白底圆 + 语义色字形。
     * 仅对 {@code OK/WARN/FAIL/INFO} 有意义；其余 kind 退化为单色 {@link #of}。
     */
    public static Icon badge(Kind kind, int size, Color fill, Color glyph) {
        Color f = fill != null ? fill : Color.GRAY;
        Color gl = glyph != null ? glyph : Color.WHITE;
        return new VectorIcon(size, g2 -> paintBadge(kind, g2, f, gl));
    }

    // ── 便捷方法（直接接 BurpTheme 语义色）──

    /** 状态图标：ok=✓ / warn=! / fail=✕ / null=空心占位（⬜ 的替代）。 */
    public static Icon status(BurpTheme theme, int size, Boolean ok) {
        if (ok == null) return of(Kind.NEUTRAL, size, theme.mutedText());
        return ok ? of(Kind.OK, size, theme.statusOk())
                  : of(Kind.WARN, size, theme.statusPending());
    }

    private static void paint(Kind kind, Graphics2D g2, Color color) {
        switch (kind) {
            case OK -> disc(g2, color, g -> check(g));
            case WARN -> triangle(g2, color, g -> bang(g));
            case FAIL -> disc(g2, color, g -> cross(g));
            case INFO -> disc(g2, color, g -> infoGlyph(g));
            case NEUTRAL -> ring(g2, color);
            case RUNNING -> spinnerArc(g2, color);
            case SHIELD -> shield(g2, color);
            case IMPORT -> importTray(g2, color);
            case KEY -> key(g2, color);
            case COOKIE -> cookie(g2, color);
            case SEARCH -> search(g2, color);
            case FOLDER -> folder(g2, color);
            case TOOLS -> wrench(g2, color);
            case ROBOT -> robot(g2, color);
            case GLOBE -> globe(g2, color);
            case GEAR -> gear(g2, color);
            case RULES -> rules(g2, color);
            case SIGNAL -> signal(g2, color);
        }
    }

    // ────────────────────────── 状态徽章 ──────────────────────────

    /** OK/WARN/FAIL/INFO 的双色分派（其余退化为单色）。 */
    private static void paintBadge(Kind kind, Graphics2D g2, Color fill, Color glyph) {
        switch (kind) {
            case OK -> disc(g2, fill, glyph, IconFactory::check);
            case WARN -> triangle(g2, fill, glyph, IconFactory::bang);
            case FAIL -> disc(g2, fill, glyph, IconFactory::cross);
            case INFO -> disc(g2, fill, glyph, IconFactory::infoGlyph);
            default -> paint(kind, g2, fill);
        }
    }

    /** 实心圆底 + 白色字形。 */
    private static void disc(Graphics2D g2, Color color, Consumer<Graphics2D> glyph) {
        disc(g2, color, Color.WHITE, glyph);
    }

    /** 实心圆底 + 指定字形色。 */
    private static void disc(Graphics2D g2, Color fill, Color glyphColor, Consumer<Graphics2D> glyph) {
        g2.setColor(fill);
        g2.fill(new Ellipse2D.Double(1.5, 1.5, 21, 21));
        g2.setColor(glyphColor);
        g2.setStroke(new BasicStroke(2.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        glyph.accept(g2);
    }

    /** 圆角三角底 + 白色字形（警告）。 */
    private static void triangle(Graphics2D g2, Color color, Consumer<Graphics2D> glyph) {
        triangle(g2, color, Color.WHITE, glyph);
    }

    /** 圆角三角底 + 指定字形色。 */
    private static void triangle(Graphics2D g2, Color fill, Color glyphColor, Consumer<Graphics2D> glyph) {
        Path2D tri = new Path2D.Double();
        tri.moveTo(12, 2.5);
        tri.lineTo(22.5, 21);
        tri.lineTo(1.5, 21);
        tri.closePath();
        g2.setColor(fill);
        g2.setStroke(new BasicStroke(3.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.draw(tri); // 圆角描边让顶点变圆
        g2.fill(tri);
        g2.setColor(glyphColor);
        g2.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        glyph.accept(g2);
    }

    private static void check(Graphics2D g2) {
        Path2D p = new Path2D.Double();
        p.moveTo(6.5, 12.3);
        p.lineTo(10.5, 16.2);
        p.lineTo(17.5, 8);
        g2.draw(p);
    }

    private static void cross(Graphics2D g2) {
        g2.draw(new java.awt.geom.Line2D.Double(8, 8, 16, 16));
        g2.draw(new java.awt.geom.Line2D.Double(16, 8, 8, 16));
    }

    private static void bang(Graphics2D g2) {
        // 三角内的感叹号靠下（三角重心偏下）
        g2.draw(new java.awt.geom.Line2D.Double(12, 9, 12, 15));
        g2.fill(new Ellipse2D.Double(10.9, 16.6, 2.2, 2.2));
    }

    private static void infoGlyph(Graphics2D g2) {
        g2.fill(new Ellipse2D.Double(10.9, 6.4, 2.2, 2.2));
        g2.draw(new java.awt.geom.Line2D.Double(12, 10.5, 12, 17.5));
    }

    /** 空心圆——未配置/占位（替代 ⬜）。 */
    private static void ring(Graphics2D g2, Color color) {
        g2.setColor(color);
        g2.setStroke(new BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.draw(new Ellipse2D.Double(2.5, 2.5, 19, 19));
    }

    /** 300° 圆弧——「运行中」静态形态（动效由外部 Timer 旋转）。 */
    private static void spinnerArc(Graphics2D g2, Color color) {
        g2.setColor(color);
        g2.setStroke(new BasicStroke(2.6f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2.draw(new java.awt.geom.Arc2D.Double(3, 3, 18, 18, 90, 300, java.awt.geom.Arc2D.OPEN));
    }

    // ────────────────────────── 功能线性图标 ──────────────────────────

    private static void stroke(Graphics2D g2, Color color) {
        g2.setColor(color);
        g2.setStroke(new BasicStroke(1.9f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
    }

    /** 盾牌（品牌 / 检测规则语义）——描边盾形 + 内嵌对勾。 */
    private static void shield(Graphics2D g2, Color color) {
        stroke(g2, color);
        Path2D s = shieldPath();
        g2.draw(s);
        Path2D chk = new Path2D.Double();
        chk.moveTo(8.5, 12);
        chk.lineTo(11, 14.6);
        chk.lineTo(15.8, 8.8);
        g2.draw(chk);
    }

    private static Path2D shieldPath() {
        Path2D s = new Path2D.Double();
        s.moveTo(12, 2.5);
        s.lineTo(20, 5.5);
        s.lineTo(20, 12);
        s.curveTo(20, 17.5, 16.4, 20.3, 12, 21.8);
        s.curveTo(7.6, 20.3, 4, 17.5, 4, 12);
        s.lineTo(4, 5.5);
        s.closePath();
        return s;
    }

    /** 导入——托盘 + 向下箭头。 */
    private static void importTray(Graphics2D g2, Color color) {
        stroke(g2, color);
        // 向下箭头
        g2.draw(new java.awt.geom.Line2D.Double(12, 3.5, 12, 13.5));
        Path2D arrow = new Path2D.Double();
        arrow.moveTo(8, 9.8);
        arrow.lineTo(12, 13.8);
        arrow.lineTo(16, 9.8);
        g2.draw(arrow);
        // 托盘（开口向上的 U）
        Path2D tray = new Path2D.Double();
        tray.moveTo(4.5, 15);
        tray.lineTo(4.5, 20);
        tray.lineTo(19.5, 20);
        tray.lineTo(19.5, 15);
        g2.draw(tray);
    }

    /** 钥匙——环 + 杆 + 齿。 */
    private static void key(Graphics2D g2, Color color) {
        stroke(g2, color);
        g2.draw(new Ellipse2D.Double(4, 4, 8, 8));
        g2.draw(new java.awt.geom.Line2D.Double(10.5, 10.5, 20, 20));
        g2.draw(new java.awt.geom.Line2D.Double(20, 20, 17.5, 20));
        g2.draw(new java.awt.geom.Line2D.Double(17.8, 17.8, 15.8, 17.8));
    }

    /** 曲奇——圆 + 几点巧克力豆（认证会话 🍪）。 */
    private static void cookie(Graphics2D g2, Color color) {
        stroke(g2, color);
        g2.draw(new Ellipse2D.Double(3.5, 3.5, 17, 17));
        g2.setColor(color);
        g2.fill(new Ellipse2D.Double(8.5, 8, 1.8, 1.8));
        g2.fill(new Ellipse2D.Double(13.5, 10, 1.8, 1.8));
        g2.fill(new Ellipse2D.Double(10, 14, 1.8, 1.8));
    }

    /** 放大镜——检索。 */
    private static void search(Graphics2D g2, Color color) {
        stroke(g2, color);
        g2.draw(new Ellipse2D.Double(4, 4, 12, 12));
        g2.draw(new java.awt.geom.Line2D.Double(14.5, 14.5, 20.5, 20.5));
    }

    /** 文件夹——带上凸标签。 */
    private static void folder(Graphics2D g2, Color color) {
        stroke(g2, color);
        Path2D f = new Path2D.Double();
        f.moveTo(3.5, 7);
        f.lineTo(9, 7);
        f.lineTo(11, 9.5);
        f.lineTo(20.5, 9.5);
        f.lineTo(20.5, 19);
        f.lineTo(3.5, 19);
        f.closePath();
        g2.draw(f);
    }

    /** 扳手——工具管理。 */
    private static void wrench(Graphics2D g2, Color color) {
        stroke(g2, color);
        Path2D w = new Path2D.Double();
        // 扳手头（缺口环）+ 斜柄
        w.moveTo(16.5, 4.5);
        w.curveTo(13.5, 4, 11, 6.5, 11.6, 9.5);
        w.lineTo(4.5, 16.6);
        w.lineTo(7.4, 19.5);
        w.lineTo(14.5, 12.4);
        w.curveTo(17.5, 13, 20, 10.5, 19.5, 7.5);
        w.lineTo(16.6, 10.4);
        w.lineTo(13.6, 7.4);
        w.closePath();
        g2.draw(w);
    }

    /** 机器人——Agent 模式。 */
    private static void robot(Graphics2D g2, Color color) {
        stroke(g2, color);
        // 头
        g2.draw(new RoundRectangle2D.Double(5, 8, 14, 11, 3, 3));
        // 天线
        g2.draw(new java.awt.geom.Line2D.Double(12, 8, 12, 4.5));
        g2.setColor(color);
        g2.fill(new Ellipse2D.Double(10.8, 2.8, 2.4, 2.4));
        // 眼睛
        g2.fill(new Ellipse2D.Double(8.5, 12, 2.2, 2.2));
        g2.fill(new Ellipse2D.Double(13.3, 12, 2.2, 2.2));
    }

    /** 地球——浏览器。 */
    private static void globe(Graphics2D g2, Color color) {
        stroke(g2, color);
        g2.draw(new Ellipse2D.Double(3.5, 3.5, 17, 17));
        g2.draw(new Ellipse2D.Double(8.5, 3.5, 7, 17)); // 经线
        g2.draw(new java.awt.geom.Line2D.Double(3.5, 12, 20.5, 12)); // 赤道
    }

    /** 齿轮——设置/高级。 */
    private static void gear(Graphics2D g2, Color color) {
        stroke(g2, color);
        double cx = 12, cy = 12, rIn = 4.3, rOut = 8.2;
        Path2D teeth = new Path2D.Double();
        for (int i = 0; i < 8; i++) {
            double a = Math.PI * 2 * i / 8;
            double a2 = a + Math.PI / 8;
            teeth.moveTo(cx + rIn * Math.cos(a), cy + rIn * Math.sin(a));
            teeth.lineTo(cx + rOut * Math.cos(a), cy + rOut * Math.sin(a));
            // 用短弧近似齿冠
            teeth.moveTo(cx + rOut * Math.cos(a), cy + rOut * Math.sin(a));
            teeth.lineTo(cx + rOut * Math.cos(a2), cy + rOut * Math.sin(a2));
        }
        g2.draw(teeth);
        g2.draw(new Ellipse2D.Double(cx - rIn, cy - rIn, rIn * 2, rIn * 2));
        g2.draw(new Ellipse2D.Double(cx - 2, cy - 2, 4, 4));
    }

    /** 规则清单——盾牌 + 三条横线（检测规则管理）。 */
    private static void rules(Graphics2D g2, Color color) {
        stroke(g2, color);
        g2.draw(shieldPath());
        g2.draw(new java.awt.geom.Line2D.Double(8, 9.5, 16, 9.5));
        g2.draw(new java.awt.geom.Line2D.Double(8, 12.5, 16, 12.5));
        g2.draw(new java.awt.geom.Line2D.Double(8, 15.5, 13, 15.5));
    }

    /** 信号波——带外/回连（OOB / DNSLog）：左下角源点 + 三道向右上放射的同心弧。 */
    private static void signal(Graphics2D g2, Color color) {
        stroke(g2, color);
        double cx = 5.5, cy = 18.5;
        for (double r : new double[]{5.5, 10, 14.5}) {
            g2.draw(new java.awt.geom.Arc2D.Double(
                    cx - r, cy - r, r * 2, r * 2, 0, 90, java.awt.geom.Arc2D.OPEN));
        }
        g2.setColor(color);
        g2.fill(new Ellipse2D.Double(cx - 1.6, cy - 1.6, 3.2, 3.2));
    }

    // ────────────────────────── Icon 实现 ──────────────────────────

    /** 把 24×24 空间的 painter 缩放到目标尺寸绘制。 */
    private record VectorIcon(int size, Consumer<Graphics2D> painter) implements Icon {
        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
                g2.translate(x, y);
                double s = size / UNIT;
                g2.scale(s, s);
                painter.accept(g2);
            } finally {
                g2.dispose();
            }
        }

        @Override public int getIconWidth() { return size; }
        @Override public int getIconHeight() { return size; }
    }
}
