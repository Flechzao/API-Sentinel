package com.flechazo.apisentinel.fun;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.*;

/**
 * 彩蛋系统：Konami Code + 趣味提示
 */
public class EasterEggs {

    // Konami Code: ↑↑↓↓←→←→BA
    private static final int[] KONAMI = {
        KeyEvent.VK_UP, KeyEvent.VK_UP,
        KeyEvent.VK_DOWN, KeyEvent.VK_DOWN,
        KeyEvent.VK_LEFT, KeyEvent.VK_RIGHT,
        KeyEvent.VK_LEFT, KeyEvent.VK_RIGHT,
        KeyEvent.VK_B, KeyEvent.VK_A
    };
    private static int konamiIndex = 0;
    private static boolean konamiActivated = false;

    private static final String[] FUNNY_ERRORS = {
        "网络开小差了，它可能需要一杯咖啡 ☕",
        "请求迷路了，正在派遣搜救队...",
        "服务器正在思考人生，请稍后再试",
        "连接被防火墙的热情拥抱拦截了",
        "目标服务器表示：今天不想上班",
        "网络抖动中，就像你的咖啡杯在桌上振动",
        "请求超时了——它可能去环游世界了"
    };

    private static final String[] FUNNY_TIPS = {
        "小贴士：Ctrl+D 可以快速复制请求到 Repeater",
        "小贴士：Burp 的 Comparer 工具对比响应差异非常好用",
        "小贴士：测试 IDOR 时，记得用两个不同账号的 Cookie",
        "小贴士：SQL 注入报错信息中的数据库版本是重要线索",
        "小贴士：CORS 测试时，Origin 头可以用任意域名",
        "小贴士：路径穿越不仅限于 ../，还有 ..%2f 和 ..%252f",
        "小贴士：竞态条件测试需要真正的并发，不是串行重放"
    };

    private static final Random random = new Random();

    /**
     * 注册 Konami Code 监听到指定组件
     */
    public static void registerKonamiCode(JComponent component, Runnable onActivate) {
        component.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (konamiActivated) return;
                if (e.getKeyCode() == KONAMI[konamiIndex]) {
                    konamiIndex++;
                    if (konamiIndex == KONAMI.length) {
                        konamiActivated = true;
                        konamiIndex = 0;
                        SwingUtilities.invokeLater(onActivate);
                    }
                } else {
                    konamiIndex = (e.getKeyCode() == KONAMI[0]) ? 1 : 0;
                }
            }
        });
        component.setFocusable(true);
    }

    public static String getFunnyError() {
        return FUNNY_ERRORS[random.nextInt(FUNNY_ERRORS.length)];
    }

    public static String getFunnyTip() {
        return FUNNY_TIPS[random.nextInt(FUNNY_TIPS.length)];
    }

    /**
     * 特殊日期检查
     */
    public static String getSpecialDateMessage() {
        Calendar cal = Calendar.getInstance();
        int month = cal.get(Calendar.MONTH) + 1;
        int day = cal.get(Calendar.DAY_OF_MONTH);

        if (month == 1 && day == 1) return "新年快乐！愿新的一年零漏洞！";
        if (month == 4 && day == 1) return "愚人节！今天发现的所有漏洞都是真的（大概）";
        if (month == 10 && day == 31) return "万圣节快乐！不给糖就捣蛋，不给漏洞就扫描！";
        if (month == 12 && day == 25) return "圣诞快乐！最好的礼物是零漏洞的代码";
        if (month == 3 && day == 14) return "π 日快乐！3.14159... 就像你的漏洞数量一样无穷无尽";
        if (month == 10 && day == 4) return "今天是 404 日！Not Found... 但漏洞 Found！";
        return null;
    }
}
