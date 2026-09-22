package com.demo.vulnapp.controller;

import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * #51 VULNERABLE: coupon replay — the same coupon code can be applied
 * unlimited times. No tracking of whether a coupon has been used.
 * #52 SAFE: one-time-use coupons — marked as used after first application.
 *
 * Business logic vulnerability: an attacker can reuse a discount coupon
 * across multiple orders to get repeated discounts.
 */
@RestController
public class CouponController {

    private static final Map<String, Coupon> COUPONS = new ConcurrentHashMap<>();

    static {
        COUPONS.put("SAVE10", new Coupon("SAVE10", 10.0, "满100减10"));
        COUPONS.put("VIP20", new Coupon("VIP20", 20.0, "VIP 8折优惠"));
        COUPONS.put("NEW50", new Coupon("NEW50", 50.0, "新用户立减50"));
        COUPONS.put("SUMMER30", new Coupon("SUMMER30", 30.0, "夏日清凉满减"));
        COUPONS.put("TECH100", new Coupon("TECH100", 100.0, "数码产品满500减100"));
        COUPONS.put("FIRST15", new Coupon("FIRST15", 15.0, "首单立减15"));
    }

    record Coupon(String code, double discount, String description) {}

    /**
     * #51: VULNERABLE — applies coupon without tracking usage.
     * The same coupon can be used unlimited times.
     */
    @PostMapping("/api/coupon/apply")
    public Map<String, Object> applyCoupon(@RequestBody Map<String, String> body) {
        String code = body.getOrDefault("code", "").toUpperCase();
        double orderTotal = parseDouble(body.getOrDefault("orderTotal", "0"));

        Coupon coupon = COUPONS.get(code);
        if (coupon == null) {
            return Map.of("success", false, "error", "无效的优惠码");
        }

        double newTotal = Math.max(0, orderTotal - coupon.discount());
        return Map.of(
                "success", true,
                "code", coupon.code(),
                "description", coupon.description(),
                "discount", coupon.discount(),
                "originalTotal", orderTotal,
                "newTotal", newTotal
        );
    }

    /**
     * #52: SAFE — tracks coupon usage, rejects already-used coupons.
     */
    @PostMapping("/api/coupon/redeem")
    public Map<String, Object> applyCouponSafe(@RequestBody Map<String, String> body) {
        String code = body.getOrDefault("code", "").toUpperCase();
        double orderTotal = parseDouble(body.getOrDefault("orderTotal", "0"));

        Coupon coupon = COUPONS.get(code);
        if (coupon == null) {
            return Map.of("success", false, "error", "无效的优惠码");
        }

        // Check if already used (simplified: mark as used in the map)
        if (usedCoupons.contains(code)) {
            return Map.of("success", false, "error", "该优惠码已使用，不可重复使用");
        }

        usedCoupons.add(code);
        double newTotal = Math.max(0, orderTotal - coupon.discount());
        return Map.of(
                "success", true,
                "code", coupon.code(),
                "description", coupon.description(),
                "discount", coupon.discount(),
                "originalTotal", orderTotal,
                "newTotal", newTotal,
                "message", "优惠码已标记为已使用"
        );
    }

    private final Set<String> usedCoupons = ConcurrentHashMap.newKeySet();

    /** Reset used coupons (called by ResetController). */
    public void resetUsedCoupons() {
        usedCoupons.clear();
    }

    private static double parseDouble(String s) {
        try { return Double.parseDouble(s); }
        catch (NumberFormatException e) { return 0; }
    }
}
