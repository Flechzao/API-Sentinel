package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.InvoiceService;
import com.demo.vulnapp.service.OrderService;
import com.demo.vulnapp.service.UserStore;
import com.demo.vulnapp.controller.CouponController;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Reset all in-memory and database state back to initial seed values.
 * Used by the benchmark framework between test runs to ensure repeatability.
 * Not a scored endpoint — purely test infrastructure.
 */
@RestController
public class ResetController {

    private final JdbcTemplate jdbc;
    private final OrderService orderService;
    private final UserStore userStore;
    private final InvoiceService invoiceService;
    private final CouponController couponController;

    public ResetController(JdbcTemplate jdbc,
                           OrderService orderService,
                           UserStore userStore,
                           InvoiceService invoiceService,
                           CouponController couponController) {
        this.jdbc = jdbc;
        this.orderService = orderService;
        this.userStore = userStore;
        this.invoiceService = invoiceService;
        this.couponController = couponController;
    }

    @PostMapping("/api/admin/reset")
    public Map<String, Object> reset(
            @CookieValue(value = "SESSION_USER", required = false) String sessionUser) {
        if (sessionUser == null) {
            return Map.of("success", false, "error", "not authenticated");
        }

        // Reset H2 tables
        resetWallets();
        resetProducts();
        resetUsers();

        // Reset in-memory stores
        orderService.reset();
        userStore.reset();
        invoiceService.reset();
        couponController.resetUsedCoupons();

        return Map.of(
                "success", true,
                "message", "All state reset to initial seed values",
                "tables", Map.of("wallets", 10, "products", 15, "users", 10),
                "stores", Map.of("orders", 10, "invoices", 6, "users", 10)
        );
    }

    private void resetWallets() {
        jdbc.execute("DELETE FROM wallets");
        jdbc.update("INSERT INTO wallets VALUES (1, 1000.00)");
        jdbc.update("INSERT INTO wallets VALUES (2, 500.00)");
        jdbc.update("INSERT INTO wallets VALUES (3, 200.00)");
        jdbc.update("INSERT INTO wallets VALUES (4, 3500.00)");
        jdbc.update("INSERT INTO wallets VALUES (5, 1200.50)");
        jdbc.update("INSERT INTO wallets VALUES (6, 800.00)");
        jdbc.update("INSERT INTO wallets VALUES (7, 2200.00)");
        jdbc.update("INSERT INTO wallets VALUES (8, 450.75)");
        jdbc.update("INSERT INTO wallets VALUES (9, 1800.00)");
        jdbc.update("INSERT INTO wallets VALUES (10, 600.00)");
    }

    private void resetProducts() {
        jdbc.execute("DELETE FROM products");
        jdbc.update("INSERT INTO products VALUES (1, 'Widget', 9.99)");
        jdbc.update("INSERT INTO products VALUES (2, 'Gadget', 19.99)");
        jdbc.update("INSERT INTO products VALUES (3, 'Gizmo', 29.99)");
        jdbc.update("INSERT INTO products VALUES (4, '无线耳机', 199.00)");
        jdbc.update("INSERT INTO products VALUES (5, '蓝牙音箱', 299.00)");
        jdbc.update("INSERT INTO products VALUES (6, '机械键盘', 499.00)");
        jdbc.update("INSERT INTO products VALUES (7, '鼠标垫', 39.90)");
        jdbc.update("INSERT INTO products VALUES (8, 'USB-C 充电线', 19.90)");
        jdbc.update("INSERT INTO products VALUES (9, '手机支架', 29.90)");
        jdbc.update("INSERT INTO products VALUES (10, '笔记本电脑包', 159.00)");
        jdbc.update("INSERT INTO products VALUES (11, '显示器', 1299.00)");
        jdbc.update("INSERT INTO products VALUES (12, '摄像头', 349.00)");
        jdbc.update("INSERT INTO products VALUES (13, '移动硬盘 1TB', 399.00)");
        jdbc.update("INSERT INTO products VALUES (14, '路由器', 259.00)");
        jdbc.update("INSERT INTO products VALUES (15, '充电宝 20000mAh', 129.00)");
    }

    private void resetUsers() {
        jdbc.execute("DELETE FROM users");
        jdbc.update("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')");
        jdbc.update("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')");
        jdbc.update("INSERT INTO users VALUES (3, 'admin', 'admin@example.com')");
        jdbc.update("INSERT INTO users VALUES (4, 'charlie', 'charlie@example.com')");
        jdbc.update("INSERT INTO users VALUES (5, 'diana', 'diana@example.com')");
        jdbc.update("INSERT INTO users VALUES (6, 'eve', 'eve@example.com')");
        jdbc.update("INSERT INTO users VALUES (7, 'frank', 'frank@example.com')");
        jdbc.update("INSERT INTO users VALUES (8, 'grace', 'grace@example.com')");
        jdbc.update("INSERT INTO users VALUES (9, 'henry', 'henry@example.com')");
        jdbc.update("INSERT INTO users VALUES (10, 'iris', 'iris@example.com')");
    }
}
