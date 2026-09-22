package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deliberately vulnerable: getOrder() never checks whether the requesting
 * user actually owns the order (#4 IDOR in GROUND_TRUTH.md — the check is
 * simply absent here, one hop below the controller). Returns null for
 * unknown ids, which OrdersController does not guard against either
 * (#3 NPE / stack-trace leak).
 */
@Component
public class OrderService {

    public record Order(String id, int ownerUserId, String item, double total) {}

    private final Map<String, Order> orders = new LinkedHashMap<>();

    public OrderService() {
        reset();
    }

    /** Restore initial seed data. */
    public void reset() {
        orders.clear();
        orders.put("1001", new Order("1001", 1, "Widget x2", 19.98));
        orders.put("1002", new Order("1002", 2, "Gadget x1", 19.99));
        orders.put("1003", new Order("1003", 2, "Gizmo x3", 89.97));
        orders.put("1004", new Order("1004", 1, "无线耳机 x1", 199.00));
        orders.put("1005", new Order("1005", 3, "机械键盘 x2", 998.00));
        orders.put("1006", new Order("1006", 4, "蓝牙音箱 x1", 299.00));
        orders.put("1007", new Order("1007", 5, "笔记本电脑包 x1", 159.00));
        orders.put("1008", new Order("1008", 1, "USB-C 充电线 x3", 59.70));
        orders.put("1009", new Order("1009", 6, "显示器 x1", 1299.00));
        orders.put("1010", new Order("1010", 7, "充电宝 x2", 258.00));
    }

    /** No ownership check against the caller — any authenticated session can
     *  read any other user's order by guessing/incrementing the id. */
    public Order getOrder(String id) {
        return orders.get(id);
    }

    /** Return all orders (used by utility endpoints and reset). */
    public List<Order> getAllOrders() {
        return new ArrayList<>(orders.values());
    }
}
