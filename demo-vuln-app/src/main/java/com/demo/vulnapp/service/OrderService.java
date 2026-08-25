package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
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
        orders.put("1001", new Order("1001", 1, "Widget x2", 19.98));
        orders.put("1002", new Order("1002", 2, "Gadget x1", 19.99));
        orders.put("1003", new Order("1003", 2, "Gizmo x3", 89.97));
    }

    /** No ownership check against the caller — any authenticated session can
     *  read any other user's order by guessing/incrementing the id. */
    public Order getOrder(String id) {
        return orders.get(id);
    }
}
