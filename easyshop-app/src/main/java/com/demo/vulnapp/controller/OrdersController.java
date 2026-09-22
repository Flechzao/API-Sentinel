package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.OrderService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * #3 / #4 in GROUND_TRUTH.md, both on the same endpoint:
 *  - #3: unknown id -> OrderService returns null -> NPE here -> Spring's
 *    default error handling (stacktrace/message included, see
 *    application.properties) leaks a full stack trace.
 *  - #4: known id belonging to a DIFFERENT user is still returned — no
 *    ownership check anywhere in the call chain (see OrderService).
 */
@RestController
public class OrdersController {

    private final OrderService orderService;

    public OrdersController(OrderService orderService) {
        this.orderService = orderService;
    }

    @GetMapping("/api/orders/{id}")
    public Map<String, Object> getOrder(@PathVariable String id) {
        OrderService.Order order = orderService.getOrder(id);
        return Map.of(
                "id", order.id(),
                "ownerUserId", order.ownerUserId(),
                "item", order.item(),
                "total", order.total());
    }

    /**
     * Deep-trigger endpoint: only reachable through the SPA's order detail page
     * (login → orders → click order → modify quantity → save).
     * No IDOR check — any authenticated user can modify any order's quantity.
     */
    @PutMapping("/api/orders/{id}/quantity")
    public Map<String, Object> updateQuantity(@PathVariable String id,
                                               @RequestBody Map<String, Object> body) {
        OrderService.Order order = orderService.getOrder(id);
        int quantity = body.containsKey("quantity")
                ? ((Number) body.get("quantity")).intValue() : 1;
        return Map.of(
                "id", order.id(),
                "item", order.item(),
                "quantity", quantity,
                "message", "Quantity updated to " + quantity);
    }

    /**
     * Create new order — triggered by multi-step form in SPA.
     * No input validation: price/quantity can be tampered (business logic vuln).
     */
    @PostMapping("/api/orders")
    public Map<String, Object> createOrder(@RequestBody Map<String, Object> body) {
        String item = body.containsKey("item") ? body.get("item").toString() : "unknown";
        String total = body.containsKey("total") ? body.get("total").toString() : "0";
        return Map.of(
                "id", String.valueOf(System.currentTimeMillis() % 100000),
                "item", item,
                "total", total,
                "status", "pending",
                "message", "Order created");
    }
}
