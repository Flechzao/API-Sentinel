package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.OrderService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

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
}
