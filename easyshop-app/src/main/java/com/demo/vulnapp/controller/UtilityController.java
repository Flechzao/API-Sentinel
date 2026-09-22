package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.OrderService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility endpoints that make the application more realistic and provide
 * additional surfaces for the browser agent to discover.
 *
 * - /api/health — health check (standard in production apps)
 * - /api/products/list — product listing with search, sort, and pagination
 * - /api/orders/user/{userId} — user's order history
 * - /api/stats — public store statistics
 */
@RestController
public class UtilityController {

    private final JdbcTemplate jdbc;
    private final OrderService orderService;

    public UtilityController(JdbcTemplate jdbc, OrderService orderService) {
        this.jdbc = jdbc;
        this.orderService = orderService;
    }

    /** Health check — standard endpoint in any production application. */
    @GetMapping("/api/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "timestamp", Instant.now().toString(),
                "version", "1.0.0"
        );
    }

    /** Product listing with search, sort, and pagination — very common
     *  in e-commerce apps. The browser agent should discover this via
     *  navigation and use it to enumerate products. */
    @GetMapping("/api/products/list")
    public Map<String, Object> listProducts(
            @RequestParam(defaultValue = "") String search,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortOrder,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int pageSize) {

        // Validate sortBy to prevent SQL injection (whitelist approach)
        Set<String> allowedSort = Set.of("id", "name", "price");
        String safeSort = allowedSort.contains(sortBy) ? sortBy : "id";
        String safeOrder = "desc".equalsIgnoreCase(sortOrder) ? "DESC" : "ASC";

        String sql;
        List<Object> params = new ArrayList<>();
        if (!search.isEmpty()) {
            sql = "SELECT id, name, price FROM products WHERE LOWER(name) LIKE ? ORDER BY " + safeSort + " " + safeOrder;
            params.add("%" + search.toLowerCase() + "%");
        } else {
            sql = "SELECT id, name, price FROM products ORDER BY " + safeSort + " " + safeOrder;
        }

        List<Map<String, Object>> allProducts = jdbc.queryForList(sql, params.toArray());

        // Pagination
        int total = allProducts.size();
        int from = Math.min((page - 1) * pageSize, total);
        int to = Math.min(from + pageSize, total);
        List<Map<String, Object>> pageData = allProducts.subList(from, to);

        return Map.of(
                "products", pageData,
                "total", total,
                "page", page,
                "pageSize", pageSize,
                "totalPages", (int) Math.ceil((double) total / pageSize)
        );
    }

    /** User's order history — the agent should discover this by navigating
     *  to a user profile and finding their orders. */
    @GetMapping("/api/orders/user/{userId}")
    public List<Map<String, Object>> userOrders(@PathVariable int userId) {
        // Return all orders belonging to this user from the in-memory store
        return orderService.getAllOrders().stream()
                .filter(o -> o.ownerUserId() == userId)
                .map(o -> Map.<String, Object>of(
                        "id", o.id(),
                        "item", o.item(),
                        "total", o.total(),
                        "status", "shipped"))
                .collect(Collectors.toList());
    }

    /** Public store statistics — visible on the homepage. */
    @GetMapping("/api/stats")
    public Map<String, Object> storeStats() {
        int productCount = jdbc.queryForObject("SELECT COUNT(*) FROM products", Integer.class);
        return Map.of(
                "totalProducts", productCount,
                "totalOrders", orderService.getAllOrders().size(),
                "storeName", "EasyShop",
                "slogan", "品质生活，轻松购物"
        );
    }
}
