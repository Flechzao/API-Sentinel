package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.InvoiceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** #5 in GROUND_TRUTH.md — SAFE counterpart to /api/orders/{id}: the
 *  ownership check happens in InvoiceService, one hop below this controller. */
@RestController
public class InvoiceController {

    private final InvoiceService invoiceService;

    public InvoiceController(InvoiceService invoiceService) {
        this.invoiceService = invoiceService;
    }

    @GetMapping("/api/invoices/{id}")
    public ResponseEntity<?> getInvoice(@PathVariable String id,
                                         @CookieValue(value = "SESSION_USER", required = false) String sessionUser) {
        int requestingUserId = parseUserId(sessionUser);
        try {
            InvoiceService.Invoice invoice = invoiceService.getInvoice(id, requestingUserId);
            if (invoice == null) return ResponseEntity.status(404).body(Map.of("error", "not found"));
            return ResponseEntity.ok(invoice);
        } catch (InvoiceService.AccessDeniedException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        }
    }

    private static int parseUserId(String cookie) {
        try {
            return cookie == null ? -1 : Integer.parseInt(cookie);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
