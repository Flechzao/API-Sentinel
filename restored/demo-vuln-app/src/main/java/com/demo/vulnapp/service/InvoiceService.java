package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Safe counterpart to OrderService (#5 in GROUND_TRUTH.md) — getInvoice()
 * enforces that the resource's owner matches the requesting principal before
 * returning it.
 */
@Component
public class InvoiceService {

    public record Invoice(String id, int ownerUserId, double amount) {}

    public static final class AccessDeniedException extends RuntimeException {
        public AccessDeniedException(String message) { super(message); }
    }

    private final Map<String, Invoice> invoices = new LinkedHashMap<>();

    public InvoiceService() {
        invoices.put("2001", new Invoice("2001", 1, 49.99));
        invoices.put("2002", new Invoice("2002", 2, 99.99));
    }

    public Invoice getInvoice(String id, int requestingUserId) {
        Invoice invoice = invoices.get(id);
        if (invoice == null) return null;
        if (invoice.ownerUserId() != requestingUserId) {
            throw new AccessDeniedException("invoice " + id + " does not belong to user " + requestingUserId);
        }
        return invoice;
    }
}
