package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.WalletService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * #31 VULNERABLE: race condition (TOCTOU) — balance check and debit are not atomic.
 * #32 SAFE: uses atomic UPDATE ... WHERE balance >= ? to prevent double-spend.
 */
@RestController
public class RaceConditionController {

    private final WalletService walletService;

    public RaceConditionController(WalletService walletService) {
        this.walletService = walletService;
    }

    @PostMapping("/api/transfer")
    public Map<String, Object> transfer(
            @CookieValue(value = "SESSION_USER", defaultValue = "1") int userId,
            @RequestParam double amount,
            @RequestParam int toUser) {
        double balance = walletService.getBalance(userId);
        if (balance < amount) {
            return Map.of("success", false, "error", "Insufficient balance",
                    "balance", balance);
        }
        walletService.debit(userId, amount);
        walletService.credit(toUser, amount);
        return Map.of("success", true,
                "transferred", amount,
                "remaining", walletService.getBalance(userId));
    }

    @PostMapping("/api/wallet/transfer")
    public Map<String, Object> transferSafe(
            @CookieValue(value = "SESSION_USER", defaultValue = "1") int userId,
            @RequestParam double amount,
            @RequestParam int toUser) {
        boolean ok = walletService.debitAtomic(userId, amount);
        if (!ok) {
            return Map.of("success", false, "error", "Insufficient balance");
        }
        walletService.credit(toUser, amount);
        return Map.of("success", true,
                "transferred", amount,
                "remaining", walletService.getBalance(userId));
    }
}
