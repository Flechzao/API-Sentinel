package com.demo.vulnapp.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class WalletService {

    private final JdbcTemplate jdbc;

    public WalletService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public double getBalance(int userId) {
        Double bal = jdbc.queryForObject(
                "SELECT balance FROM wallets WHERE user_id = ?", Double.class, userId);
        return bal != null ? bal : 0.0;
    }

    public void debit(int userId, double amount) {
        jdbc.update("UPDATE wallets SET balance = balance - ? WHERE user_id = ?", amount, userId);
    }

    public void credit(int userId, double amount) {
        jdbc.update("UPDATE wallets SET balance = balance + ? WHERE user_id = ?", amount, userId);
    }

    public boolean debitAtomic(int userId, double amount) {
        int rows = jdbc.update(
                "UPDATE wallets SET balance = balance - ? WHERE user_id = ? AND balance >= ?",
                amount, userId, amount);
        return rows > 0;
    }
}
