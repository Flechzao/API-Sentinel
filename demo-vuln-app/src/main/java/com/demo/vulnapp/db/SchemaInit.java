package com.demo.vulnapp.db;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Creates and seeds the H2 in-memory schema used by SqliController. */
@Component
public class SchemaInit implements ApplicationRunner {

    private final JdbcTemplate jdbc;

    public SchemaInit(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void run(ApplicationArguments args) {
        jdbc.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(64), email VARCHAR(128))");
        jdbc.execute("CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(64), price DECIMAL(10,2))");

        jdbc.update("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')");
        jdbc.update("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')");
        jdbc.update("INSERT INTO users VALUES (3, 'admin', 'admin@example.com')");

        jdbc.update("INSERT INTO products VALUES (1, 'Widget', 9.99)");
        jdbc.update("INSERT INTO products VALUES (2, 'Gadget', 19.99)");
        jdbc.update("INSERT INTO products VALUES (3, 'Gizmo', 29.99)");

        // Wallets for race-condition demo (#31-#32)
        jdbc.execute("CREATE TABLE wallets (user_id INT PRIMARY KEY, balance DECIMAL(10,2))");
        jdbc.update("INSERT INTO wallets VALUES (1, 1000.00)");
        jdbc.update("INSERT INTO wallets VALUES (2, 500.00)");
        jdbc.update("INSERT INTO wallets VALUES (3, 200.00)");
    }
}
