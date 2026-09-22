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

        // Users (10 records)
        jdbc.update("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')");
        jdbc.update("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')");
        jdbc.update("INSERT INTO users VALUES (3, 'admin', 'admin@example.com')");
        jdbc.update("INSERT INTO users VALUES (4, 'charlie', 'charlie@example.com')");
        jdbc.update("INSERT INTO users VALUES (5, 'diana', 'diana@example.com')");
        jdbc.update("INSERT INTO users VALUES (6, 'eve', 'eve@example.com')");
        jdbc.update("INSERT INTO users VALUES (7, 'frank', 'frank@example.com')");
        jdbc.update("INSERT INTO users VALUES (8, 'grace', 'grace@example.com')");
        jdbc.update("INSERT INTO users VALUES (9, 'henry', 'henry@example.com')");
        jdbc.update("INSERT INTO users VALUES (10, 'iris', 'iris@example.com')");

        // Products (15 records)
        jdbc.update("INSERT INTO products VALUES (1, 'Widget', 9.99)");
        jdbc.update("INSERT INTO products VALUES (2, 'Gadget', 19.99)");
        jdbc.update("INSERT INTO products VALUES (3, 'Gizmo', 29.99)");
        jdbc.update("INSERT INTO products VALUES (4, '无线耳机', 199.00)");
        jdbc.update("INSERT INTO products VALUES (5, '蓝牙音箱', 299.00)");
        jdbc.update("INSERT INTO products VALUES (6, '机械键盘', 499.00)");
        jdbc.update("INSERT INTO products VALUES (7, '鼠标垫', 39.90)");
        jdbc.update("INSERT INTO products VALUES (8, 'USB-C 充电线', 19.90)");
        jdbc.update("INSERT INTO products VALUES (9, '手机支架', 29.90)");
        jdbc.update("INSERT INTO products VALUES (10, '笔记本电脑包', 159.00)");
        jdbc.update("INSERT INTO products VALUES (11, '显示器', 1299.00)");
        jdbc.update("INSERT INTO products VALUES (12, '摄像头', 349.00)");
        jdbc.update("INSERT INTO products VALUES (13, '移动硬盘 1TB', 399.00)");
        jdbc.update("INSERT INTO products VALUES (14, '路由器', 259.00)");
        jdbc.update("INSERT INTO products VALUES (15, '充电宝 20000mAh', 129.00)");

        // Wallets (10 records)
        jdbc.execute("CREATE TABLE wallets (user_id INT PRIMARY KEY, balance DECIMAL(10,2))");
        jdbc.update("INSERT INTO wallets VALUES (1, 1000.00)");
        jdbc.update("INSERT INTO wallets VALUES (2, 500.00)");
        jdbc.update("INSERT INTO wallets VALUES (3, 200.00)");
        jdbc.update("INSERT INTO wallets VALUES (4, 3500.00)");
        jdbc.update("INSERT INTO wallets VALUES (5, 1200.50)");
        jdbc.update("INSERT INTO wallets VALUES (6, 800.00)");
        jdbc.update("INSERT INTO wallets VALUES (7, 2200.00)");
        jdbc.update("INSERT INTO wallets VALUES (8, 450.75)");
        jdbc.update("INSERT INTO wallets VALUES (9, 1800.00)");
        jdbc.update("INSERT INTO wallets VALUES (10, 600.00)");
    }
}
