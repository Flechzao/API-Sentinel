package com.demo.vulnapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Ground-truth demo app for API Sentinel's Phase 0 benchmark — deliberately
 * vulnerable, see GROUND_TRUTH.md. Not a real product; do not deploy anywhere
 * reachable from the internet.
 */
@SpringBootApplication
public class VulnAppApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnAppApplication.class, args);
    }
}
