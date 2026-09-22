package com.demo.vulnapp.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** #16 in GROUND_TRUTH.md — VULNERABLE: no Spring Security on the classpath
 *  means no CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy
 *  are ever added to this (or any) response. */
@RestController
public class DashboardController {

    @GetMapping(value = "/web/dashboard", produces = MediaType.TEXT_HTML_VALUE)
    public String dashboard() {
        return "<html><body><h1>Dashboard</h1><p>Welcome to the demo app.</p></body></html>";
    }
}
