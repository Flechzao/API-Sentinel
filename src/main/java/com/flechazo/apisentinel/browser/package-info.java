/**
 * Browser automation module for client-side security testing.
 *
 * <p>Provides real browser rendering via Playwright + Chromium to enable:
 * <ul>
 *   <li>DOM XSS detection (client-side data flow analysis)</li>
 *   <li>SPA route discovery (Vue Router / React Router extraction)</li>
 *   <li>JS Bundle analysis (API keys, internal URLs, secrets)</li>
 *   <li>Stored XSS verification (confirm payload execution in browser)</li>
 * </ul>
 *
 * <p>All browser traffic is proxied through Burp (via --proxy-server) so
 * HttpTrafficHandler captures it automatically.
 *
 * @see BrowserService
 * @see BrowserManager
 */
package com.flechazo.apisentinel.browser;
