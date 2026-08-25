package com.demo.vulnapp.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * #21 VULNERABLE: reflected XSS — user input directly embedded in HTML.
 * #22 SAFE: same feature but HTML-encodes the input.
 */
@RestController
public class XssController {

    /** #21: VULNERABLE — name is reflected raw into HTML. */
    @GetMapping(value = "/api/greet", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam(defaultValue = "Guest") String name) {
        return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
    }

    /** #22: SAFE — HTML-encodes the name before embedding. */
    @GetMapping(value = "/api/greet-safe", produces = MediaType.TEXT_HTML_VALUE)
    public String greetSafe(@RequestParam(defaultValue = "Guest") String name) {
        String escaped = name
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
        return "<html><body><h1>Hello, " + escaped + "!</h1></body></html>";
    }
}
