package com.demo.vulnapp.controller;

import freemarker.template.Configuration;
import freemarker.template.Template;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * #23 VULNERABLE: Server-Side Template Injection — user input used as template source.
 * #24 SAFE: user input passed as template data, not as template code.
 */
@RestController
public class SstiController {

    private final Configuration freemarkerCfg;

    public SstiController() {
        this.freemarkerCfg = new Configuration(Configuration.VERSION_2_3_32);
        this.freemarkerCfg.setDefaultEncoding("UTF-8");
    }

    /** #23: VULNERABLE — user input is the template itself, allowing ${7*7} → 49. */
    @GetMapping("/api/render")
    public Map<String, Object> render(@RequestParam String template) {
        try {
            Template tpl = new Template("user-input", new StringReader(template), freemarkerCfg);
            StringWriter out = new StringWriter();
            tpl.process(new HashMap<>(), out);
            return Map.of("result", out.toString());
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    /** #24: SAFE — user input is treated as data, not as template code. */
    @GetMapping("/api/preview")
    public Map<String, Object> renderSafe(@RequestParam String template) {
        try {
            Template tpl = new Template("fixed", new StringReader("Hello, ${name}!"), freemarkerCfg);
            StringWriter out = new StringWriter();
            Map<String, Object> data = new HashMap<>();
            data.put("name", template);
            tpl.process(data, out);
            return Map.of("result", out.toString());
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }
}
