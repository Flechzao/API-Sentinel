package com.flechazo.apisentinel.browser;

import java.util.List;

/**
 * Describes a form field extracted from the page DOM.
 *
 * <p>Used by {@link PageRenderer#extractFormFields} to help the Agent decide
 * which selectors to target and what values to fill in when using
 * {@code browser_interact}.
 *
 * @param tagName     HTML tag: "input", "select", or "textarea"
 * @param type        input type: "text", "password", "email", "select", etc.
 * @param name        the name attribute (used in form submission)
 * @param id          the id attribute (useful for CSS selectors)
 * @param placeholder the placeholder text (hint about expected value)
 * @param required    whether the field is marked as required
 * @param options     for &lt;select&gt; elements: list of option values; empty for others
 */
public record FormFieldInfo(
        String tagName,
        String type,
        String name,
        String id,
        String placeholder,
        boolean required,
        List<String> options
) {}
