package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.microsoft.playwright.ElementHandle;
import com.microsoft.playwright.Page;

import java.util.*;

/**
 * Simplifies DOM for LLM consumption by extracting only interactive elements.
 *
 * <p>Full DOMs can be 50KB+ which is too large for LLM context. This class
 * extracts a compact, structured list of interactive elements (buttons, links,
 * inputs, etc.) that the LLM can reason about to make navigation decisions.
 *
 * <p>Output example:
 * <pre>
 * [
 *   { "id": 1, "tag": "a", "text": "系统管理", "selector": ".menu-system", "role": "menu" },
 *   { "id": 2, "tag": "button", "text": "新建用户", "selector": "#btn-create", "role": "button" },
 *   { "id": 3, "tag": "input", "placeholder": "搜索...", "selector": "input.search", "type": "text" }
 * ]
 * </pre>
 */
public class DomSimplifier {

    private final LeveledLogger logger;

    /** Maximum number of interactive elements to extract (prevents token overflow). */
    private static final int MAX_ELEMENTS = 80;

    /** Maximum text length per element (truncate long labels). */
    private static final int MAX_TEXT_LENGTH = 60;

    public DomSimplifier(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Extract interactive elements from the page.
     *
     * @param page the Playwright page
     * @return list of interactive element descriptors
     */
    public List<InteractiveElement> extract(Page page) {
        List<InteractiveElement> elements = new ArrayList<>();

        try {
            // JavaScript to extract interactive elements
            String js = """
                (() => {
                    const elements = [];
                    const seen = new Set();
                    
                    // Selectors for interactive elements, ordered by priority
                    const selectorGroups = [
                        // Navigation/menu items
                        { selectors: ['a[href]', '[role=menuitem]', '[role=tab]', 'nav a', '.menu-item', '.nav-item'], priority: 'nav' },
                        // Buttons
                        { selectors: ['button:not([disabled])', '[role=button]', 'input[type=submit]', 'input[type=button]'], priority: 'button' },
                        // Form inputs
                        { selectors: ['input:not([type=hidden]):not([disabled])', 'select:not([disabled])', 'textarea:not([disabled])'], priority: 'input' },
                        // Clickable elements with native handlers or explicit attributes
                        { selectors: ['[onclick]', '[data-action]', '[tabindex]'], priority: 'clickable' },
                        // Framework click handlers — Vue @click / React onClick don't produce
                        // HTML attributes, so we detect by common interactive CSS patterns
                        // and cursor:pointer computed style (scanned separately below)
                        { selectors: [
                            '[class*=trigger]', '[class*=dropdown]', '[class*=menu-btn]',
                            '[class*=tab]', '[class*=toggle]', '[class*=clickable]',
                            '[class*=action]', '[class*=handler]', '[class*=interactive]',
                            '.dropdown-trigger', '.nav-link', '.tab-btn', '.step',
                            '[v-on:click]', '[@click]', '[v-click]'
                        ], priority: 'framework' }
                    ];
                    
                    function isVisible(el) {
                        const rect = el.getBoundingClientRect();
                        if (rect.width === 0 && rect.height === 0) return false;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
                        return true;
                    }
                    
                    function getText(el) {
                        // Try aria-label first
                        let text = el.getAttribute('aria-label') || '';
                        if (!text) {
                            // Try placeholder for inputs
                            text = el.placeholder || '';
                        }
                        if (!text) {
                            // Try textContent for buttons/links
                            text = (el.textContent || '').trim();
                        }
                        if (!text) {
                            // Try title attribute
                            text = el.getAttribute('title') || '';
                        }
                        // Truncate
                        return text.substring(0, %d).replace(/\\s+/g, ' ');
                    }
                    
                    function buildSelector(el) {
                        // Priority: id > data-testid > aria-label > unique class combo
                        if (el.id) return '#' + el.id;
                        if (el.getAttribute('data-testid')) {
                            return '[data-testid="' + el.getAttribute('data-testid') + '"]';
                        }
                        if (el.getAttribute('aria-label')) {
                            return '[aria-label="' + el.getAttribute('aria-label') + '"]';
                        }
                        // Build a selector from tag + meaningful classes
                        const tag = el.tagName.toLowerCase();
                        const classes = Array.from(el.classList)
                            .filter(c => !c.startsWith('el-') && !c.startsWith('ant-') && c.length < 20)
                            .slice(0, 2);
                        if (classes.length > 0) {
                            return tag + '.' + classes.join('.');
                        }
                        // Fallback: nth-child
                        const parent = el.parentElement;
                        if (parent) {
                            const siblings = Array.from(parent.children).filter(c => c.tagName === el.tagName);
                            const idx = siblings.indexOf(el) + 1;
                            if (idx > 0 && siblings.length > 1) {
                                return tag + ':nth-of-type(' + idx + ')';
                            }
                        }
                        return tag;
                    }
                    
                    function getRole(el) {
                        return el.getAttribute('role') || 
                               (el.tagName === 'A' ? 'link' : 
                                el.tagName === 'BUTTON' ? 'button' :
                                el.tagName === 'INPUT' ? 'input' :
                                el.type || '');
                    }
                    
                    for (const group of selectorGroups) {
                        for (const selector of group.selectors) {
                            try {
                                for (const el of document.querySelectorAll(selector)) {
                                    if (elements.length >= %d) break;
                                    if (!isVisible(el)) continue;
                                    
                                    // Deduplicate by selector
                                    const sel = buildSelector(el);
                                    if (seen.has(sel)) continue;
                                    seen.add(sel);
                                    
                                    elements.push({
                                        id: elements.length + 1,
                                        tag: el.tagName.toLowerCase(),
                                        type: el.type || '',
                                        text: getText(el),
                                        placeholder: el.placeholder || '',
                                        href: el.href || '',
                                        selector: sel,
                                        role: getRole(el),
                                        priority: group.priority,
                                        // Include some context classes
                                        classes: Array.from(el.classList)
                                            .filter(c => c.startsWith('menu') || c.startsWith('nav') || 
                                                         c.startsWith('tab') || c.startsWith('btn') ||
                                                         c.startsWith('sidebar') || c.startsWith('header'))
                                            .slice(0, 3)
                                            .join(' ')
                                    });
                                }
                            } catch (e) { /* skip invalid selector */ }
                            if (elements.length >= %d) break;
                        }
                        if (elements.length >= %d) break;
                    }
                    
                    // Post-scan: find elements with cursor:pointer that the CSS
                    // selectors above missed (catches Vue @click / React onClick
                    // handlers that don't produce HTML attributes).
                    if (elements.length < %d) {
                        const cursorEls = document.querySelectorAll('*');
                        for (const el of cursorEls) {
                            if (elements.length >= %d) break;
                            // Skip elements already found
                            const sel = buildSelector(el);
                            if (seen.has(sel)) continue;
                            // Skip non-interactive tags
                            const tag = el.tagName.toLowerCase();
                            if (['script', 'style', 'head', 'meta', 'link', 'br', 'hr', 'img', 'span'].includes(tag) && !el.className) continue;
                            if (!isVisible(el)) continue;
                            // Check cursor:pointer — framework click handlers
                            // almost always set this via CSS or framework defaults
                            const style = window.getComputedStyle(el);
                            if (style.cursor === 'pointer') {
                                seen.add(sel);
                                elements.push({
                                    id: elements.length + 1,
                                    tag: tag,
                                    type: el.type || '',
                                    text: getText(el),
                                    placeholder: el.placeholder || '',
                                    href: el.href || '',
                                    selector: sel,
                                    role: getRole(el),
                                    priority: 'cursor-pointer',
                                    classes: Array.from(el.classList)
                                        .filter(c => c.startsWith('menu') || c.startsWith('nav') || 
                                                     c.startsWith('tab') || c.startsWith('btn') ||
                                                     c.startsWith('dropdown') || c.startsWith('trigger') ||
                                                     c.startsWith('sidebar') || c.startsWith('header'))
                                        .slice(0, 3)
                                        .join(' ')
                                });
                            }
                        }
                    }
                    
                    return elements;
                })()
                """.formatted(MAX_TEXT_LENGTH, MAX_ELEMENTS, MAX_ELEMENTS, MAX_ELEMENTS, MAX_ELEMENTS, MAX_ELEMENTS);

            Object result = page.evaluate(js);

            if (result instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        InteractiveElement el = parseElement(map);
                        if (el != null) {
                            elements.add(el);
                        }
                    }
                }
            }

            logger.debug("[DomSimplifier] 提取了 %d 个可交互元素", elements.size());

        } catch (Exception e) {
            logger.warn("[DomSimplifier] 提取可交互元素失败: %s", e.getMessage());
        }

        return elements;
    }

    /**
     * Format elements for LLM prompt.
     *
     * @param elements the interactive elements
     * @return formatted string for prompt
     */
    public String formatForPrompt(List<InteractiveElement> elements) {
        if (elements.isEmpty()) {
            return "(页面无可见可交互元素)";
        }

        StringBuilder sb = new StringBuilder();
        for (InteractiveElement el : elements) {
            sb.append(el.id()).append(". ");

            // Type indicator
            switch (el.tag()) {
                case "a" -> sb.append("[链接] ");
                case "button" -> sb.append("[按钮] ");
                case "input" -> sb.append("[输入框").append(el.type().isEmpty() ? "" : ":" + el.type()).append("] ");
                case "select" -> sb.append("[下拉框] ");
                case "textarea" -> sb.append("[文本域] ");
                default -> sb.append("[").append(el.tag()).append("] ");
            }

            // Text or placeholder
            if (!el.text().isEmpty()) {
                sb.append("\"").append(el.text()).append("\"");
            } else if (!el.placeholder().isEmpty()) {
                sb.append("(placeholder: ").append(el.placeholder()).append(")");
            } else if (!el.href().isEmpty()) {
                sb.append("(href: ").append(el.href()).append(")");
            }

            // Selector
            sb.append(" → ").append(el.selector());

            // Context classes if any
            if (!el.classes().isEmpty()) {
                sb.append(" [").append(el.classes()).append("]");
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Parse a single element from JavaScript result.
     */
    private InteractiveElement parseElement(Map<?, ?> map) {
        try {
            return new InteractiveElement(
                    toInt(map.get("id")),
                    str(map.get("tag")),
                    str(map.get("type")),
                    str(map.get("text")),
                    str(map.get("placeholder")),
                    str(map.get("href")),
                    str(map.get("selector")),
                    str(map.get("role")),
                    str(map.get("priority")),
                    str(map.get("classes"))
            );
        } catch (Exception e) {
            return null;
        }
    }

    private String str(Object obj) {
        return obj instanceof String s ? s : "";
    }

    private int toInt(Object obj) {
        if (obj instanceof Number n) return n.intValue();
        return 0;
    }

    /**
     * Represents an interactive element on the page.
     *
     * @param id          unique identifier (1-based)
     * @param tag         HTML tag name (button, a, input, etc.)
     * @param type        input type if applicable (text, password, submit, etc.)
     * @param text        visible text content or aria-label
     * @param placeholder placeholder attribute for inputs
     * @param href        href for links
     * @param selector    CSS selector to locate this element
     * @param role        ARIA role or inferred role
     * @param priority    extraction priority (nav, button, input, clickable)
     * @param classes     relevant CSS classes (menu/nav/tab/btn related)
     */
    public record InteractiveElement(
            int id,
            String tag,
            String type,
            String text,
            String placeholder,
            String href,
            String selector,
            String role,
            String priority,
            String classes
    ) {
        /**
         * Check if this element matches a keyword (case-insensitive).
         */
        public boolean matchesKeyword(String keyword) {
            if (keyword == null || keyword.isEmpty()) return false;
            String lower = keyword.toLowerCase();
            return text.toLowerCase().contains(lower)
                    || placeholder.toLowerCase().contains(lower)
                    || classes.toLowerCase().contains(lower)
                    || selector.toLowerCase().contains(lower);
        }
    }
}
