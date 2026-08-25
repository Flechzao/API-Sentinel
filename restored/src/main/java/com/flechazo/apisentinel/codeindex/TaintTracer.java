package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regex-heuristic, NOT AST-based, backward taint tracer: starting from a
 * dangerous-sink line and the tainted variable name at that line, walks
 * variable assignments backward within the enclosing function; when the
 * variable turns out to be a function parameter, jumps to a caller (found
 * via the same grep-based call-site lookup FindCallersTool uses) and keeps
 * tracing there, up to a hop limit. Every result carries the caveat that
 * this is best-effort — string concatenation, field access, aliasing through
 * containers, and multi-line signatures beyond what this class explicitly
 * handles will all show up as an early DEAD_END that the model must verify
 * by hand (read_file/grep_repo), not treat as a proof.
 */
public final class TaintTracer {

    public enum StepKind { ASSIGNMENT, PARAMETER, SOURCE_MATCH, DEAD_END, HOP_LIMIT }

    public record TraceStep(Path file, int line, String snippet, String variable, StepKind kind) {}

    public record TraceResult(List<TraceStep> chain, String terminationReason,
                               List<String> otherCallSitesNotTraced) {}

    private static final int DEFAULT_MAX_STEPS = 20;
    private static final int DEFAULT_MAX_HOPS = 3;
    private static final int MAX_DECL_CANDIDATES = 5;
    private static final int MAX_SIGNATURE_EXTRA_LINES = 10;

    private TaintTracer() {}

    public static TraceResult trace(List<CodeRepo> repos, Path sinkFile, int sinkLine, String variableName) {
        return trace(repos, sinkFile, sinkLine, variableName, DEFAULT_MAX_STEPS, DEFAULT_MAX_HOPS);
    }

    public static TraceResult trace(List<CodeRepo> repos, Path sinkFile, int sinkLine, String variableName,
                                     int maxSteps, int maxHops) {
        List<TraceStep> chain = new ArrayList<>();
        List<String> otherCallSites = new ArrayList<>();

        Path file = sinkFile;
        int line = sinkLine; // 1-indexed
        String variable = variableName;
        int steps = 0;
        int hops = 0;

        while (true) {
            if (steps >= maxSteps) return new TraceResult(chain, "达到最大追踪步数(" + maxSteps + ")", otherCallSites);
            if (hops > maxHops) return new TraceResult(chain, "达到最大跨文件跳数(" + maxHops + ")", otherCallSites);

            List<String> lines;
            try {
                lines = Files.readAllLines(file);
            } catch (IOException e) {
                return new TraceResult(chain, "无法读取文件: " + file, otherCallSites);
            }

            FunctionBounds fn = locateEnclosingFunction(lines, file, line - 1);
            if (fn == null) {
                return new TraceResult(chain, "无法定位 " + file + ":" + line + " 所在函数边界", otherCallSites);
            }

            steps++;
            AssignmentHit hit = findNearestAssignment(lines, fn.start, line - 1, variable);
            if (hit != null) {
                String snippet = (hit.lineIdx + 1) + ": " + lines.get(hit.lineIdx).trim();
                if (TaintSourceMap.matchesSource(hit.rhs)) {
                    chain.add(new TraceStep(file, hit.lineIdx + 1, snippet, variable, StepKind.SOURCE_MATCH));
                    return new TraceResult(chain, "找到污染源", otherCallSites);
                }
                chain.add(new TraceStep(file, hit.lineIdx + 1, snippet, variable, StepKind.ASSIGNMENT));
                if (isBareIdentifier(hit.rhs)) {
                    variable = hit.rhs.trim();
                    line = hit.lineIdx + 1;
                    continue;
                }
                return new TraceResult(chain, "赋值来源是复杂表达式（字符串拼接/方法调用/字段访问等），"
                        + "本工具无法继续自动追踪，请人工核查: " + hit.rhs, otherCallSites);
            }

            ParamInfo param = findParameter(lines, fn, variable);
            if (param == null) {
                return new TraceResult(chain, "变量既非函数内可识别的赋值也非函数参数"
                        + "（可能是类字段/解构参数/未覆盖的绑定方式）", otherCallSites);
            }
            String paramSnippet = (fn.declLine() + 1) + ": " + lines.get(fn.declLine()).trim();
            if (TaintSourceMap.matchesSource(param.rawText())) {
                chain.add(new TraceStep(file, fn.declLine() + 1, paramSnippet, variable, StepKind.SOURCE_MATCH));
                return new TraceResult(chain, "找到污染源（函数参数本身即请求绑定）", otherCallSites);
            }
            chain.add(new TraceStep(file, fn.declLine() + 1, paramSnippet, variable, StepKind.PARAMETER));

            if (fn.name() == null) {
                return new TraceResult(chain, "无法提取函数名以查找调用处", otherCallSites);
            }

            List<RepoGrepper.GrepMatch> callSites = findCallSites(repos, fn.name());
            if (callSites.isEmpty()) {
                return new TraceResult(chain, "未找到 " + fn.name() + " 的调用处（可能是入口方法/反射调用/接口方法）", otherCallSites);
            }

            RepoGrepper.GrepMatch firstCall = callSites.get(0);
            for (int i = 1; i < callSites.size(); i++) {
                otherCallSites.add(callSites.get(i).file() + ":" + callSites.get(i).line());
            }

            steps++;
            String argExpr = extractArgumentAtIndex(firstCall.file(), firstCall.line(), fn.name(), param.index());
            if (argExpr == null) {
                return new TraceResult(chain, "无法从调用处 " + firstCall.file() + ":" + firstCall.line()
                        + " 解析出对应位置的实参（参数个数不符/多行调用未覆盖）", otherCallSites);
            }
            if (TaintSourceMap.matchesSource(argExpr)) {
                chain.add(new TraceStep(firstCall.file(), firstCall.line(),
                        firstCall.line() + ": " + argExpr, param.name(), StepKind.SOURCE_MATCH));
                return new TraceResult(chain, "找到污染源（调用处实参直接来自请求）", otherCallSites);
            }
            if (!isBareIdentifier(argExpr)) {
                chain.add(new TraceStep(firstCall.file(), firstCall.line(),
                        firstCall.line() + ": " + argExpr, param.name(), StepKind.DEAD_END));
                return new TraceResult(chain, "调用处实参是复杂表达式，非简单标识符/污染源，"
                        + "本工具无法继续自动追踪，请人工核查: " + argExpr, otherCallSites);
            }

            file = firstCall.file();
            line = firstCall.line();
            variable = argExpr.trim();
            hops++;
        }
    }

    // ===== Function boundary detection =====

    private record FunctionBounds(int declLine, int start, int end, String name, boolean indentMode) {}

    private static final Pattern JAVA_DECL = Pattern.compile(
            "^\\s*(?:@\\w+(?:\\([^)]*\\))?\\s*)*(?:public|private|protected)\\s+(?:static\\s+)?"
          + "(?:final\\s+)?(?:synchronized\\s+)?[\\w<>\\[\\],.\\s]+?\\s+(\\w+)\\s*\\(");
    private static final Pattern PY_DECL = Pattern.compile("^(\\s*)(?:async\\s+)?def\\s+(\\w+)\\s*\\(");
    private static final Pattern JS_NAMED_DECL = Pattern.compile(
            "^\\s*(?:export\\s+)?(?:async\\s+)?function\\s+(\\w+)\\s*\\(");
    private static final Pattern JS_ARROW_DECL = Pattern.compile(
            "^\\s*(?:export\\s+)?const\\s+(\\w+)\\s*=\\s*(?:async\\s+)?\\([^)]*\\)\\s*=>");
    private static final Pattern JS_METHOD_DECL = Pattern.compile(
            "^\\s*(?:async\\s+)?(\\w+)\\s*\\([^)]*\\)\\s*\\{");
    private static final java.util.Set<String> JS_KEYWORDS = java.util.Set.of(
            "if", "for", "while", "switch", "catch", "function", "return");

    private static boolean isPython(Path file) { return file.toString().toLowerCase().endsWith(".py"); }

    private static FunctionBounds locateEnclosingFunction(List<String> lines, Path file, int targetIdx) {
        boolean python = isPython(file);
        int candidatesTried = 0;
        int searchFrom = targetIdx;

        while (searchFrom >= 0 && candidatesTried < MAX_DECL_CANDIDATES) {
            int declIdx = -1;
            String name = null;
            int indent = 0;

            for (int i = searchFrom; i >= 0; i--) {
                String l = lines.get(i);
                if (python) {
                    Matcher m = PY_DECL.matcher(l);
                    if (m.find()) { declIdx = i; indent = m.group(1).length(); name = m.group(2); break; }
                } else {
                    Matcher jm = JAVA_DECL.matcher(l);
                    if (jm.find()) { declIdx = i; name = jm.group(1); break; }
                    Matcher named = JS_NAMED_DECL.matcher(l);
                    if (named.find()) { declIdx = i; name = named.group(1); break; }
                    Matcher arrow = JS_ARROW_DECL.matcher(l);
                    if (arrow.find()) { declIdx = i; name = arrow.group(1); break; }
                    Matcher method = JS_METHOD_DECL.matcher(l);
                    if (method.find() && !JS_KEYWORDS.contains(method.group(1))) {
                        declIdx = i; name = method.group(1); break;
                    }
                }
            }

            if (declIdx < 0) return null;
            candidatesTried++;

            int end = python ? findPythonBlockEnd(lines, declIdx, indent) : findBraceBlockEnd(lines, declIdx);

            if (targetIdx >= declIdx && targetIdx <= end) {
                return new FunctionBounds(declIdx, declIdx, end, name, python);
            }
            // This candidate's body doesn't actually reach the target line —
            // keep searching further back for an outer/earlier declaration.
            searchFrom = declIdx - 1;
        }
        return null;
    }

    private static int findPythonBlockEnd(List<String> lines, int declIdx, int declIndent) {
        for (int i = declIdx + 1; i < lines.size(); i++) {
            String l = lines.get(i);
            if (l.isBlank()) continue;
            int lineIndent = leadingWhitespaceLen(l);
            if (lineIndent <= declIndent) return i - 1;
        }
        return lines.size() - 1;
    }

    private static int findBraceBlockEnd(List<String> lines, int declIdx) {
        int depth = 0;
        boolean opened = false;
        int searchLimit = Math.min(lines.size(), declIdx + 500);
        for (int i = declIdx; i < searchLimit; i++) {
            String l = lines.get(i);
            for (int c = 0; c < l.length(); c++) {
                char ch = l.charAt(c);
                if (ch == '{') { depth++; opened = true; }
                else if (ch == '}') {
                    depth--;
                    if (opened && depth == 0) return i;
                }
            }
        }
        return searchLimit - 1; // heuristic ceiling if braces never balance within the window
    }

    private static int leadingWhitespaceLen(String l) {
        int n = 0;
        while (n < l.length() && (l.charAt(n) == ' ' || l.charAt(n) == '\t')) n++;
        return n;
    }

    // ===== Assignment search =====

    private record AssignmentHit(int lineIdx, String rhs) {}

    private static AssignmentHit findNearestAssignment(List<String> lines, int start, int beforeIdxExclusive, String variable) {
        Pattern assign = Pattern.compile("\\b" + Pattern.quote(variable) + "\\s*(?<![=!<>])=(?!=)\\s*(.+)");
        for (int i = beforeIdxExclusive - 1; i >= start; i--) {
            Matcher m = assign.matcher(lines.get(i));
            if (m.find()) {
                String rhs = stripTrailingCommentAndSemicolon(m.group(1));
                if (!rhs.isBlank()) return new AssignmentHit(i, rhs);
            }
        }
        return null;
    }

    private static String stripTrailingCommentAndSemicolon(String s) {
        String r = s.trim();
        int lineComment = indexOfCommentStart(r);
        if (lineComment >= 0) r = r.substring(0, lineComment).trim();
        if (r.endsWith(";")) r = r.substring(0, r.length() - 1).trim();
        return r;
    }

    /** Finds a trailing "//" or "#" comment start outside of string literals
     *  (best-effort — does not handle every escaping edge case). */
    private static int indexOfCommentStart(String s) {
        boolean inStr = false;
        char strCh = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') { i++; continue; }
                if (c == strCh) inStr = false;
                continue;
            }
            if (c == '"' || c == '\'') { inStr = true; strCh = c; continue; }
            if (c == '#') return i;
            if (c == '/' && i + 1 < s.length() && s.charAt(i + 1) == '/') return i;
        }
        return -1;
    }

    private static final Pattern BARE_IDENTIFIER = Pattern.compile("^[A-Za-z_]\\w*$");

    private static boolean isBareIdentifier(String s) {
        return s != null && BARE_IDENTIFIER.matcher(s.trim()).matches();
    }

    // ===== Parameter extraction =====

    private record ParamInfo(String name, String rawText, int index) {}

    private static ParamInfo findParameter(List<String> lines, FunctionBounds fn, String variable) {
        List<ParamInfo> params = extractParameters(lines, fn);
        for (ParamInfo p : params) {
            if (variable.equals(p.name())) return p;
        }
        return null;
    }

    /** Extracts the parameter list text spanning from declLine forward (up to
     *  MAX_SIGNATURE_EXTRA_LINES for multi-line signatures), splits it into
     *  named parameters. */
    private static List<ParamInfo> extractParameters(List<String> lines, FunctionBounds fn) {
        StringBuilder sig = new StringBuilder();
        int limit = Math.min(lines.size(), fn.declLine() + 1 + MAX_SIGNATURE_EXTRA_LINES);
        for (int i = fn.declLine(); i < limit; i++) {
            sig.append(lines.get(i)).append('\n');
            if (balancedParens(sig.toString())) break;
        }
        String text = sig.toString();
        int open = text.indexOf('(');
        if (open < 0) return List.of();
        int close = matchingParen(text, open);
        if (close < 0) return List.of();
        String paramList = text.substring(open + 1, close);
        List<String> chunks = splitTopLevel(paramList);

        List<ParamInfo> out = new ArrayList<>();
        int idx = 0;
        for (String chunk : chunks) {
            String c = chunk.trim();
            if (c.isEmpty()) continue;
            out.add(new ParamInfo(extractParamName(c), c, idx));
            idx++;
        }
        return out;
    }

    private static String extractParamName(String rawChunk) {
        String c = rawChunk.trim();
        if (c.startsWith("{") || c.startsWith("[")) return null; // destructuring — unsupported
        c = c.replaceFirst("^\\*{1,2}", ""); // Python *args/**kwargs
        int cut = c.length();
        int colon = c.indexOf(':');
        int eq = c.indexOf('=');
        if (colon >= 0) cut = Math.min(cut, colon);
        if (eq >= 0) cut = Math.min(cut, eq);
        String head = c.substring(0, cut).trim();
        // Java-style "Type name" / "@Anno Type name" — take the last token.
        String[] tokens = head.split("\\s+");
        String last = tokens.length > 0 ? tokens[tokens.length - 1] : head;
        last = last.replaceAll("\\[\\]$", "").replaceAll("^\\*+", "");
        return last.isBlank() ? null : last;
    }

    private static boolean balancedParens(String s) {
        int depth = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') { depth--; if (depth == 0) return true; }
        }
        return false;
    }

    private static int matchingParen(String s, int openIdx) {
        int depth = 0;
        for (int i = openIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    /** Depth-aware, string-literal-aware split on top-level commas. Shared by
     *  parameter-list and call-argument-list extraction. */
    private static List<String> splitTopLevel(String s) {
        List<String> out = new ArrayList<>();
        int depth = 0;
        boolean inStr = false;
        char strCh = 0;
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                cur.append(c);
                if (c == '\\' && i + 1 < s.length()) { cur.append(s.charAt(++i)); continue; }
                if (c == strCh) inStr = false;
                continue;
            }
            if (c == '"' || c == '\'') { inStr = true; strCh = c; cur.append(c); continue; }
            if (c == '(' || c == '[' || c == '{' || c == '<') { depth++; cur.append(c); continue; }
            if (c == ')' || c == ']' || c == '}' || c == '>') { depth--; cur.append(c); continue; }
            if (c == ',' && depth == 0) { out.add(cur.toString()); cur.setLength(0); continue; }
            cur.append(c);
        }
        if (!cur.isEmpty()) out.add(cur.toString());
        return out;
    }

    // ===== Call-site lookup (mirrors FindCallersTool's mechanics) =====

    private static final Pattern DEFINITION_HINT = Pattern.compile(
            "(?:public|private|protected|def|function)\\s");

    private static List<RepoGrepper.GrepMatch> findCallSites(List<CodeRepo> repos, String functionName) {
        if (repos == null || repos.isEmpty()) return List.of();
        Pattern callPattern = Pattern.compile("\\b" + Pattern.quote(functionName) + "\\s*\\(");
        List<RepoGrepper.GrepMatch> raw = RepoGrepper.search(repos, callPattern, null, 30, 1);
        List<RepoGrepper.GrepMatch> callers = new ArrayList<>();
        for (RepoGrepper.GrepMatch m : raw) {
            if (m.file().toString().contains("/test/")) continue;
            String contentLine = lineWithoutNumberPrefix(m.context(), m.line());
            if (contentLine != null && DEFINITION_HINT.matcher(contentLine).find()
                    && looksLikeDefinition(contentLine, functionName)) {
                continue; // skip the definition line itself
            }
            callers.add(m);
        }
        return callers;
    }

    private static boolean looksLikeDefinition(String line, String functionName) {
        return (JAVA_DECL.matcher(line).find() || PY_DECL.matcher(line).find()
                || JS_NAMED_DECL.matcher(line).find()) && line.contains(functionName + "(");
    }

    private static String lineWithoutNumberPrefix(String context, int targetLine) {
        if (context == null) return null;
        String prefix = targetLine + ": ";
        for (String l : context.split("\n")) {
            if (l.startsWith(prefix)) return l.substring(prefix.length());
        }
        return null;
    }

    private static String extractArgumentAtIndex(Path file, int callLine, String functionName, int paramIndex) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file);
        } catch (IOException e) {
            return null;
        }
        int idx = callLine - 1;
        if (idx < 0 || idx >= lines.size()) return null;

        StringBuilder text = new StringBuilder();
        int limit = Math.min(lines.size(), idx + 1 + MAX_SIGNATURE_EXTRA_LINES);
        for (int i = idx; i < limit; i++) {
            text.append(lines.get(i)).append('\n');
            if (balancedParensFrom(text.toString(), functionName)) break;
        }
        String full = text.toString();
        int callPos = full.indexOf(functionName + "(");
        if (callPos < 0) return null;
        int open = callPos + functionName.length();
        int close = matchingParen(full, open);
        if (close < 0) return null;
        List<String> args = splitTopLevel(full.substring(open + 1, close));
        if (paramIndex < 0 || paramIndex >= args.size()) return null;
        return args.get(paramIndex).trim();
    }

    private static boolean balancedParensFrom(String s, String functionName) {
        int callPos = s.indexOf(functionName + "(");
        if (callPos < 0) return false;
        return matchingParen(s, callPos + functionName.length()) >= 0;
    }
}
