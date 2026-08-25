package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.codeindex.parser.RouteEntry;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Shared route-relationship resolver behind both the map_sibling_endpoints
 * tool (in-loop, LLM-driven cluster hunting) and the AgentController's
 * Controller-level cascade (P2 of the cluster-hunting upgrade; see
 * payloads/chain-hunting.md, docs/THIRD-PARTY.md). Single source of truth
 * for: locating an endpoint's own indexed route, enumerating its siblings
 * (same_controller first, then same_prefix, write methods first within each
 * group), and concretizing a sibling pattern with the source endpoint's
 * actual dynamic-segment values (PUT /api/users/{id} + GET /api/users/1001
 * → PUT /api/users/1001) so a cascaded analysis starts from a requestable
 * path instead of a template.
 *
 * <p>All lookups are free, pure local index reads — no HTTP requests.
 */
public final class SiblingRouteResolver {

    private SiblingRouteResolver() {}

    private static final Set<String> WRITE_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    /** A sibling route plus how it relates to the source endpoint. */
    public record Sibling(RouteEntry route, String relation) {}

    /**
     * A ready-to-queue cascade target: the sibling's HTTP method, its indexed
     * pattern, the pattern with the source's dynamic values substituted
     * (falls back to the pattern itself when segments don't align), and its
     * relation/write flags for prioritization and display.
     */
    public record CascadeTarget(
        String httpMethod,
        String routePattern,
        String concretePath,
        String relation,
        boolean write
    ) {}

    public static boolean isWriteMethod(String method) {
        return method != null && WRITE_METHODS.contains(method.toUpperCase());
    }

    /** Locates the entry's own route candidates. Combines CodeIndexService's
     *  exact/fuzzy lookup with a stricter segment-wise match on top: the
     *  service's fuzzy scorer excludes ":param" and common segments from its
     *  shared-segment count, so /api/users/1001 fails to score against
     *  /api/users/{id} (only the contains-branch salvages a shorter key like
     *  /api/users). The segment-wise pass requires literal segments to be
     *  equal and only accepts DYNAMIC-LOOKING entry segments (digits/UUID/hex)
     *  where the pattern has a :param slot — so /api/users/me never claims
     *  /api/users/{id}'s slot. */
    public static List<RouteEntry> findSelfRoutes(CodeIndexService svc, String apiPath) {
        List<RouteEntry> combined = new ArrayList<>(svc.findByPath(apiPath));
        String normalized = RouteEntry.normalize(apiPath);
        for (List<RouteEntry> routes : svc.getAllRoutes().values()) {
            for (RouteEntry r : routes) {
                if (segmentsMatch(normalized, r.normalizedPattern())) {
                    combined.add(r);
                }
            }
        }
        // Dedup while preserving order (RouteEntry is a record).
        return new ArrayList<>(new LinkedHashSet<>(combined));
    }

    /** findByPath is method-agnostic and fuzzy-match order is not guaranteed
     *  (e.g. GET /api/users/1001 can return the PUT /api/users/{id} route
     *  first) — prefer the candidate whose HTTP method AND segment count match
     *  the entry (segment count distinguishes /api/users/{id} from
     *  /api/users/{id}/audit when both surface in a fuzzy result). */
    public static RouteEntry selectSelfRoute(List<RouteEntry> candidates, String entryMethod, String apiPath) {
        int segments = countSegments(RouteEntry.normalize(apiPath));
        RouteEntry methodOnly = null;
        for (RouteEntry r : candidates) {
            boolean methodOk = entryMethod != null && entryMethod.equalsIgnoreCase(r.httpMethod());
            if (methodOk && countSegments(r.normalizedPattern()) == segments) {
                return r;
            }
            if (methodOk && methodOnly == null) {
                methodOnly = r;
            }
        }
        return methodOnly != null ? methodOnly : candidates.get(0);
    }

    /**
     * Enumerates the source route's siblings, deduped and ordered for
     * attack-priority: same_controller before same_prefix (an authz flaw
     * found in one handler method almost certainly repeats in its
     * controller-mates), write methods first within each group (the IDOR
     * read→write escalation targets).
     *
     * <p>Collects ALL matching routes first and only truncates to {@code max}
     * AFTER the priority sort — truncating during collection (the naive
     * loop-break) would fill the window with whatever the route map's
     * iteration order yields, which is exactly wrong once max is small
     * (cascade callers pass ~10). A repo's route count bounds collection
     * naturally, so the full pass is cheap.
     */
    public static List<Sibling> resolveSiblings(CodeIndexService svc, RouteEntry selfRoute, int max) {
        String selfParent = parentPath(selfRoute.normalizedPattern());
        List<Sibling> sameController = new ArrayList<>();
        List<Sibling> samePrefix = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (List<RouteEntry> routes : svc.getAllRoutes().values()) {
            for (RouteEntry r : routes) {
                if (isSameRoute(r, selfRoute)) continue;
                String key = r.httpMethod() + " " + r.routePattern() + " "
                        + r.sourceFile() + ":" + r.startLine();
                if (!seen.add(key)) continue;

                if (sameControllerClass(r, selfRoute)) {
                    sameController.add(new Sibling(r, "same_controller"));
                } else if (selfParent != null && selfParent.equals(parentPath(r.normalizedPattern()))) {
                    samePrefix.add(new Sibling(r, "same_prefix"));
                }
            }
        }
        sortSiblings(sameController);
        sortSiblings(samePrefix);
        List<Sibling> all = new ArrayList<>(sameController.size() + samePrefix.size());
        all.addAll(sameController);
        all.addAll(samePrefix);
        return all.size() > max ? new ArrayList<>(all.subList(0, max)) : all;
    }

    /**
     * Controller-level cascade entry point: resolves the source endpoint's
     * own route, then returns its siblings as ready-to-queue targets with
     * concrete requestable paths. Empty when the endpoint isn't indexed (no
     * code repo / different service — cascade simply doesn't fire, which is
     * the correct silent degradation).
     */
    public static List<CascadeTarget> resolveCascadeTargets(CodeIndexService svc,
                                                             String httpMethod,
                                                             String apiPath,
                                                             int max) {
        List<RouteEntry> self = findSelfRoutes(svc, apiPath);
        if (self.isEmpty()) return List.of();
        RouteEntry selfRoute = selectSelfRoute(self, httpMethod, apiPath);

        List<CascadeTarget> targets = new ArrayList<>();
        for (Sibling s : resolveSiblings(svc, selfRoute, max)) {
            RouteEntry r = s.route();
            targets.add(new CascadeTarget(
                    r.httpMethod(),
                    r.routePattern(),
                    concretePath(apiPath, r.routePattern()),
                    s.relation(),
                    isWriteMethod(r.httpMethod())));
        }
        return targets;
    }

    /**
     * Substitutes the source path's actual values into a sibling pattern's
     * {@code :param}/{id} slots: /api/users/{id} + /api/users/1001 →
     * /api/users/1001. Segment counts must match; literal pattern segments
     * belong to the TARGET endpoint and are kept as-is (source
     * /api/users/1001/audit → sibling /api/users/{id}/orders yields
     * /api/users/1001/orders — only the :param slot takes the source's
     * value); a :param slot only accepts a dynamic-looking source segment,
     * so GET /api/users/me never fabricates PUT /api/users/me for
     * /api/users/{id}. Any mismatch falls back to the raw pattern (the
     * cascaded analysis then treats it as a no-traffic endpoint, which it
     * honestly is).
     */
    public static String concretePath(String sourceApiPath, String routePattern) {
        if (sourceApiPath == null || routePattern == null) return routePattern;
        String[] src = RouteEntry.normalize(sourceApiPath).split("/");
        String[] pat = RouteEntry.normalize(routePattern).split("/");
        if (src.length != pat.length) return routePattern;

        // normalize() drops the leading slash — rebuild it so the output
        // matches the apiPath format callers (dedup keys, URLs) expect.
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < pat.length; i++) {
            String seg = pat[i];
            if (seg.isEmpty()) continue;
            out.append('/');
            if (seg.equals(":param")) {
                if (!looksDynamic(src[i])) return routePattern;
                out.append(src[i]);
            } else {
                out.append(seg);
            }
        }
        return out.length() == 0 ? routePattern : out.toString();
    }

    /** Same segment count; literal segments must be equal; a :param slot only
     *  accepts a dynamic-looking value. */
    static boolean segmentsMatch(String normalizedPath, String normalizedPattern) {
        String[] pathSegs = normalizedPath.split("/");
        String[] patternSegs = normalizedPattern.split("/");
        if (pathSegs.length != patternSegs.length) return false;
        for (int i = 0; i < pathSegs.length; i++) {
            String ps = pathSegs[i];
            String pat = patternSegs[i];
            if (pat.equals(":param")) {
                if (!looksDynamic(ps)) return false;
            } else if (!ps.equals(pat)) {
                return false;
            }
        }
        return true;
    }

    /** Pure digits / UUID / long hex — same dynamic-segment classes the
     *  traffic normalizer recognizes. A literal like "me" or "audit" is NOT
     *  dynamic and must match a literal pattern segment. */
    static boolean looksDynamic(String segment) {
        if (segment == null || segment.isEmpty()) return false;
        return segment.matches("\\d+")
                || segment.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                || segment.matches("[0-9a-f]{16,}");
    }

    static int countSegments(String normalizedPattern) {
        if (normalizedPattern == null || normalizedPattern.equals("/")) return 0;
        return (int) java.util.Arrays.stream(normalizedPattern.split("/"))
                .filter(s -> !s.isEmpty()).count();
    }

    /** Same method + same normalized pattern = the route we started from. */
    static boolean isSameRoute(RouteEntry a, RouteEntry b) {
        return Objects.equals(a.httpMethod(), b.httpMethod())
                && Objects.equals(a.normalizedPattern(), b.normalizedPattern());
    }

    /** Same controller requires a non-null class name AND the same source
     *  file — Python/Node routes with null className never match here, and
     *  identically-named classes in different files don't false-positive. */
    static boolean sameControllerClass(RouteEntry a, RouteEntry b) {
        return a.className() != null && b.className() != null
                && a.className().equals(b.className())
                && a.sourceFile().equals(b.sourceFile());
    }

    /** /api/users/{id} → /api/users; /api/users → /api; "/" → null. */
    static String parentPath(String normalizedPattern) {
        if (normalizedPattern == null) return null;
        int idx = normalizedPattern.lastIndexOf('/');
        if (idx <= 0) return null;
        return normalizedPattern.substring(0, idx);
    }

    /** Write methods first within each relation group — they're the IDOR
     *  read→write escalation targets. */
    private static void sortSiblings(List<Sibling> siblings) {
        siblings.sort((a, b) -> Boolean.compare(
                !isWriteMethod(a.route().httpMethod()),
                !isWriteMethod(b.route().httpMethod())));
    }
}
