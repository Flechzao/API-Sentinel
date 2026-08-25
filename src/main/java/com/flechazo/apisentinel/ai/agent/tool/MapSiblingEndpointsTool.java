package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.SiblingRouteResolver;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.codeindex.parser.RouteEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Locates the current endpoint's backend route in the code index and lists
 * its "sibling endpoints" — other routes in the SAME controller class
 * (same_controller: an authz flaw found here almost certainly repeats there)
 * and routes sharing the same resource-prefix parent (same_prefix: e.g.
 * /api/users/{id} and /api/users/me). Write methods are flagged priority=high
 * because the IDOR read→write escalation requires testing them.
 * <p>
 * Free, pure local index lookup — no HTTP requests. Distilled from the
 * Cluster Hunt Protocol's "MAP SIBLINGS" step (see payloads/chain-hunting.md,
 * docs/THIRD-PARTY.md).
 */
public class MapSiblingEndpointsTool implements AgentTool {

    /** Cap so a huge repo can't blow up the tool-result token budget. */
    private static final int MAX_SIBLINGS = 30;

    private final ToolContext ctx;

    public MapSiblingEndpointsTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "map_sibling_endpoints"; }

    @Override
    public String description() {
        return "从已索引的代码仓库定位当前接口的后端路由，并列出它的兄弟端点："
             + "同一 Controller 类中的其它路由方法（same_controller——发现的鉴权/校验缺陷"
             + "大概率在这些方法中同样存在）和相同资源前缀的其它路径（same_prefix）。"
             + "写方法（POST/PUT/PATCH/DELETE）标记 priority=high：确认读越权后必须测写变体"
             + "才能完成定级。免费，纯本地索引查询，不发请求。需先配置并索引代码仓库；"
             + "当前接口不在索引中时会失败，可改用 grep_repo 搜索路径片段手动定位。";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        CodeIndexService svc = ctx.codeIndexService();
        if (svc == null) {
            return "{\"success\": false, \"error\": \"未配置代码仓库索引，无法定位兄弟端点。\"}";
        }

        String path = ctx.entry().getApiPath();
        List<RouteEntry> self = SiblingRouteResolver.findSelfRoutes(svc, path);
        if (self.isEmpty()) {
            return "{\"success\": false, \"error\": \"当前接口 " + path
                    + " 未在代码索引中找到对应路由（仓库可能未覆盖该服务）。"
                    + "可改用 grep_repo 搜索路径片段手动定位后 read_file 查看。\"}";
        }

        RouteEntry selfRoute = SiblingRouteResolver.selectSelfRoute(self, ctx.entry().getHttpMethod(), path);

        // Route-relationship logic lives in SiblingRouteResolver (shared with
        // AgentController's cascade); this tool only renders its JSON view.
        List<JsonObject> sameController = new ArrayList<>();
        List<JsonObject> samePrefix = new ArrayList<>();
        for (SiblingRouteResolver.Sibling s : SiblingRouteResolver.resolveSiblings(svc, selfRoute, MAX_SIBLINGS)) {
            JsonObject json = siblingJson(s.route(), s.relation());
            if ("same_controller".equals(s.relation())) sameController.add(json);
            else samePrefix.add(json);
        }

        JsonObject out = new JsonObject();
        out.addProperty("success", true);
        JsonObject selfJson = new JsonObject();
        selfJson.addProperty("http_method", selfRoute.httpMethod());
        selfJson.addProperty("route_pattern", selfRoute.routePattern());
        selfJson.addProperty("source", selfRoute.displayLocation());
        if (selfRoute.className() != null) selfJson.addProperty("class_name", selfRoute.className());
        selfJson.addProperty("method_name", selfRoute.methodName());
        out.add("self_route", selfJson);

        JsonArray arr = new JsonArray();
        sameController.forEach(arr::add);
        samePrefix.forEach(arr::add);
        out.add("siblings", arr);
        out.addProperty("count", arr.size());
        out.addProperty("note", "same_controller=同一 Controller 类的其它路由（优先测，鉴权缺陷大概率复现）；"
                + "same_prefix=同资源前缀路径；priority=high 的写方法是读越权升级为数据篡改的必测项。"
                + "把已确认的攻击模式逐个实测到这些端点上（send_request），全部无差异也是有效结论。");
        return out.toString();
    }

    private static JsonObject siblingJson(RouteEntry r, String relation) {
        JsonObject o = new JsonObject();
        o.addProperty("http_method", r.httpMethod());
        o.addProperty("route_pattern", r.routePattern());
        o.addProperty("source", r.displayLocation());
        if (r.className() != null) o.addProperty("class_name", r.className());
        o.addProperty("method_name", r.methodName());
        o.addProperty("relation", relation);
        o.addProperty("priority",
                SiblingRouteResolver.isWriteMethod(r.httpMethod()) ? "high" : "normal");
        return o;
    }
}
