package burp.analytics.export;

import burp.analytics.data.ServiceDefinition;
import burp.analytics.tls.TlsPatternHostRules;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** FoxyProxy JSON: TLS mirror excludes (full URL regex) + trailing {@code include} wildcard. */
public final class FoxyProxyConfigExporter {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private FoxyProxyConfigExporter() {}

    public static Map<String, String> tlsExcludePatternsByService(List<ServiceDefinition> definitions) {
        Map<String, String> patternToSourceService = new LinkedHashMap<>();
        if (definitions == null) {
            return patternToSourceService;
        }
        for (ServiceDefinition s : definitions) {
            if (s == null || !s.isTlsPassThrough()) {
                continue;
            }
            for (String hostRule : TlsPatternHostRules.hostRulesFromPatterns(s.getPatterns())) {
                if (hostRule == null || hostRule.isBlank()) {
                    continue;
                }
                patternToSourceService.putIfAbsent(hostRule, s.getName());
            }
        }
        return patternToSourceService;
    }

    public static int tlsExcludeRuleCount(List<ServiceDefinition> definitions) {
        return tlsExcludePatternsByService(definitions).size();
    }

    public static String foxyProxyUrlPatternRegex(String hostRule) {
        if (hostRule == null || hostRule.isBlank()) {
            return "";
        }
        String h = hostRule.trim();
        if (h.startsWith("^")) {
            h = h.substring(1);
        }
        if (h.endsWith("$")) {
            h = h.substring(0, h.length() - 1);
        }
        h = h.trim();
        if (h.isEmpty()) {
            return "";
        }
        return "^https?://" + h + "(/.*)?$";
    }

    public static String buildExcludesJson(List<ServiceDefinition> definitions) {
        Map<String, String> patternToSourceService = tlsExcludePatternsByService(definitions);
        JsonArray root = new JsonArray();
        for (Map.Entry<String, String> e : patternToSourceService.entrySet()) {
            String pattern = foxyProxyUrlPatternRegex(e.getKey());
            if (pattern.isEmpty()) {
                continue;
            }
            JsonObject row = new JsonObject();
            row.addProperty("include", "exclude");
            row.addProperty("type", "regex");
            row.addProperty("title", "TLS mirror: " + e.getValue());
            row.addProperty("pattern", pattern);
            row.addProperty("active", true);
            root.add(row);
        }
        JsonObject catchAll = new JsonObject();
        catchAll.addProperty("include", "include");
        catchAll.addProperty("type", "wildcard");
        catchAll.addProperty("title", "Everything Else");
        catchAll.addProperty("pattern", "*");
        catchAll.addProperty("active", true);
        root.add(catchAll);
        return GSON.toJson(root);
    }
}
