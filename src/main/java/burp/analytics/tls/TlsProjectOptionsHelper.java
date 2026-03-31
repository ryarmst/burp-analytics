package burp.analytics.tls;

import burp.analytics.data.ServiceDefinition;
import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Merge Burp TLS pass-through rules from service patterns; remove only analytics-managed hosts no longer required. */
public final class TlsProjectOptionsHelper {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private TlsProjectOptionsHelper() {}

    public static boolean hasTlsRules(List<ServiceDefinition> definitions) {
        if (definitions == null) {
            return false;
        }
        for (ServiceDefinition s : definitions) {
            if (s != null && s.isTlsPassThrough()) {
                List<String> rules = TlsPatternHostRules.hostRulesFromPatterns(s.getPatterns());
                if (!rules.isEmpty()) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void mergeTlsRulesIntoBurp(MontoyaApi api, List<ServiceDefinition> definitions) {
        if (definitions == null) {
            return;
        }
        Set<String> managedHosts = managedHostsFromAllDefinitions(definitions);
        Set<String> requiredHosts = requiredHostsFromTlsEnabled(definitions);

        String exported;
        try {
            exported = api.burpSuite().exportProjectOptionsAsJson();
        } catch (Exception e) {
            api.logging().logToError("Analytics: export project options failed: " + e.getMessage());
            return;
        }

        JsonObject root;
        try {
            root = JsonParser.parseString(exported).getAsJsonObject();
        } catch (Exception e) {
            api.logging().logToError("Analytics: parse project options failed: " + e.getMessage());
            return;
        }

        JsonObject proxy = root.getAsJsonObject("proxy");
        if (proxy == null) {
            proxy = new JsonObject();
            root.add("proxy", proxy);
        }
        JsonObject sslPass = proxy.getAsJsonObject("ssl_pass_through");
        if (sslPass == null) {
            sslPass = new JsonObject();
            proxy.add("ssl_pass_through", sslPass);
        }
        JsonArray existing = sslPass.getAsJsonArray("rules");
        if (existing == null) {
            existing = new JsonArray();
            sslPass.add("rules", existing);
        }

        JsonArray synced = new JsonArray();
        Set<String> hostsPresent = new HashSet<>();
        int removed = 0;
        for (JsonElement el : existing) {
            if (!el.isJsonObject()) {
                synced.add(JsonParser.parseString(el.toString()));
                continue;
            }
            JsonObject r = el.getAsJsonObject();
            if (!r.has("host")) {
                synced.add(JsonParser.parseString(r.toString()).getAsJsonObject());
                continue;
            }
            String host = r.get("host").getAsString();
            if (managedHosts.contains(host) && !requiredHosts.contains(host)) {
                removed++;
                continue;
            }
            synced.add(JsonParser.parseString(r.toString()).getAsJsonObject());
            hostsPresent.add(host);
        }
        for (String host : requiredHosts) {
            if (host.isBlank() || hostsPresent.contains(host)) {
                continue;
            }
            JsonObject rule = new JsonObject();
            rule.addProperty("enabled", true);
            rule.addProperty("host", host);
            rule.addProperty("protocol", "any");
            synced.add(rule);
            hostsPresent.add(host);
        }
        sslPass.add("rules", synced);

        try {
            api.burpSuite().importProjectOptionsFromJson(GSON.toJson(root));
            api.logging()
                    .logToOutput(
                            "Analytics: synced TLS pass-through rules (removed "
                                    + removed
                                    + ", required "
                                    + requiredHosts.size()
                                    + " host pattern(s)).");
        } catch (Exception e) {
            api.logging().logToError("Analytics: import merged project options failed: " + e.getMessage());
        }
    }

    private static Set<String> managedHostsFromAllDefinitions(List<ServiceDefinition> definitions) {
        Set<String> out = new LinkedHashSet<>();
        for (ServiceDefinition s : definitions) {
            if (s == null) {
                continue;
            }
            for (String h : TlsPatternHostRules.hostRulesFromPatterns(s.getPatterns())) {
                if (!h.isBlank()) {
                    out.add(h);
                }
            }
        }
        return out;
    }

    private static Set<String> requiredHostsFromTlsEnabled(List<ServiceDefinition> definitions) {
        Set<String> out = new LinkedHashSet<>();
        for (ServiceDefinition s : definitions) {
            if (s == null || !s.isTlsPassThrough()) {
                continue;
            }
            for (String h : TlsPatternHostRules.hostRulesFromPatterns(s.getPatterns())) {
                if (!h.isBlank()) {
                    out.add(h);
                }
            }
        }
        return out;
    }
}
