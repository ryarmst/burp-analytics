package burp.analytics;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/** Match strings without scheme: {@code host[:port] + path} (query in path when present). */
public final class MatchStrings {

    private MatchStrings() {}

    public static List<String> matchTargetsForPattern(HttpRequest request) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        String full = buildWithoutScheme(request);
        if (full != null && !full.isBlank()) {
            set.add(full);
        }
        String hp = hostPortPrefix(request);
        if (hp != null && !hp.isBlank()) {
            set.add(hp);
        }
        String h = hostOnly(request);
        if (h != null && !h.isBlank()) {
            set.add(h);
        }
        return new ArrayList<>(set);
    }

    public static String hostPortPrefix(HttpRequest request) {
        if (request == null || request.httpService() == null) {
            return "";
        }
        HttpService svc = request.httpService();
        String host = svc.host();
        int port = svc.port();
        boolean defPort = (!svc.secure() && port == 80) || (svc.secure() && port == 443);
        return defPort ? host : host + ":" + port;
    }

    public static String hostOnly(HttpRequest request) {
        if (request == null || request.httpService() == null) {
            return "";
        }
        String h = request.httpService().host();
        return h != null ? h : "";
    }

    public static String fromRequest(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            return buildWithoutScheme(request);
        } catch (Exception e) {
            return "";
        }
    }

    public static String buildWithoutScheme(HttpRequest request) {
        HttpService svc = request.httpService();
        String host = svc.host();
        int port = svc.port();
        boolean defPort = (!svc.secure() && port == 80) || (svc.secure() && port == 443);
        String hp = defPort ? host : host + ":" + port;
        String path = request.path();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        return hp + path;
    }
}
