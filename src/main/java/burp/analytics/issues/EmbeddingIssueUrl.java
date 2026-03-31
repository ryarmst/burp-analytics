package burp.analytics.issues;

import burp.api.montoya.http.message.requests.HttpRequest;

/** Issue base URL: Origin, else Referer, else request URL. */
public final class EmbeddingIssueUrl {

    private EmbeddingIssueUrl() {}

    public static String issueBaseUrl(HttpRequest request) {
        if (request == null) {
            return "";
        }
        String origin = headerTrimmed(request, "Origin");
        if (origin != null && !"null".equalsIgnoreCase(origin)) {
            return origin;
        }
        String referer = headerTrimmed(request, "Referer");
        if (referer != null) {
            return referer;
        }
        try {
            return request.url();
        } catch (Exception e) {
            return "";
        }
    }

    private static String headerTrimmed(HttpRequest request, String name) {
        if (!request.hasHeader(name)) {
            return null;
        }
        String v = request.headerValue(name);
        if (v == null) {
            return null;
        }
        v = v.trim();
        return v.isEmpty() ? null : v;
    }
}
