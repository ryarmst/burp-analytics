package burp.analytics.util;

import burp.analytics.MatchStrings;
import burp.api.montoya.http.message.requests.HttpRequest;

/** Suggested pattern from a request: {@code ^host[:port]$} (matches via host targets in {@link burp.analytics.MatchStrings}). */
public final class RegexSuggest {

    private RegexSuggest() {}

    public static String literalMatchForRequest(HttpRequest request) {
        if (request == null) {
            return ".*";
        }
        String hp = MatchStrings.hostPortPrefix(request);
        if (hp.isEmpty()) {
            return ".*";
        }
        return "^" + RegexEscape.escape(hp) + "$";
    }
}

