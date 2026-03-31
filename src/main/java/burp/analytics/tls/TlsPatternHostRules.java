package burp.analytics.tls;

import burp.analytics.util.PatternSanitizer;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Derives Burp TLS host regex strings from URL patterns (no scheme). */
public final class TlsPatternHostRules {

    private TlsPatternHostRules() {}

    public static List<String> hostRulesFromPatterns(Iterable<String> patterns) {
        Set<String> out = new LinkedHashSet<>();
        if (patterns == null) {
            return List.of();
        }
        for (String raw : patterns) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String p = PatternSanitizer.stripSchemePrefix(raw.trim());
            String hostRule = hostPart(p);
            if (!hostRule.isBlank()) {
                out.add(hostRule);
            }
        }
        return new ArrayList<>(out);
    }

    static String hostPart(String pattern) {
        if (pattern.isEmpty()) {
            return "";
        }
        String p = stripTrailingOptionalPathGroups(pattern.trim());
        int slash = indexOfPathSlash(p);
        if (slash <= 0) {
            return p;
        }
        return p.substring(0, slash);
    }

    static String stripTrailingOptionalPathGroups(String pattern) {
        String s = pattern;
        while (true) {
            if (s.endsWith("$")) {
                s = s.substring(0, s.length() - 1);
                continue;
            }
            if (s.endsWith("(/.*)?")) {
                s = s.substring(0, s.length() - "(/.*)?".length());
                continue;
            }
            if (s.endsWith("(/.*)")) {
                s = s.substring(0, s.length() - "(/.*)".length());
                continue;
            }
            if (s.endsWith("(/.+)?")) {
                s = s.substring(0, s.length() - "(/.+)?".length());
                continue;
            }
            if (s.endsWith("(/.+)")) {
                s = s.substring(0, s.length() - "(/.+)".length());
                continue;
            }
            break;
        }
        return s;
    }

    private static int indexOfPathSlash(String p) {
        boolean inCharClass = false;
        boolean escape = false;
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '[' && !inCharClass) {
                inCharClass = true;
                continue;
            }
            if (c == ']' && inCharClass) {
                inCharClass = false;
                continue;
            }
            if (c != '/' || inCharClass) {
                continue;
            }
            if (i > 0 && p.charAt(i - 1) == '(') {
                continue;
            }
            int bs = 0;
            for (int j = i - 1; j >= 0 && p.charAt(j) == '\\'; j--) {
                bs++;
            }
            if (bs % 2 == 0) {
                return i;
            }
        }
        return -1;
    }
}
