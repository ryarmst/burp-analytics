package burp.analytics.util;

/** Metacharacter escapes for regex literals (no {@code \Q...\E}). */
public final class RegexEscape {

    private RegexEscape() {}

    public static String escape(String s) {
        if (s == null || s.isEmpty()) {
            return s == null ? "" : s;
        }
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || ".^$|?*+()[]{}".indexOf(c) >= 0) {
                b.append('\\');
            }
            b.append(c);
        }
        return b.toString();
    }
}
