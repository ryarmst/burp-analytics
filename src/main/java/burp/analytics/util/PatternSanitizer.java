package burp.analytics.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Strip accidental {@code http(s)://} from pattern lines. */
public final class PatternSanitizer {

    private static final Pattern LEADING_SCHEME = Pattern.compile("(?i)^https?://");

    private PatternSanitizer() {}

    public static String stripSchemePrefix(String line) {
        if (line == null) {
            return "";
        }
        return LEADING_SCHEME.matcher(line.trim()).replaceFirst("");
    }

    public static boolean containsScheme(String line) {
        if (line == null) {
            return false;
        }
        return line.trim().toLowerCase().startsWith("http://") || line.trim().toLowerCase().startsWith("https://");
    }

    public static List<String> normalizePatternLines(List<String> lines) {
        List<String> out = new ArrayList<>();
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String s = stripSchemePrefix(line);
            if (!s.isBlank()) {
                out.add(s);
            }
        }
        return out;
    }
}
