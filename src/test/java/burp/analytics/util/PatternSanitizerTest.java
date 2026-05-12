package burp.analytics.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PatternSanitizerTest {

    @Test
    void stripsLeadingHttpScheme() {
        assertEquals("analytics.example.com/path", PatternSanitizer.stripSchemePrefix("https://analytics.example.com/path"));
    }

    @Test
    void detectsLeadingScheme() {
        assertTrue(PatternSanitizer.containsScheme("HTTP://analytics.example.com"));
    }
}
