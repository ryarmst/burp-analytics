package burp.analytics.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RegexEscapeTest {

    @Test
    void escapesRegexMetacharacters() {
        assertEquals("a\\.b\\?c\\[d\\]", RegexEscape.escape("a.b?c[d]"));
    }
}
