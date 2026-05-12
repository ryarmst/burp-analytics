package burp.analytics.tls;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TlsPatternHostRulesTest {

    @Test
    void derivesHostRulesFromHostAndPathPatterns() {
        List<String> rules =
                TlsPatternHostRules.hostRulesFromPatterns(
                        List.of("^analytics\\.example\\.com/collect.*$", "^cdn\\.example\\.com$"));

        assertEquals(List.of("^analytics\\.example\\.com", "^cdn\\.example\\.com"), rules);
    }

    @Test
    void stripsOptionalTrailingPathGroups() {
        List<String> rules =
                TlsPatternHostRules.hostRulesFromPatterns(List.of("^tags\\.example\\.com(/.*)?$"));

        assertEquals(List.of("^tags\\.example\\.com"), rules);
    }
}
