package burp.analytics.matcher;

import burp.analytics.data.ServiceDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalyticsMatcherTest {

    @Test
    void matchesFirstCompiledServicePattern() {
        ServiceDefinition service = ServiceDefinition.createNew("Example Analytics");
        service.setPatterns(List.of("^analytics\\.example\\.com$", "^cdn\\.example\\.com/collect"));

        AnalyticsMatcher matcher = new AnalyticsMatcher();
        matcher.updateDefinitions(List.of(service));

        MatchResult result = matcher.match("cdn.example.com/collect?id=1").orElseThrow();

        assertEquals(service, result.getService());
        assertEquals("^cdn\\.example\\.com/collect", result.getMatchedPattern());
    }

    @Test
    void reportsInvalidRegexPatterns() {
        ServiceDefinition service = ServiceDefinition.createNew("Broken");
        service.setPatterns(List.of("[unterminated"));

        AnalyticsMatcher matcher = new AnalyticsMatcher();
        List<String> messages = matcher.validateDefinitions(List.of(service));

        assertFalse(messages.isEmpty());
        assertTrue(messages.get(0).contains("Broken"));
        assertTrue(messages.get(0).contains("[unterminated"));
    }
}
