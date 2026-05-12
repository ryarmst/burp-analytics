package burp.analytics.export;

import burp.analytics.data.ServiceDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FoxyProxyConfigExporterTest {

    @Test
    void convertsHostRegexToFoxyProxyUrlRegex() {
        assertEquals(
                "^https?://analytics\\.example\\.com(/.*)?$",
                FoxyProxyConfigExporter.foxyProxyUrlPatternRegex("^analytics\\.example\\.com$"));
    }

    @Test
    void exportsTlsEnabledServicesAndCatchAllRule() {
        ServiceDefinition service = ServiceDefinition.createNew("Example");
        service.setTlsPassThrough(true);
        service.setPatterns(List.of("^analytics\\.example\\.com$"));

        String json = FoxyProxyConfigExporter.buildExcludesJson(List.of(service));

        assertTrue(json.contains("\"include\": \"exclude\""));
        assertTrue(json.contains("\"title\": \"TLS mirror: Example\""));
        assertTrue(json.contains("\"include\": \"include\""));
        assertTrue(json.contains("\"pattern\": \"*\""));
    }
}
