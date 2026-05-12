package burp.analytics.data;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonServiceRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void savesAndLoadsServiceDefinitions() throws Exception {
        ServiceDefinition service = ServiceDefinition.createNew("Example");
        service.setPatterns(List.of("^analytics\\.example\\.com$"));

        JsonServiceRepository repository = new JsonServiceRepository();
        repository.save(tempDir, service);

        JsonServiceRepository.LoadResult result = repository.loadAllWithReport(tempDir);

        assertTrue(result.warnings().isEmpty());
        assertEquals(1, result.definitions().size());
        assertEquals("Example", result.definitions().get(0).getName());
    }

    @Test
    void reportsMalformedJsonFiles() throws Exception {
        Files.writeString(tempDir.resolve("broken.json"), "{not json");

        JsonServiceRepository.LoadResult result = new JsonServiceRepository().loadAllWithReport(tempDir);

        assertTrue(result.definitions().isEmpty());
        assertFalse(result.warnings().isEmpty());
        assertTrue(result.warnings().get(0).contains("broken.json"));
    }
}
