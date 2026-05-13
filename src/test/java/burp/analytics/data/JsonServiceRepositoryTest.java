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
    void savesMethodologyToSidecarMarkdown() throws Exception {
        ServiceDefinition service = ServiceDefinition.createNew("With Method");
        service.setPatterns(List.of("^analytics\\.example\\.com$"));
        service.setMethodology("# How to test\n\n- Step one");

        JsonServiceRepository repository = new JsonServiceRepository();
        repository.save(tempDir, service);

        Path md = JsonServiceRepository.methodologyPath(tempDir, service.getId());
        assertTrue(Files.isRegularFile(md));
        assertEquals("# How to test\n\n- Step one", Files.readString(md));

        JsonServiceRepository.LoadResult result = repository.loadAllWithReport(tempDir);
        assertEquals(1, result.definitions().size());
        assertEquals("# How to test\n\n- Step one", result.definitions().get(0).getMethodology());

        List<Path> jsonFiles = JsonServiceRepository.listJsonFiles(tempDir);
        assertEquals(1, jsonFiles.size());
        String rawJson = Files.readString(jsonFiles.get(0));
        assertTrue(rawJson.contains("\"methodology\": \"\"") || rawJson.contains("\"methodology\":\"\""));
    }

    @Test
    void methodologySidecarOverridesJsonField() throws Exception {
        String json =
                "{\"schemaVersion\":\"1\",\"id\":\"svc-md\",\"name\":\"T\",\"description\":\"\","
                        + "\"methodology\":\"ignored when md present\",\"patterns\":[\"^a$\"],"
                        + "\"tlsPassThrough\":false,\"tlsHostRegex\":\"\"}";
        Files.writeString(tempDir.resolve("svc-md.json"), json);
        Files.writeString(tempDir.resolve("svc-md.md"), "## From file");

        JsonServiceRepository.LoadResult result = new JsonServiceRepository().loadAllWithReport(tempDir);
        assertEquals(1, result.definitions().size());
        assertEquals("## From file", result.definitions().get(0).getMethodology());
    }

    @Test
    void deleteRemovesMethodologySidecar() throws Exception {
        ServiceDefinition service = ServiceDefinition.createNew("X");
        service.setPatterns(List.of("^b$"));
        service.setMethodology("notes");
        JsonServiceRepository repository = new JsonServiceRepository();
        repository.save(tempDir, service);
        Path md = JsonServiceRepository.methodologyPath(tempDir, service.getId());
        assertTrue(Files.isRegularFile(md));

        repository.delete(tempDir, service.getId());
        assertFalse(Files.exists(md));
    }
}
