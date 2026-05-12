package burp.analytics.session;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionMatchStoreTest {

    @Test
    void recordsOnlyFirstMatchForFqdnAndService() {
        SessionMatchStore store = new SessionMatchStore();

        assertTrue(
                store.recordIfNewFqdnService(
                        "analytics.example.com", "svc-1", "Example", "^analytics", "analytics.example.com", null));
        assertFalse(
                store.recordIfNewFqdnService(
                        "analytics.example.com", "svc-1", "Example", "^analytics", "analytics.example.com", null));
        assertTrue(
                store.recordIfNewFqdnService(
                        "analytics.example.com", "svc-2", "Other", "^other", "analytics.example.com", null));
        assertEquals(2, store.snapshot().size());
    }

    @Test
    void enforcesMaximumSize() {
        SessionMatchStore store = new SessionMatchStore(1);

        assertTrue(store.recordIfNewFqdnService("first.example.com", "svc-1", "First", "^first", "first.example.com", null));
        assertTrue(
                store.recordIfNewFqdnService(
                        "second.example.com", "svc-2", "Second", "^second", "second.example.com", null));

        assertEquals(1, store.snapshot().size());
        assertEquals("second.example.com", store.snapshot().get(0).getFqdn());
    }
}
