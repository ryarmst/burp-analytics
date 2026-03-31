package burp.analytics.session;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Session proxy matches: one row per FQDN, newest first. */
public final class SessionMatchStore {

    private static final int DEFAULT_MAX = 500;

    private final int maxSize;
    private final List<SessionMatch> matches = new ArrayList<>();
    private final Set<String> seenFqdns = ConcurrentHashMap.newKeySet();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public SessionMatchStore() {
        this(DEFAULT_MAX);
    }

    public SessionMatchStore(int maxSize) {
        this.maxSize = Math.max(1, maxSize);
    }

    public boolean recordIfNewFqdn(
            String fqdn,
            String serviceId,
            String serviceName,
            String matchedPattern,
            String matchTarget,
            burp.api.montoya.http.message.HttpRequestResponse evidence) {
        if (fqdn == null || fqdn.isBlank()) {
            return false;
        }
        if (!seenFqdns.add(fqdn)) {
            return false;
        }
        lock.writeLock().lock();
        try {
            matches.add(
                    0,
                    new SessionMatch(
                            Instant.now(), fqdn, serviceId, serviceName, matchedPattern, matchTarget, evidence));
            while (matches.size() > maxSize) {
                matches.remove(matches.size() - 1);
            }
        } finally {
            lock.writeLock().unlock();
        }
        return true;
    }

    public List<SessionMatch> snapshot() {
        lock.readLock().lock();
        try {
            return Collections.unmodifiableList(new ArrayList<>(matches));
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clear() {
        lock.writeLock().lock();
        try {
            matches.clear();
            seenFqdns.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }
}
