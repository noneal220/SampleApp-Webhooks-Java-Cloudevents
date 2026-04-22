package com.intuit.developer.sampleapp.webhooks.service;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

/**
 * Bounded in-memory store for diagnostic webhook captures.
 *
 * <p>Each capture records the full request (headers + raw body) and the
 * result of trying every signature candidate. Used by {@code WebhookDebugController}
 * to prove/disprove hypotheses about the sandbox CloudEvents toggle
 * (token rotation, v2.0 signing scheme, empty bodies).</p>
 */
@Service
public class WebhookDebugStore {

    private static final int MAX_ENTRIES = 50;

    private final Deque<Entry> entries = new ArrayDeque<>();

    public synchronized void add(Entry entry) {
        entries.addFirst(entry);
        while (entries.size() > MAX_ENTRIES) {
            entries.removeLast();
        }
    }

    public synchronized List<Entry> list() {
        return new ArrayList<>(entries);
    }

    public synchronized Entry latest() {
        return entries.peekFirst();
    }

    public synchronized void clear() {
        entries.clear();
    }

    public synchronized int size() {
        return entries.size();
    }

    /**
     * A single captured webhook delivery with everything we need to
     * diagnose signing / body issues.
     */
    public static class Entry {
        public final String receivedAt = Instant.now().toString();
        public final long sequence;
        public String remoteAddr;
        public String method;
        public String uri;
        public Map<String, String> headers = new LinkedHashMap<>();
        public int bodyLength;
        public String body;
        public String intuitSignatureHeader;
        public List<SignatureCandidate> signatureCandidates = new ArrayList<>();
        /** True when at least one candidate's computed value equals {@code intuitSignatureHeader}. */
        public boolean anyCandidateMatched;

        public Entry(long sequence) {
            this.sequence = sequence;
        }
    }

    /**
     * Result of attempting one HMAC scheme against the incoming body + verifier token.
     */
    public static class SignatureCandidate {
        public final String scheme;
        public final String computed;
        public final boolean matched;
        public final String note;

        public SignatureCandidate(String scheme, String computed, boolean matched, String note) {
            this.scheme = scheme;
            this.computed = computed;
            this.matched = matched;
            this.note = note;
        }
    }
}
