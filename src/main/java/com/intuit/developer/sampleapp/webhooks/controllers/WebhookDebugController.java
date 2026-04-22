package com.intuit.developer.sampleapp.webhooks.controllers;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.intuit.developer.sampleapp.webhooks.service.WebhookDebugStore;
import com.intuit.developer.sampleapp.webhooks.service.WebhookDebugStore.Entry;
import com.intuit.developer.sampleapp.webhooks.service.WebhookDebugStore.SignatureCandidate;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Diagnostic webhook receiver used to investigate EGW / CloudEvents v2.0
 * signing behavior in the QBO sandbox.
 *
 * <p>Unlike the production {@code WebhooksController}, this endpoint:</p>
 * <ul>
 *   <li>Accepts any content-type and any (or missing) signature header.</li>
 *   <li>Never returns 403 - always 200 so the sender does not retry/back off.</li>
 *   <li>Captures the full request (headers + raw body) for later inspection.</li>
 *   <li>Computes multiple candidate HMAC signatures so we can tell which
 *       signing scheme (if any) the delivery is using:
 *     <ul>
 *       <li>HMAC-SHA256 over raw body, key = verifier token as UTF-8 bytes (legacy v1.0).</li>
 *       <li>HMAC-SHA256 over raw body, key = base64-decoded verifier token
 *           (the "EGW rotates to a binary token" theory).</li>
 *       <li>Both of the above expressed as base64 AND lowercase hex.</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <p>Point the sandbox subscription at {@code /webhooks/debug}, trigger events
 * with the CloudEvents toggle both OFF and ON, then read
 * {@code GET /webhooks/debug/log} to compare. See {@code WEBHOOK-DEBUG.md}.</p>
 */
@RestController
@RequestMapping("/webhooks/debug")
public class WebhookDebugController {

    private static final Logger LOG = LoggerFactory.getLogger(WebhookDebugController.class);
    private static final String SIGNATURE_HEADER = "intuit-signature";

    private final AtomicLong sequence = new AtomicLong();

    @Autowired
    private WebhookDebugStore store;

    /** Optional - if set, we compute candidate signatures against this token. */
    @Value("${quickbooks.webhooks-verifier-token:}")
    private String verifierToken;

    /**
     * Receives a diagnostic webhook. Always returns 200 so the sender treats
     * it as successful and does not alter delivery behavior.
     */
    @PostMapping(consumes = MediaType.ALL_VALUE)
    public ResponseEntity<Map<String, Object>> receive(HttpServletRequest request, @org.springframework.web.bind.annotation.RequestBody(required = false) String body) {
        Entry entry = new Entry(sequence.incrementAndGet());
        entry.remoteAddr = request.getRemoteAddr();
        entry.method = request.getMethod();
        entry.uri = request.getRequestURI();
        entry.headers = readHeaders(request);
        entry.body = body == null ? "" : body;
        entry.bodyLength = entry.body.length();
        entry.intuitSignatureHeader = firstHeader(entry.headers, SIGNATURE_HEADER);
        entry.signatureCandidates = computeCandidates(entry.body, entry.intuitSignatureHeader);
        entry.anyCandidateMatched = entry.signatureCandidates.stream().anyMatch(c -> c.matched);

        store.add(entry);

        LOG.info("=====================================================");
        LOG.info("DEBUG WEBHOOK #{} captured - bodyLen={}, headers={}",
            entry.sequence, entry.bodyLength, entry.headers.size());
        LOG.info("Incoming intuit-signature: {}", entry.intuitSignatureHeader);
        for (SignatureCandidate c : entry.signatureCandidates) {
            LOG.info("  candidate [{}] matched={} computed={}", c.scheme, c.matched, c.computed);
        }
        LOG.info("Body preview: {}", entry.body.substring(0, Math.min(300, entry.body.length())));
        LOG.info("=====================================================");

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "ok");
        resp.put("sequence", entry.sequence);
        resp.put("bodyLength", entry.bodyLength);
        resp.put("anyCandidateMatched", entry.anyCandidateMatched);
        return ResponseEntity.ok(resp);
    }

    /** Returns every captured delivery as JSON (newest first). */
    @GetMapping(value = "/log", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> log() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("count", store.size());
        resp.put("verifierTokenConfigured", verifierToken != null && !verifierToken.isEmpty());
        resp.put("entries", store.list());
        return ResponseEntity.ok(resp);
    }

    /** Returns only the most recent capture (convenience). */
    @GetMapping(value = "/latest", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Entry> latest() {
        Entry latest = store.latest();
        if (latest == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(latest);
    }

    /** Clears the capture buffer so you can start a clean test run. */
    @DeleteMapping("/log")
    public ResponseEntity<Map<String, Object>> clear() {
        int before = store.size();
        store.clear();
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("cleared", before);
        return ResponseEntity.ok(resp);
    }

    // =========================================================
    // helpers
    // =========================================================

    private Map<String, String> readHeaders(HttpServletRequest req) {
        Map<String, String> out = new LinkedHashMap<>();
        Enumeration<String> names = req.getHeaderNames();
        if (names == null) return out;
        for (String name : Collections.list(names)) {
            out.put(name, String.join(", ", Collections.list(req.getHeaders(name))));
        }
        return out;
    }

    private String firstHeader(Map<String, String> headers, String name) {
        // headers map is case-sensitive; request header names may come through
        // with any casing, so do a case-insensitive lookup.
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    /**
     * Computes every candidate HMAC we suspect might be in play. The list of
     * candidates is the core of the diagnostic - whichever one matches the
     * incoming {@code intuit-signature} tells us the sender's signing scheme.
     */
    private java.util.List<SignatureCandidate> computeCandidates(String body, String incomingSignature) {
        java.util.List<SignatureCandidate> out = new java.util.ArrayList<>();
        if (verifierToken == null || verifierToken.isEmpty()) {
            out.add(new SignatureCandidate("skipped", null, false,
                "No verifier token configured - set WEBHOOKS_VERIFIER_TOKEN to enable signature comparison."));
            return out;
        }
        if (body == null) body = "";

        byte[] utf8Key = verifierToken.getBytes(StandardCharsets.UTF_8);
        out.addAll(tryKey("utf8", utf8Key, body, incomingSignature));

        // "Token is actually a base64-encoded binary key" theory
        try {
            byte[] b64Key = Base64.getDecoder().decode(verifierToken);
            out.addAll(tryKey("base64-decoded", b64Key, body, incomingSignature));
        } catch (IllegalArgumentException ex) {
            out.add(new SignatureCandidate("base64-decoded", null, false,
                "Verifier token is not valid base64, skipping this candidate."));
        }

        return out;
    }

    private java.util.List<SignatureCandidate> tryKey(String keyLabel, byte[] key, String body, String incoming) {
        java.util.List<SignatureCandidate> out = new java.util.ArrayList<>();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] digest = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));

            String b64 = Base64.getEncoder().encodeToString(digest);
            String hex = toHex(digest);

            out.add(new SignatureCandidate(
                "HmacSHA256 / key=" + keyLabel + " / base64",
                b64, equalsSafe(b64, incoming), null));
            out.add(new SignatureCandidate(
                "HmacSHA256 / key=" + keyLabel + " / hex",
                hex, equalsSafe(hex, incoming), null));
        } catch (Exception e) {
            out.add(new SignatureCandidate("HmacSHA256 / key=" + keyLabel, null, false,
                "Failed: " + e.getMessage()));
        }
        return out;
    }

    private static boolean equalsSafe(String a, String b) {
        return a != null && b != null && a.equals(b);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
