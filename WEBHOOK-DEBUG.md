# Webhook Debug Endpoint

A non-enforcing diagnostic receiver used to investigate three open
questions about the sandbox's CloudEvents toggle:

1. **Does toggling CloudEvents silently rotate the verifier token?** (the HMAC
   starts failing for v1.0 traffic at the moment the toggle is flipped)
2. **Does CloudEvents v2.0 use a different signing scheme** (HTTP Signing
   extension) than v1.0's single `intuit-signature` HMAC header?
3. **Are v2.0 notification bodies actually arriving empty (`{}`)** in sandbox?

## What it does

`POST /webhooks/debug` accepts any request, logs it, and **always returns 200**
so the sender does not retry/back off. For each capture it records:

- Every header exactly as received
- The raw body (so we can see whether v2.0 bodies are empty)
- The incoming `intuit-signature` value
- A table of **signature candidates** - for each, the scheme used, the
  computed value, and whether it matches the incoming signature. The
  candidates are:
  - `HmacSHA256 / key=utf8 / base64`   (legacy v1.0)
  - `HmacSHA256 / key=utf8 / hex`
  - `HmacSHA256 / key=base64-decoded / base64`   (the "EGW rotates to a binary key" theory)
  - `HmacSHA256 / key=base64-decoded / hex`

Whichever candidate matches tells us the sender's signing scheme. If none
match, either the body hash differs (empty body?) or the scheme is
something else entirely (HTTP Signing extension? different canonicalization?).

## Endpoints

| Method | Path                      | Purpose                                       |
|--------|---------------------------|-----------------------------------------------|
| POST   | `/webhooks/debug`         | Receive a delivery; always 200                |
| GET    | `/webhooks/debug/log`     | All captured deliveries (newest first)        |
| GET    | `/webhooks/debug/latest`  | Just the most recent capture                  |
| DELETE | `/webhooks/debug/log`     | Clear the buffer between test runs            |

## Test procedure (to answer A / B / C)

### 0. Prep

```bash
# verifier token from the dev portal (needed for signature comparison)
echo 'WEBHOOKS_VERIFIER_TOKEN=<token-from-portal>' >> .env
QB_ENVIRONMENT=sandbox ./gradlew bootRun
```

Expose `http://localhost:8080` publicly (CWS URL or `cloudflared tunnel --url`).
Set the sandbox webhook endpoint to `<public-url>/webhooks/debug`.

### 1. Baseline - CloudEvents toggle OFF

```bash
curl -X DELETE http://localhost:8080/webhooks/debug/log
# trigger an event in the sandbox company (e.g., create a Customer)
curl -s http://localhost:8080/webhooks/debug/latest | jq
```

Expect: `anyCandidateMatched=true`, specifically `utf8 / base64`.
If it matches, legacy v1.0 signing works with the current token.

### 2. Flip the toggle - CloudEvents ON, change nothing else

```bash
# in the dev portal, flip CloudEvents ON for the same subscription.
# do NOT change the verifier token in .env.
curl -X DELETE http://localhost:8080/webhooks/debug/log
# trigger another event
curl -s http://localhost:8080/webhooks/debug/latest | jq
```

Interpret:

- `anyCandidateMatched=false` + `body == "{}"`  -> hypothesis **C** confirmed (empty v2.0 body).
- `anyCandidateMatched=false` + non-empty body + *new* headers (`signature`, `signature-input`, `digest`, `ce-signature`) -> hypothesis **B** confirmed (different signing scheme).
- `anyCandidateMatched=false` and the `intuit-signature` value *changed* from step 1 with no app-side change -> hypothesis **A** supported: refresh the portal token into `.env`, restart, retry. If it now matches, the toggle silently rotated the token.
- `anyCandidateMatched=true` under `base64-decoded / base64` -> the token is actually a base64-encoded binary key (the internal note's theory).

### 3. Rotate token

```bash
# copy the current verifier token from the portal -> .env
# restart the app
curl -X DELETE http://localhost:8080/webhooks/debug/log
# trigger an event
curl -s http://localhost:8080/webhooks/debug/latest | jq '.signatureCandidates'
```

Which candidate scheme matches now? That is the signing scheme the EGW /
CloudEvents-enabled subscription is actually using.

## Notes

- The buffer holds the 50 most recent captures in memory. Restart clears it.
- The receiver accepts any content-type (including `application/cloudevents-batch+json`).
- No signature enforcement happens on `/webhooks/debug` - the real
  `/webhooks` endpoint is untouched and keeps its 403 behavior.
