# Fraud Detection API — Rate Limiting + Anomaly Detection

Protects a gift-card-style balance/PIN-check endpoint against the fraud
patterns that actually target these systems: card-number enumeration,
PIN brute-forcing, and distributed low-and-slow attacks.

This is a **reference implementation** with a mock balance endpoint.
Swap `src/balanceApi.js`'s logic for your real database lookup and keep
the surrounding rate-limiting/anomaly-detection layers as-is.

## Why this shape (not a honeypot)

Gift-card fraud on a balance/PIN endpoint is almost always **automated
enumeration against the real API**, not someone poking at your webpage.
A decoy site doesn't address that threat model. What does:

- Rate limiting (per-IP AND per-card — attackers rotate IPs, not card numbers)
- Detecting *patterns* across many requests, not just volume
- Never leaking whether a card number is valid vs. the PIN being wrong
  (that oracle is what lets attackers separate enumeration from brute-forcing)

## Project layout

```
fraud-detection-api/
  src/
    server.js            # entry point, wires everything together
    balanceApi.js         # the endpoint itself (replace with your real DB lookup)
    rateLimiting.js        # per-IP and per-card rate limits
    anomalyDetection.js     # pattern detection: enumeration, card-testing, distributed attacks
    alerts.js                # where alerts go (console now, Slack-ready)
  logs/
    fraud-events.log         # every attempt + every fired alert
```

## 1. Install and run

```bash
npm install
npm start
# -> [fraud-detection-api] listening on http://localhost:5000
```

## 2. Test as a normal user

```bash
curl -s -X POST http://localhost:5000/api/balance \
  -H "Content-Type: application/json" \
  -d '{"cardNumber":"4111111111111111","pin":"1234"}'
```

Returns `{"balance":50}`. Check `logs/fraud-events.log` — a normal
`success` attempt, no alerts.

## 3. Test: per-card PIN brute-forcing

Hammer one card with wrong PINs:

```bash
for i in $(seq 1 7); do
  curl -s -X POST http://localhost:5000/api/balance \
    -H "Content-Type: application/json" \
    -d "{\"cardNumber\":\"4111111111111111\",\"pin\":\"000$i\"}"
  echo
done
```

After 5 attempts on that card within 5 minutes, you'll get:
```json
{"error":"Too many attempts on this card. Please try again later."}
```
and a `card_limit_exceeded` entry in `logs/fraud-events.log`.

## 4. Test: sequential card-number enumeration

Simulate an attacker walking through card numbers:

```bash
for i in $(seq 0 5); do
  curl -s -X POST http://localhost:5000/api/balance \
    -H "Content-Type: application/json" \
    -d "{\"cardNumber\":\"411111111111111$i\",\"pin\":\"0000\"}"
  echo
done
```

Watch the server console — after enough sequential card numbers from one
IP, you'll see:
```
🚨 FRAUD ALERT: { "pattern": "sequential_card_enumeration", ... }
```

## 5. Test: per-IP rate limit (general volume)

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:5000/api/balance \
    -H "Content-Type: application/json" \
    -d '{"cardNumber":"4222222222222222","pin":"9999"}'
done
```

After 10 requests in a minute from one IP, you'll start seeing `429`
responses.

## 6. Wire up real alerts

Edit `src/alerts.js` — the Slack webhook block is written and commented
out. Set `SLACK_WEBHOOK_URL` as an environment variable and uncomment it
to get alerts posted to a Slack channel in real time.

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

## 7. Tuning for your real traffic

All thresholds live in two files — tune them against your actual
legitimate-user behavior before relying on them:

- `src/rateLimiting.js`
  - `CARD_MAX_ATTEMPTS` / `CARD_WINDOW_MS` — attempts allowed per card
  - `perIpLimiter` config — general per-IP request volume
- `src/anomalyDetection.js`
  - `CARD_TESTING_THRESHOLD` — distinct cards from one IP before flagging
  - `DISTRIBUTED_IP_THRESHOLD` — distinct IPs hitting one card before flagging
  - `looksSequential()` — how strictly "sequential" is defined

Start permissive and tighten based on `logs/fraud-events.log` data from
real traffic, rather than guessing thresholds up front.

## 8. Honeytoken cards + decoy responses

Two additions on top of rate limiting and anomaly detection:

- **`src/honeytokens.js`** — a small set of card numbers that are never
  real. No legitimate customer can ever submit one, so any hit is a
  confirmed-fraud signal (no false-positive risk, unlike thresholds).
- **`src/flaggedActors.js`** + **`src/decoyResponse.js`** — once an IP
  hits a honeytoken, or triggers a high-confidence pattern (sequential
  enumeration, card-testing), it's flagged for 24 hours. Flagged IPs get
  a **plausible fake balance** back instead of an error — they don't
  realize they've been caught, so they keep interacting (more intel for
  you) instead of immediately rotating infrastructure.

### Test: honeytoken hit

```bash
curl -s -X POST http://localhost:5000/api/balance \
  -H "Content-Type: application/json" \
  -d '{"cardNumber":"4999999999999901","pin":"0000"}'
```

Returns a fake-but-plausible `{"balance": ...}` — looks like success.
Check `logs/fraud-events.log`: you'll see a `honeytoken_hit` event and an
`ALERT` entry. No legitimate response was ever computed; the number
doesn't exist in `FAKE_CARDS` at all.

### Test: flagged actor stays on decoy responses

Immediately after the honeytoken hit above, try a *real* card from the
same "IP" (curl from the same machine):

```bash
curl -s -X POST http://localhost:5000/api/balance \
  -H "Content-Type: application/json" \
  -d '{"cardNumber":"4111111111111111","pin":"1234"}'
```

Even though `4111111111111111`/`1234` is a valid combination in
`FAKE_CARDS`, you'll get a **decoy balance**, not the real `$50` — because
this IP is now flagged. Check `logs/fraud-events.log` for a
`flagged_actor_request` entry showing why.

### Deploying honeytokens for real

Don't reuse the example numbers in `honeytokens.js` as-is — generate your
own that pass your system's format/checksum validation but are never
issued to any real customer, then seed them somewhere an attacker's
reconnaissance might realistically encounter them (see the comments in
`honeytokens.js` for the reasoning). The file is intentionally small and
explicit so you can swap in your real values.

## 9. Moving toward production

- Replace the in-memory `Map`s (`cardAttempts`, `recentAttempts`) with
  Redis if you run more than one instance of this service.
- Replace `FAKE_CARDS` in `balanceApi.js` with your real lookup — keep
  the "generic error either way" behavior, it's load-bearing.
- Consider adding device fingerprinting (e.g. a JS-side fingerprint sent
  with each request) as another signal alongside IP, since IP alone is
  weak against residential proxy networks.
- If you're behind a CDN/WAF (Cloudflare, Akamai, etc.), push basic bot
  detection there too — this app-level layer catches what slips through.
