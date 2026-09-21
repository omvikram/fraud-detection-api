// src/flaggedActors.js
// Once an IP is confirmed malicious (honeytoken hit, or a high-confidence
// anomaly pattern), we don't want to just block it - blocking teaches the
// attacker to rotate IPs immediately. Instead, flagged IPs get routed to
// a DECOY response path: plausible-looking fake data instead of a real
// answer or an obvious error, so they keep interacting with a dead end
// while you gather intel, without an obvious signal that they were caught.

const FLAG_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours - longer than a generic honeypot flag,
                                          // since a honeytoken hit is high-confidence, not a guess

const flagged = new Map(); // ip -> { expiry, reason }

function flagActor(ip, reason) {
  flagged.set(ip, { expiry: Date.now() + FLAG_TTL_MS, reason });
}

function getFlag(ip) {
  const entry = flagged.get(ip);
  if (!entry) return null;
  if (Date.now() > entry.expiry) {
    flagged.delete(ip);
    return null;
  }
  return entry;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of flagged.entries()) {
    if (now > entry.expiry) flagged.delete(ip);
  }
}, 10 * 60 * 1000).unref();

module.exports = { flagActor, getFlag };
