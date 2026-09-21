// src/rateLimiting.js
// Two independent rate limits, because fraud on card-balance endpoints
// shows up in two different shapes:
//
// 1. Per-IP: one attacker hammering the endpoint from a single source.
// 2. Per-card-number: many IPs (botnet/proxy rotation) all guessing PINs
//    for the SAME card number - this defeats naive per-IP limiting, so
//    it needs its own counter.

const rateLimit = require('express-rate-limit');
const { recordAttempt } = require('./anomalyDetection');

// Per-IP: generous enough for real users occasionally mistyping a PIN,
// tight enough to stop rapid automated guessing from one source.
const perIpLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,             // 10 attempts/min/IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// Per-card-number limiting: tracked manually (express-rate-limit only
// keys by IP by default), since the request body isn't available until
// after body-parsing middleware runs.
const cardAttempts = new Map(); // cardNumber -> [{ timestamp, ip }]
const CARD_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const CARD_MAX_ATTEMPTS = 5;          // max distinct attempts per card in that window

function perCardLimiter(req, res, next) {
  const { cardNumber } = req.body;
  if (!cardNumber) return next(); // let balanceApi.js handle validation

  const now = Date.now();
  const attempts = (cardAttempts.get(cardNumber) || []).filter(
    (a) => now - a.timestamp < CARD_WINDOW_MS
  );

  if (attempts.length >= CARD_MAX_ATTEMPTS) {
    recordAttempt({
      type: 'card_limit_exceeded',
      cardNumber,
      ip: req.headers['x-forwarded-for'] || req.ip,
      attemptCount: attempts.length,
    });
    return res.status(429).json({ error: 'Too many attempts on this card. Please try again later.' });
  }

  attempts.push({ timestamp: now, ip: req.headers['x-forwarded-for'] || req.ip });
  cardAttempts.set(cardNumber, attempts);
  next();
}

// Periodic cleanup so the Map doesn't grow forever.
setInterval(() => {
  const now = Date.now();
  for (const [card, attempts] of cardAttempts.entries()) {
    const fresh = attempts.filter((a) => now - a.timestamp < CARD_WINDOW_MS);
    if (fresh.length === 0) cardAttempts.delete(card);
    else cardAttempts.set(card, fresh);
  }
}, 5 * 60 * 1000).unref();

module.exports = { perIpLimiter, perCardLimiter };
