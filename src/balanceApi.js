// src/balanceApi.js
// Stand-in for your REAL gift-card balance/PIN lookup endpoint.
// In production this would query your actual card database.
// Kept deliberately simple so the fraud-detection layer (the actual point
// of this project) is easy to see.

const express = require('express');
const { recordAttempt } = require('./anomalyDetection');
const { isHoneytoken } = require('./honeytokens');
const { flagActor, getFlag } = require('./flaggedActors');
const { generateDecoyBalance } = require('./decoyResponse');
const router = express.Router();

// Fake "database" of valid cards, just for demo purposes.
// In production, this would be your real card database or API call to your card provider.
const FAKE_CARDS = {
  '4111111111111111': { pin: '1234', balance: 50.0 },
  '4222222222222222': { pin: '5678', balance: 25.0 },
};

router.post('/balance', (req, res) => {
  const { cardNumber, pin } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.ip;

  if (!cardNumber || !pin) {
    return res.status(400).json({ error: 'cardNumber and pin are required' });
  }

  // --- Honeytoken check: highest priority, before anything else. ---
  // No real customer can ever submit one of these numbers, so this is
  // a confirmed-malicious signal, not a heuristic guess.
  if (isHoneytoken(cardNumber)) {
    flagActor(ip, 'honeytoken_hit');
    recordAttempt({ type: 'honeytoken_hit', ip, cardNumber });
    // Serve a decoy success so the attacker doesn't realize they hit a
    // tripwire - they think the card is real and keep engaging.
    return res.json({ balance: generateDecoyBalance(cardNumber) });
  }

  // --- Already-flagged actor: keep serving decoy data, not real logic. ---
  const flag = getFlag(ip);
  if (flag) {
    recordAttempt({ type: 'flagged_actor_request', ip, cardNumber, reason: flag.reason });
    return res.json({ balance: generateDecoyBalance(cardNumber) });
  }

  const card = FAKE_CARDS[cardNumber];
  const success = !!card && card.pin === pin;

  // Record every attempt - success or failure - for anomaly analysis.
  // (Rate limiting middleware already ran before this handler; this
  // feeds the pattern-detection layer regardless of outcome.)
  recordAttempt({ type: success ? 'success' : 'failure', ip, cardNumber });

  if (!success) {
    // Deliberately generic error - never reveal whether the card number
    // exists but the PIN was wrong, vs. the card not existing at all.
    // That distinction is exactly what lets attackers enumerate valid
    // card numbers before brute-forcing PINs.
    return res.status(401).json({ error: 'Invalid card number or PIN' });
  }

  return res.json({ balance: card.balance });
});

module.exports = router;
