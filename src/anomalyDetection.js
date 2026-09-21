// src/anomalyDetection.js
// Detects fraud PATTERNS that simple rate limiting misses:
//
// 1. Sequential card-number enumeration
//    (attacker tries 4111111111111111, then ...12, ...13, ...14 ...)
// 2. Low-and-slow distributed attacks
//    (many different IPs, each making only 1-2 requests, but collectively
//    hammering the same small set of card numbers - defeats per-IP limits)
// 3. High card-guess diversity from one IP in a short window
//    (one IP trying many DIFFERENT card numbers quickly - a card-testing
//    pattern, distinct from PIN-brute-forcing one known card)
//
// This module doesn't block anything itself - it scores and logs, and
// exposes a hook (`onAlert`) you can wire to Slack/email/PagerDuty.
// Blocking decisions belong in rateLimiting.js / your WAF; this is the
// "notice something is wrong" layer.

const fs = require('fs');
const path = require('path');
const { flagActor } = require('./flaggedActors');

const LOG_FILE = path.join(__dirname, '..', 'logs', 'fraud-events.log');

// Recent attempts, kept in memory for pattern analysis.
// Each entry: { timestamp, ip, cardNumber }
const recentAttempts = [];
const RETENTION_MS = 15 * 60 * 1000; // keep 15 minutes of history for analysis

// Register alert handlers here (e.g. a Slack webhook call).
const alertHandlers = [];
function onAlert(handler) {
  alertHandlers.push(handler);
}

function fireAlert(alert) {
  logToFile({ type: 'ALERT', ...alert });
  alertHandlers.forEach((h) => {
    try {
      h(alert);
    } catch (err) {
      console.error('[anomalyDetection] alert handler failed:', err.message);
    }
  });
}

function logToFile(entry) {
  fs.appendFileSync(
    LOG_FILE,
    JSON.stringify({ timestamp: new Date().toISOString(), ...entry }) + '\n'
  );
}

function pruneOldAttempts() {
  const cutoff = Date.now() - RETENTION_MS;
  while (recentAttempts.length && recentAttempts[0].timestamp < cutoff) {
    recentAttempts.shift();
  }
}

// Are these card numbers sequential/near-sequential? Simple heuristic:
// compare as integers, check if consecutive attempts differ by a small
// fixed step (1, 2, 10, etc.) - real enumeration tools often increment
// predictably.
function looksSequential(cardNumbers) {
  if (cardNumbers.length < 4) return false;
  const nums = cardNumbers.map((c) => BigInt(c)).sort((a, b) => (a < b ? -1 : 1));
  let consistentStepCount = 0;
  let lastDiff = null;
  for (let i = 1; i < nums.length; i++) {
    const diff = nums[i] - nums[i - 1];
    if (diff > 0n && diff <= 10n) {
      if (lastDiff === null || diff === lastDiff) {
        consistentStepCount++;
      }
      lastDiff = diff;
    }
  }
  return consistentStepCount >= nums.length - 2; // most steps are consistent
}

/**
 * Call this on every balance-check attempt (success or failure).
 */
function recordAttempt({ type, ip, cardNumber, attemptCount }) {
  logToFile({ type: type || 'attempt', ip, cardNumber, attemptCount });

  if (!cardNumber) return; // e.g. card_limit_exceeded events already logged above

  const now = Date.now();
  recentAttempts.push({ timestamp: now, ip, cardNumber });
  pruneOldAttempts();

  // --- Pattern 1: sequential enumeration from one IP ---
  const thisIpCards = recentAttempts
    .filter((a) => a.ip === ip)
    .map((a) => a.cardNumber);

  const uniqueCardsFromIp = [...new Set(thisIpCards)];
  if (uniqueCardsFromIp.length >= 4 && looksSequential(uniqueCardsFromIp)) {
    fireAlert({
      pattern: 'sequential_card_enumeration',
      ip,
      cardsSeen: uniqueCardsFromIp.length,
      sample: uniqueCardsFromIp.slice(0, 5),
    });
    // High-confidence, IP-attributable pattern - move this IP to decoy
    // responses going forward instead of just alerting.
    flagActor(ip, 'sequential_card_enumeration');
  }

  // --- Pattern 2: card-testing (many distinct cards, one IP, short window) ---
  const CARD_TESTING_THRESHOLD = 8; // distinct cards from one IP in 15 min
  if (uniqueCardsFromIp.length >= CARD_TESTING_THRESHOLD) {
    fireAlert({
      pattern: 'card_testing_single_ip',
      ip,
      distinctCardsAttempted: uniqueCardsFromIp.length,
    });
    flagActor(ip, 'card_testing_single_ip');
  }

  // --- Pattern 3: low-and-slow distributed attack on one card ---
  const attemptsOnThisCard = recentAttempts.filter((a) => a.cardNumber === cardNumber);
  const distinctIpsOnCard = new Set(attemptsOnThisCard.map((a) => a.ip));
  const DISTRIBUTED_IP_THRESHOLD = 6; // distinct IPs hitting the same card in 15 min
  if (distinctIpsOnCard.size >= DISTRIBUTED_IP_THRESHOLD) {
    fireAlert({
      pattern: 'distributed_attack_single_card',
      cardNumber,
      distinctIps: distinctIpsOnCard.size,
    });
  }
}

module.exports = { recordAttempt, onAlert };
