// src/decoyResponse.js
// Generates plausible-but-fake balance responses for confirmed bad actors.
// The goal: their request "succeeds" in a way that looks real, so they
// keep interacting (giving you more intel) instead of immediately
// realizing they've been caught and switching tactics/infrastructure.

function generateDecoyBalance(cardNumber) {
  // Deterministic-but-fake: same card number always gets the same fake
  // balance within a session, so it doesn't look randomly generated if
  // they check twice.
  let hash = 0;
  for (const char of cardNumber) {
    hash = (hash * 31 + char.charCodeAt(0)) % 100000;
  }
  const fakeBalance = (hash % 200) + 1; // $1 - $200, plausible range
  return Math.round(fakeBalance * 100) / 100;
}

module.exports = { generateDecoyBalance };
