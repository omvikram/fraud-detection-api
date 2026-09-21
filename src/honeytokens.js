// src/honeytokens.js
// Honeytoken card numbers: fake-but-realistic-looking card numbers that
// are NOT assigned to any real customer. No legitimate user could ever
// submit one, because it doesn't exist in your real system. Any balance
// check against one of these is therefore a near-100%-confidence fraud
// signal - there's no false-positive path like there is with rate limits
// or behavioral heuristics.
//
// How to actually deploy honeytokens (do this once you're ready for
// production, against your REAL card system - not as fake data you
// invent locally):
//   1. Generate card numbers that pass your normal format/checksum
//      validation (e.g. valid Luhn checksum) but are never issued to
//      any real customer or added to your real balance database.
//   2. Seed them somewhere an attacker's reconnaissance might find them:
//      e.g. a deliberately-planted "leaked" list on a paste site you
//      monitor, a fake export file with tracking, or simply reserved
//      numbers you never issue but which fall inside a range attackers
//      commonly guess/enumerate (e.g. sequential blocks).
//   3. Anything that touches one of these numbers is not a "maybe" -
//      treat it as confirmed malicious activity immediately.

const HONEYTOKEN_CARDS = new Set([
  '4999999999999901',
  '4999999999999902',
  '4999999999999903',
  // Add more as you seed them. Keep this list out of your real card
  // range so it never collides with an actual issued card number.
]);

function isHoneytoken(cardNumber) {
  return HONEYTOKEN_CARDS.has(cardNumber);
}

module.exports = { isHoneytoken, HONEYTOKEN_CARDS };
