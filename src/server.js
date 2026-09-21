// src/server.js
const express = require('express');
require('./alerts'); // registers alert handlers as a side effect

const balanceApi = require('./balanceApi');
const { perIpLimiter, perCardLimiter } = require('./rateLimiting');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

// Order matters: per-IP limiter first (cheapest check), then per-card
// limiter (needs the parsed body), then the actual endpoint.
app.use('/api', perIpLimiter, perCardLimiter, balanceApi);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`[fraud-detection-api] listening on http://localhost:${PORT}`);
  console.log(`[fraud-detection-api] try: POST http://localhost:${PORT}/api/balance`);
});
