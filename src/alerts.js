// src/alerts.js
// Wire anomaly-detection alerts to wherever you want to be notified.
// Ships with a console logger; the Slack webhook function is ready to
// use once you set SLACK_WEBHOOK_URL.

const { onAlert } = require('./anomalyDetection');

onAlert((alert) => {
  console.warn('🚨 FRAUD ALERT:', JSON.stringify(alert, null, 2));
});

// Uncomment and set SLACK_WEBHOOK_URL to enable Slack notifications.
// Requires Node 18+ (built-in fetch) - you're on Node 22, so you're set.
//
// const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;
// if (SLACK_WEBHOOK_URL) {
//   onAlert(async (alert) => {
//     await fetch(SLACK_WEBHOOK_URL, {
//       method: 'POST',
//       headers: { 'Content-Type': 'application/json' },
//       body: JSON.stringify({
//         text: `🚨 Fraud pattern detected: *${alert.pattern}*\n\`\`\`${JSON.stringify(alert, null, 2)}\`\`\``,
//       }),
//     });
//   });
// }

module.exports = {};
