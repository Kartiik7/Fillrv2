/**
 * server.js — Application entry point
 *
 * Startup guards:
 *  - Fails fast if any required env var is missing
 *  - Fails fast if JWT_SECRET is too short (< 32 chars)
 *  - Catches unhandled rejections / exceptions without crashing silently
 */

require('dotenv').config();

const logger  = require('./src/services/logger');
const app     = require('./src/app');
const connectDB = require('./src/config/db');

const isProd = process.env.NODE_ENV === 'production';
const PORT   = process.env.PORT || 5000;

// ── Startup environment guards ────────────────────────────────
// Single consolidated check: fail fast with a clear message per variable.
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET'];
for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    logger.error(`[FATAL] Missing required environment variable: ${varName}`);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  logger.error('[FATAL] JWT_SECRET must be at least 32 characters long.');
  process.exit(1);
}

if (!process.env.GOOGLE_CLIENT_ID) {
  logger.warn('GOOGLE_CLIENT_ID is not set. Google OAuth login will not work.');
}

// ── Graceful unhandled error handling ───────────────────────
// Prevents silent failures and uncontrolled crashes
process.on('unhandledRejection', (reason) => {
  logger.error('[Server] Unhandled Rejection:', isProd ? String(reason?.message || reason) : reason);
});

process.on('uncaughtException', (err) => {
  logger.error('[Server] Uncaught Exception:', isProd ? err.message : err);
  process.exit(1);
});

// ── Start ─────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, () => {
    logger.info(`[Server] Running on http://localhost:${PORT} [${process.env.NODE_ENV || 'development'}]`);
  });
});
