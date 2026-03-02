/**
 * metricsService.js — Fire-and-forget metrics recording
 *
 * All functions:
 *  - Use $inc / $addToSet for atomic, non-blocking updates
 *  - Wrapped in try/catch — failures are logged, never thrown
 *  - Must NOT be awaited on the main request path (fire-and-forget)
 *  - Upsert ensures the daily document is auto-created
 *
 * Usage in controllers:
 *   const { incrementMetric, trackActiveUser } = require('../services/metricsService');
 *   incrementMetric('userRegistrations');          // fire-and-forget
 *   trackActiveUser(req.user._id);                // fire-and-forget
 */

const SystemMetric = require('../models/SystemMetric');
const LifetimeMetric = require('../models/LifetimeMetric');
const config  = require('../config/config');
const logger  = require('./logger');

const LIFETIME_KEY = 'global';

const DAILY_TO_LIFETIME_FIELD = Object.freeze({
  userRegistrations: 'registrations',
  loginRequests: 'logins',
  extensionAuthRequests: 'extensionAuthRequests',
  passwordResetRequests: 'passwordResetRequests',
  apiErrors: 'apiErrors',
});

/**
 * Get today's date as YYYY-MM-DD string.
 */
const todayStr = () => new Date().toISOString().slice(0, 10);

/**
 * Increment a numeric metric field for today.
 * @param {string} field - One of: userRegistrations, extensionAuthRequests,
 *                         passwordResetRequests, apiErrors, totalRequests
 */
const incrementMetric = (field) => {
  const allowed = config.metrics.allowedFields || [
    'userRegistrations',
    'loginRequests',
    'extensionAuthRequests',
    'passwordResetRequests',
    'apiErrors',
    'totalRequests',
  ];
  if (!allowed.includes(field)) return;

  SystemMetric.updateOne(
    { date: todayStr() },
    { $inc: { [field]: 1 } },
    { upsert: true }
  ).catch((err) => {
    logger.error(`[Metrics] Failed to increment ${field}:`, err.message);
  });

  const lifetimeField = DAILY_TO_LIFETIME_FIELD[field];
  if (!lifetimeField) return;

  LifetimeMetric.updateOne(
    { key: LIFETIME_KEY },
    { $inc: { [lifetimeField]: 1 }, $setOnInsert: { key: LIFETIME_KEY } },
    { upsert: true }
  ).catch((err) => {
    logger.error(`[Metrics] Failed to increment lifetime ${lifetimeField}:`, err.message);
  });
};

/**
 * Track an active user for today (deduplicated via $addToSet).
 * @param {string|ObjectId} userId
 */
const trackActiveUser = (userId) => {
  if (!userId) return;

  SystemMetric.updateOne(
    { date: todayStr() },
    { $addToSet: { activeUsers: userId } },
    { upsert: true }
  ).catch((err) => {
    logger.error('[Metrics] Failed to track active user:', err.message);
  });
};

/**
 * Shorthand: increment apiErrors for today.
 */
const incrementError = () => {
  SystemMetric.updateOne(
    { date: todayStr() },
    { $inc: { apiErrors: 1 }, $set: { lastApiErrorAt: new Date() } },
    { upsert: true }
  ).catch((err) => {
    logger.error('[Metrics] Failed to increment apiErrors:', err.message);
  });

  LifetimeMetric.updateOne(
    { key: LIFETIME_KEY },
    { $inc: { apiErrors: 1 }, $setOnInsert: { key: LIFETIME_KEY } },
    { upsert: true }
  ).catch((err) => {
    logger.error('[Metrics] Failed to increment lifetime apiErrors:', err.message);
  });
};

/**
 * Shorthand: increment totalRequests for today.
 */
const incrementRequest = () => {
  incrementMetric('totalRequests');
};

module.exports = {
  incrementMetric,
  trackActiveUser,
  incrementError,
  incrementRequest,
};
