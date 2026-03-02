/**
 * config.js — Centralized application configuration constants
 *
 * All environment-dependent values should be read here once
 * and referenced throughout the codebase via this module.
 */

module.exports = {
  metrics: {
    /**
     * Whitelist of allowed metric field names for incrementMetric().
     * Prevents arbitrary field writes to the SystemMetric collection.
     */
    allowedFields: [
      'userRegistrations',
      'loginRequests',
      'extensionAuthRequests',
      'passwordResetRequests',
      'apiErrors',
      'totalRequests',
    ],
  },

  pagination: {
    /** Default page size for paginated admin endpoints */
    defaultLimit: 20,
    /** Maximum page size a client can request */
    maxLimit: 100,
  },

  token: {
    /** JWT access token expiry */
    jwtExpiry: process.env.JWT_EXPIRY || '7d',
    /** Verification / reset token byte length */
    tokenBytes: 32,
    /** Password reset token validity in ms (30 minutes) */
    resetExpiry: 30 * 60 * 1000,
    /** Email verification token validity in ms (24 hours) */
    verifyExpiry: 24 * 60 * 60 * 1000,
  },
};
