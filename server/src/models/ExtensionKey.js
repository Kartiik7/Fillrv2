/**
 * ExtensionKey.js — Revocable, hashed extension secret key model
 *
 * Security architecture:
 *  - Raw key is NEVER stored — only a bcrypt hash (10 salt rounds).
 *  - keyId is a UUIDv4 used for identification (revoke/rotate) — not the key itself.
 *  - isActive flag enables instant revocation without deleting audit trail.
 *  - expiresAt enables automatic key expiry — extension must re-auth after.
 *  - Max 5 active keys per user — prevents multiple-device abuse.
 *
 * Protects against:
 *  - Key leakage:          Only bcrypt hash stored; raw key returned once at generation.
 *  - Multiple device abuse: MAX_KEYS_PER_USER = 5 limit enforced in controller.
 *  - Stale key reuse:      expiresAt check in auth flow; isActive revocation.
 *  - DB dump exposure:     bcrypt hashes resist offline brute force.
 */

const mongoose = require('mongoose');

const extensionKeySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  keyId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  hashedKey: {
    type: String,
    required: true,
  },
  // SHA-256 of raw key — used for fast O(1) lookup before bcrypt verification.
  // Not a substitute for bcrypt (bcrypt protects against offline DB dumps).
  // This simply narrows the search to 1 candidate key instead of scanning all keys.
  lookupHash: {
    type: String,
    index: true,
    default: null,
  },
  deviceName: {
    type: String,
    default: 'Chrome Extension',
    maxlength: 100,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  lastUsedAt: {
    type: Date,
    default: null,
  },
}, { timestamps: true });

// Compound index for legacy auth query (keys without lookupHash)
extensionKeySchema.index({ isActive: 1, expiresAt: 1 });
// Fast lookup index for new keys with lookupHash
extensionKeySchema.index({ lookupHash: 1, isActive: 1, expiresAt: 1 });
// userId index — used to list/count a user's keys quickly
extensionKeySchema.index({ userId: 1, isActive: 1 });

// Static: count active keys for a user (used by generation limit)
extensionKeySchema.statics.countActiveByUser = function (userId) {
  return this.countDocuments({ userId, isActive: true });
};

// Constants — exported for controller use
extensionKeySchema.statics.MAX_KEYS_PER_USER = 5;
extensionKeySchema.statics.KEY_VALIDITY_DAYS = 90;

module.exports = mongoose.model('ExtensionKey', extensionKeySchema);
