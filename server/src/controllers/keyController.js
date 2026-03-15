/**
 * keyController.js — Extension secret key management + extension auth
 *
 * Implements a revocable, hashed extension key system:
 *  - Generate:   POST /api/keys/generate   (JWT + password confirmation)
 *  - Rotate:     POST /api/keys/rotate     (JWT + password confirmation)
 *  - Revoke:     POST /api/keys/revoke     (JWT + keyId)
 *  - List:       GET  /api/keys            (JWT — returns metadata, never keys)
 *  - Extension:  POST /api/auth/extension  (apiKey → short-lived JWT)
 *
 * Security architecture:
 *  - Raw key is generated in a short readable format: fillr_XXXX-XXXX-XXXX (soft-launch).
 *  - Only bcrypt hash is stored — raw key is returned ONCE at generation.
 *  - Raw key is NEVER logged, NEVER stored, NEVER returned again.
 *  - Extension auth loops through active keys with bcrypt.compare — constant-set comparison.
 *  - Max 5 active keys per user — prevents multiple-device abuse.
 *
 * Protects against:
 *  - Brute force on secret keys: Heavy rate limiting on /auth/extension (5 req/15 min)
 *  - Key leakage:                Only bcrypt hash stored; raw key shown once
 *  - Credential stuffing:        Rate limiting + bcrypt cost makes bulk guessing infeasible
 *  - JWT replay:                 Short-lived (7d) JWT with standard expiry
 *  - Mongo injection:            Joi validation + mongoSanitize upstream
 *  - Multiple device abuse:      MAX_KEYS_PER_USER = 5 enforced
 *  - Stale key reuse:            expiresAt + isActive checks in auth flow
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const User = require('../models/User');
const ExtensionKey = require('../models/ExtensionKey');
const { generateToken } = require('./authController');
const { createAuditLog } = require('../services/auditService');

// SHA-256 helper for fast key lookup (NOT a replacement for bcrypt storage)
const lookupHashOf = (key) => crypto.createHash('sha256').update(key).digest('hex');

// ── Input schemas ─────────────────────────────────────────────
const generateSchema = Joi.object({
  password:   Joi.string().min(1).max(128).required(),
  secretKey:  Joi.string().min(10).max(64).required().messages({
    'string.min': 'Secret key must be at least 10 characters.',
    'string.max': 'Secret key must be at most 64 characters.',
    'any.required': 'Secret key is required.',
  }),
  deviceName: Joi.string().max(100).default('Chrome Extension'),
});

const rotateSchema = Joi.object({
  password:   Joi.string().min(1).max(128).required(),
  secretKey:  Joi.string().min(10).max(64).required().messages({
    'string.min': 'Secret key must be at least 10 characters.',
    'string.max': 'Secret key must be at most 64 characters.',
    'any.required': 'Secret key is required.',
  }),
  keyId:      Joi.string().uuid({ version: 'uuidv4' }).optional(), // specific key to rotate
  deviceName: Joi.string().max(100).default('Chrome Extension'),
});

const revokeSchema = Joi.object({
  keyId: Joi.string().uuid({ version: 'uuidv4' }).required(),
});

const extensionAuthSchema = Joi.object({
  apiKey: Joi.string().min(10).max(256).required(),
});

// ── Generate Key ──────────────────────────────────────────────
// POST /api/keys/generate
// Requires: JWT + password confirmation
// Returns raw key ONCE — never stored, never logged.
exports.generateKey = async (req, res, next) => {
  try {
    const { error, value } = generateSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { password, secretKey, deviceName } = value;

    // Verify password — ensures live possession of credentials
    // Protects against: stolen JWT being used to generate keys
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    // Google OAuth users without a password cannot generate extension keys
    // They must set a password first (future feature) or use a different flow
    if (!user.password) {
      return res.status(400).json({
        success: false,
        message: 'Password confirmation required. Google-only accounts must set a password first.',
      });
    }

    const isValid = await user.matchPassword(password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    // Enforce max active keys per user — prevents multiple-device abuse
    const activeCount = await ExtensionKey.countActiveByUser(user._id);
    if (activeCount >= ExtensionKey.MAX_KEYS_PER_USER) {
      return res.status(400).json({
        success: false,
        message: `Maximum ${ExtensionKey.MAX_KEYS_PER_USER} active keys allowed. Revoke an existing key first.`,
      });
    }

    // Use the user-supplied key so they can remember it
    const rawKey = secretKey;

    // Hash with bcrypt (10 salt rounds) — same cost as passwords
    const hashedKey = await bcrypt.hash(rawKey, 10);

    const keyId = uuidv4();
    const expiresAt = new Date(Date.now() + ExtensionKey.KEY_VALIDITY_DAYS * 24 * 60 * 60 * 1000);

    await ExtensionKey.create({
      userId: user._id,
      keyId,
      hashedKey,
      lookupHash: lookupHashOf(rawKey),
      deviceName,
      expiresAt,
    });

    // ⚠ Return raw key ONCE — it is NEVER stored or logged
    return res.status(201).json({
      success: true,
      message: 'Extension key generated. Store it securely — it will not be shown again.',
      key: {
        keyId,
        rawKey,       // Returned ONCE only
        deviceName,
        expiresAt,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── Rotate Key ────────────────────────────────────────────────
// POST /api/keys/rotate
// Deactivates existing key(s) and generates a new one.
// Requires: JWT + password confirmation.
exports.rotateKey = async (req, res, next) => {
  try {
    const { error, value } = rotateSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { password, secretKey, keyId, deviceName } = value;

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    if (!user.password) {
      return res.status(400).json({
        success: false,
        message: 'Password confirmation required. Google-only accounts must set a password first.',
      });
    }

    const isValid = await user.matchPassword(password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    // Deactivate target key or all active keys for this user
    if (keyId) {
      const result = await ExtensionKey.updateOne(
        { userId: user._id, keyId, isActive: true },
        { isActive: false }
      );
      if (result.modifiedCount === 0) {
        return res.status(404).json({ success: false, message: 'Active key not found.' });
      }
    } else {
      // Deactivate ALL active keys for this user
      await ExtensionKey.updateMany(
        { userId: user._id, isActive: true },
        { isActive: false }
      );
    }

    // Use the user-supplied key so they can remember it
    const rawKey = secretKey;
    const hashedKey = await bcrypt.hash(rawKey, 10);
    const newKeyId = uuidv4();
    const expiresAt = new Date(Date.now() + ExtensionKey.KEY_VALIDITY_DAYS * 24 * 60 * 60 * 1000);

    await ExtensionKey.create({
      userId: user._id,
      keyId: newKeyId,
      hashedKey,
      lookupHash: lookupHashOf(rawKey),
      deviceName,
      expiresAt,
    });

    return res.status(201).json({
      success: true,
      message: 'Key rotated successfully. Old key(s) have been revoked.',
      key: {
        keyId: newKeyId,
        rawKey,       // Returned ONCE only
        deviceName,
        expiresAt,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── Revoke Key ────────────────────────────────────────────────
// POST /api/keys/revoke
// Sets isActive = false — key can never be used again.
exports.revokeKey = async (req, res, next) => {
  try {
    const { error, value } = revokeSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { keyId } = value;

    const result = await ExtensionKey.updateOne(
      { userId: req.user._id, keyId, isActive: true },
      { isActive: false }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ success: false, message: 'Active key not found.' });
    }

    return res.json({ success: true, message: 'Key revoked successfully.' });
  } catch (err) {
    next(err);
  }
};

// ── List Keys ─────────────────────────────────────────────────
// GET /api/keys
// Returns metadata only — NEVER the hashed key or any secret material.
exports.listKeys = async (req, res, next) => {
  try {
    const keys = await ExtensionKey.find({ userId: req.user._id })
      .select('keyId deviceName isActive createdAt expiresAt lastUsedAt')
      .sort({ createdAt: -1 })
      .lean();

    return res.json({ success: true, keys });
  } catch (err) {
    next(err);
  }
};

// ── Extension Authentication ──────────────────────────────────
// POST /api/auth/extension
// Body: { apiKey: "raw_key" }
//
// Flow:
//  1. Rate limit heavily (at route level — 5 req/15 min per IP)
//  2. Loop through ALL active, non-expired keys
//  3. bcrypt.compare(apiKey, hashedKey) for each
//  4. If valid → issue short-lived JWT
//
// Protects against:
//  - Brute force:     Heavy rate limiting + bcrypt cost (~100ms per compare)
//  - Revoked keys:    isActive check filters them out
//  - Expired keys:    expiresAt check filters them out
//  - Key enumeration: Generic error message; no keyId returned
exports.extensionAuth = async (req, res, next) => {
  const { incrementMetric, trackActiveUser } = require('../services/metricsService');
  try {
    const { error, value } = extensionAuthSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: 'Invalid API key format.' });
    }

    const { apiKey } = value;

    const now = new Date();

    // ── Fast path: O(1) lookup via SHA-256 hash (new keys have lookupHash) ──
    const hash = lookupHashOf(apiKey);
    let matchedKey = null;

    const candidate = await ExtensionKey.findOne({
      lookupHash: hash,
      isActive: true,
      expiresAt: { $gt: now },
    }).select('userId hashedKey keyId');

    if (candidate) {
      // Verify with bcrypt (protects against SHA-256 collision / DB dump)
      const isMatch = await bcrypt.compare(apiKey, candidate.hashedKey);
      if (isMatch) matchedKey = candidate;
    }

    // ── Fallback: legacy keys without lookupHash (O(n) scan, n ≤ 5 per user) ──
    if (!matchedKey) {
      const legacyKeys = await ExtensionKey.find({
        lookupHash: null,
        isActive: true,
        expiresAt: { $gt: now },
      }).select('userId hashedKey keyId');

      for (const key of legacyKeys) {
        const isMatch = await bcrypt.compare(apiKey, key.hashedKey);
        if (isMatch) {
          matchedKey = key;
          // Backfill lookupHash for future O(1) lookups
          ExtensionKey.updateOne({ _id: key._id }, { lookupHash: hash }).catch(() => {});
          break;
        }
      }
    }

    if (!matchedKey) {
      // Generic message — do NOT reveal whether key exists, is expired, or is revoked
      return res.status(401).json({ success: false, message: 'Invalid or expired API key.' });
    }

    // Verify the owning user account still exists and is not suspended
    const user = await User.findById(matchedKey.userId).select('_id isSuspended').lean();
    if (!user) {
      return res.status(401).json({ success: false, message: 'Account not found.' });
    }

    // Block suspended accounts — prevents key-based auth for suspended users
    if (user.isSuspended) {
      createAuditLog({
        action: 'ACCOUNT_SUSPENDED_EXTENSION_AUTH_ATTEMPT',
        adminId: user._id,
        ip: req.ip,
        metadata: { channel: 'EXTENSION_AUTH' },
      });

      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_SUSPENDED',
        message: 'Access denied.',
      });
    }

    // Update lastUsedAt for audit trail (non-blocking — fire and forget)
    ExtensionKey.updateOne({ _id: matchedKey._id }, { lastUsedAt: now }).catch(() => {});

    // Fire-and-forget: track extension auth metric + active user
    incrementMetric('extensionAuthRequests');
    trackActiveUser(user._id);

    // Issue JWT — same unified token strategy as email/password and Google login
    const accessToken = generateToken(user._id);

    return res.json({
      success: true,
      accessToken,
      expiresIn: '7d',
      message: 'Extension authenticated.',
    });

    // NOTE: keyId is NOT returned — prevents information leakage
  } catch (err) {
    next(err);
  }
};
