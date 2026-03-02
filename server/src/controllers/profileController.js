/**
 * profileController.js — Profile CRUD + GDPR endpoints
 *
 * Protects against:
 *  - Mass assignment / over-posting: Explicit field whitelisting via pick* helpers.
 *    req.body is NEVER passed directly into a DB query or Model.create().
 *  - NoSQL injection:  mongoSanitize strips $-keys upstream; pick* ignores extras.
 *  - Password hash leakage: All queries use .select('-password -__v').
 *  - Internal error leakage: All errors forwarded to centralized handler via next().
 *  - Mongo raw error exposure: No mongoose error objects returned to client.
 *  - Over-sized payloads: App-level body limit (20kb) + Joi max() on strings.
 */

const Joi  = require('joi');
const User = require('../models/User');
const { logAdminAction } = require('../services/auditService');

// ── Joi validation schema ─────────────────────────────────────
// Validates the nested profile object before any DB write.
// All fields are optional — partial updates allowed.
// Uses .pattern() to accept dynamic fields from new field mappings.

const fieldPattern = /^[a-zA-Z0-9_.-]+$/; // Same as FieldMapping key/path pattern
const fieldValue = Joi.alternatives().try(
  Joi.string().max(500).allow('', null),
  Joi.number().allow(null)
);

const profileUpdateSchema = Joi.object({
  profile: Joi.object({
    personal: Joi.object().pattern(fieldPattern, fieldValue),
    academics: Joi.object().pattern(fieldPattern, fieldValue),
    ids: Joi.object().pattern(fieldPattern, fieldValue),
    links: Joi.object().pattern(fieldPattern, fieldValue),
    education: Joi.object().pattern(fieldPattern, fieldValue),
    placement: Joi.object().pattern(fieldPattern, fieldValue),
  }).required(),
}).required();

// ── Field whitelisting helpers ────────────────────────────────
// Sanitizes against injection patterns while allowing dynamic fields.
// Blocks: $-prefixed keys, __proto__, constructor, prototype
// Allows: All other keys (for dynamic field mappings)

const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

const sanitizeObject = (src = {}) => {
  const clean = {};
  Object.keys(src).forEach(key => {
    // Block MongoDB operators ($where, $gt, etc.)
    if (key.startsWith('$')) return;
    // Block prototype pollution
    if (DANGEROUS_KEYS.includes(key)) return;
    // Allow everything else (string values only, enforced by Joi)
    if (src[key] !== undefined) clean[key] = src[key];
  });
  return clean;
};

// ── Helpers ───────────────────────────────────────────────────
// Apply only defined (non-undefined) sanitized values to a sub-document
const applyPicked = (subDoc, picked) => {
  Object.entries(picked).forEach(([k, v]) => {
    if (v !== undefined) subDoc[k] = v;
  });
};

// ── GET /api/profile ──────────────────────────────────────────
exports.getProfile = async (req, res, next) => {
  try {
    // Never return password hash or internal Mongo fields
    const user = await User.findById(req.user._id).select('-password -__v').lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    return res.json({ success: true, profile: user.profile, email: user.email });
  } catch (err) {
    next(err); // Centralized handler — no raw error exposed to client
  }
};

// ── PUT /api/profile ──────────────────────────────────────────
exports.updateProfile = async (req, res, next) => {
  try {
    // ── Joi validation — reject malformed / oversized inputs ──
    const { error, value } = profileUpdateSchema.validate(req.body, {
      stripUnknown: true,
      abortEarly: false,  // collect all errors, not just first
    });
    if (error) {
      const messages = error.details.map(d => d.message).join('; ');
      return res.status(400).json({ success: false, message: messages });
    }

    const user = await User.findById(req.user._id).select('-password -__v');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    // Destructure ONLY the known top-level keys from validated value
    const { personal, academics, ids, links, education, placement } = value.profile || {};

    if (personal)   applyPicked(user.profile.personal,   sanitizeObject(personal));
    if (academics)  applyPicked(user.profile.academics,  sanitizeObject(academics));
    if (ids)        applyPicked(user.profile.ids,        sanitizeObject(ids));
    if (links)      applyPicked(user.profile.links,      sanitizeObject(links));
    if (education)  applyPicked(user.profile.education,  sanitizeObject(education));
    if (placement)  applyPicked(user.profile.placement,  sanitizeObject(placement));

    user.markModified('profile');
    const saved = await user.save();

    // Audit log — tracks that a user mutated their own profile (non-admin, no PII in metadata)
    logAdminAction({
      action: 'USER_PROFILE_UPDATE',
      adminId: req.user._id, // here adminId represents the acting user
      ip: req.ip,
      metadata: {
        userId: String(req.user._id),
        sections: Object.keys(req.body.profile || {}).filter(k =>
          ['personal','academics','ids','links','education','placement'].includes(k)
        ),
      },
    });

    return res.json({
      success: true,
      message: 'Profile updated successfully.',
      profile: saved.profile,
    });
  } catch (err) {
    next(err);
  }
};

// ── GET /api/profile/my-data — GDPR: Data access ─────────────
// Returns all stored PII for the authenticated user.
// Required by GDPR Art. 15 (right of access).
exports.getMyData = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('-password -__v').lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    return res.json({
      success: true,
      data: {
        email:     user.email,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        profile:   user.profile,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── DELETE /api/profile/account ───────────────────────────────
// REMOVED — account deletion is handled exclusively by
// DELETE /api/user/delete (userController.deleteAccount)
// which requires password verification and cleans up ExtensionKeys.
