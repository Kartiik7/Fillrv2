/**
 * adminRoutes.js — Admin-only management routes
 *
 * All routes require: authMiddleware + requireAdmin (applied via router.use)
 * Rate limited separately from global limiter (30 req / 15 min per IP).
 *
 * ── Field Mappings ────────────────────────────────────────────
 *  POST   /api/admin/field-mappings         Create or upsert a field mapping
 *  DELETE /api/admin/field-mappings/:key    Delete a field mapping by key
 *
 * ── User Management ───────────────────────────────────────────
 *  GET    /api/admin/users                  List users (no PII beyond email)
 *  PATCH  /api/admin/users/:id/role         Change a user's role (self-protection)
 *  PATCH  /api/admin/users/:id/suspend      Toggle isSuspended (self-protection)
 *  DELETE /api/admin/users/:id              Hard-delete user (self-delete guard)
 *
 * ── Metrics & Audit ───────────────────────────────────────────
 *  GET    /api/admin/metrics/summary        Dashboard metrics (daily/weekly/total)
 *  GET    /api/admin/audit-logs             Paginated audit log (newest first)
 *  GET    /api/admin/mappings/debug-match   Mapping quality debugger (admin-only)
 *
 * Security:
 *  - Joi validation on all inputs (no dynamic code, no regex injection)
 *  - Keyword strings: no $, {, }, \ — prevents injection patterns
 *  - primary: 1–30 entries (required); secondary/negative: 0–20; generic: 0–10
 *  - key/path: max 100 chars, alphanumeric + dots/underscores/hyphens only
 *  - Role can ONLY be changed via PATCH /api/admin/users/:id/role — never from
 *    registration, profile update, or any other public route
 *  - Admin cannot delete, demote, or suspend themselves
 *  - All actions audit-logged (fire-and-forget) with UPPER_SNAKE_CASE action names
 *  - No PII, JWT, passwords, or tokens in metadata
 *  - Rate limited: 30 req / 15 min per IP
 *  - No eval, no Function constructor, no dynamic execution
 */

const express          = require('express');
const Joi              = require('joi');
const rateLimit        = require('express-rate-limit');
const mongoose         = require('mongoose');
const authMiddleware   = require('../middleware/authMiddleware');
const requireAdmin     = require('../middleware/adminMiddleware');
const FieldMapping     = require('../models/FieldMapping');
const ConfigVersion    = require('../models/ConfigVersion');
const SystemMetric     = require('../models/SystemMetric');
const LifetimeMetric   = require('../models/LifetimeMetric');
const AuditLog         = require('../models/AuditLog');
const User             = require('../models/User');
const ExtensionKey     = require('../models/ExtensionKey');
const { ROLES }        = require('../models/User');
const { logAdminAction } = require('../services/auditService');
const logger             = require('../services/logger');

const router = express.Router();

// ── Rate limiter for admin routes ─────────────────────────────
// Stricter than global — 30 requests per 15 minutes per IP
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many admin requests. Try again later.' },
});

// Apply rate limiter + auth + admin check to ALL routes in this router
router.use(adminLimiter);
router.use(authMiddleware, requireAdmin);

// ── Action constants (UPPER_SNAKE_CASE) ───────────────────────
const ACTIONS = Object.freeze({
  FIELD_MAPPING_UPSERT:   'FIELD_MAPPING_UPSERT',
  FIELD_MAPPING_DELETE:   'FIELD_MAPPING_DELETE',
  USER_ROLE_CHANGE:       'USER_ROLE_CHANGE',
  USER_SUSPEND_TOGGLE:    'USER_SUSPEND_TOGGLE',
  USER_DELETE:            'USER_DELETE',
  ADMIN_SELF_MODIFICATION_BLOCKED: 'ADMIN_SELF_MODIFICATION_BLOCKED',
});

const blockedAdminModification = (req, res, metadata) => {
  logAdminAction({
    action: ACTIONS.ADMIN_SELF_MODIFICATION_BLOCKED,
    adminId: req.user._id,
    ip: req.ip,
    metadata,
  });

  return res.status(403).json({
    success: false,
    code: 'ADMIN_SELF_MODIFICATION_BLOCKED',
    message: 'Action blocked.',
  });
};

// ── Joi schemas ───────────────────────────────────────────────
// key/path: alphanumeric + dots, underscores, hyphens (no special chars)
const KEY_PATTERN = /^[a-zA-Z0-9._-]+$/;
// Keyword string: no $, {, }, \ — prevents injection patterns
const kwItem = Joi.string().trim().max(100).pattern(/^[^${}\\]+$/);

const fieldMappingSchema = Joi.object({
  key: Joi.string()
    .trim()
    .max(100)
    .pattern(KEY_PATTERN)
    .required()
    .messages({
      'string.pattern.base': 'key must contain only letters, numbers, dots, underscores, or hyphens.',
    }),
  path: Joi.string()
    .trim()
    .max(100)
    .pattern(KEY_PATTERN)
    .required()
    .messages({
      'string.pattern.base': 'path must contain only letters, numbers, dots, underscores, or hyphens.',
    }),
  fieldType: Joi.string()
    .valid('text', 'number', 'date', 'email', 'tel', 'url', 'textarea', 'select')
    .default('text'),
  // High-confidence labels (required, 1–30)
  primary: Joi.array().items(kwItem).min(1).max(30).required()
    .messages({ 'array.min': 'At least one primary keyword is required.' }),
  // Optional categories
  secondary: Joi.array().items(kwItem).max(20).default([]),
  generic:   Joi.array().items(kwItem).max(10).default([]),
  negative:  Joi.array().items(kwItem).max(20).default([]),
});

const deleteParamSchema = Joi.object({
  key: Joi.string()
    .trim()
    .max(100)
    .pattern(KEY_PATTERN)
    .required()
    .messages({
      'string.pattern.base': 'key must contain only letters, numbers, dots, underscores, or hyphens.',
    }),
});

const userIdParamSchema = Joi.object({
  id: Joi.string()
    .trim()
    .custom((value, helpers) => {
      if (!mongoose.isValidObjectId(value)) {
        return helpers.error('any.invalid');
      }
      return value;
    })
    .required()
    .messages({ 'any.invalid': 'Invalid user ID.' }),
});

const roleChangeSchema = Joi.object({
  // role must be a valid ROLES value — enum driven from the single-source constant
  role: Joi.string()
    .valid(...Object.values(ROLES))
    .required()
    .messages({
      'any.only': `role must be one of: ${Object.values(ROLES).join(', ')}`,
    }),
});

const mappingDebugQuerySchema = Joi.object({
  label: Joi.string().trim().max(200).required(),
});

const normalizeLabel = (text) => {
  if (!text) return '';
  return String(text)
    .toLowerCase()
    .replace(/\bclass\s+xii\b/g, 'class 12')
    .replace(/\bclass\s+x\b/g, 'class 10')
    .replace(/\bxiith\b/g, '12th')
    .replace(/\bxth\b/g, '10th')
    .replace(/\bxii\b/g, '12')
    .replace(/\bx\b/g, '10')
    .replace(/\bgrad\.?(?=[^a-z]|$)/g, 'graduation')
    .replace(/%/g, ' percentage ')
    .replace(/[\/\-]/g, ' ')
    .replace(/[^a-z0-9 ]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
};

const tokenize = (text) => {
  if (!text) return [];
  return normalizeLabel(text).split(' ').filter((token) => token.length > 0);
};

const preprocessKeywords = (arr) => (
  (Array.isArray(arr) ? arr : []).map((kw) => tokenize(String(kw)))
);

const calculateAdvancedScore = (tokens, config) => {
  const {
    primary = [],
    secondary = [],
    generic = [],
    negative = [],
  } = config;

  let score = 0;

  primary.forEach((kwTokens) => {
    if (kwTokens.every((token) => tokens.includes(token))) score += 5;
  });
  secondary.forEach((kwTokens) => {
    if (kwTokens.every((token) => tokens.includes(token))) score += 3;
  });
  generic.forEach((kwTokens) => {
    if (kwTokens.every((token) => tokens.includes(token))) score += 1;
  });
  negative.forEach((kwTokens) => {
    if (kwTokens.every((token) => tokens.includes(token))) score -= 5;
  });

  score = Math.max(0, score);
  const maxPossibleScore = primary.length * 5 + secondary.length * 3 + generic.length;
  const confidence = maxPossibleScore > 0 ? score / maxPossibleScore : 0;

  return { score, confidence };
};

const asPositiveInt = (value, fallback, min = 1, max = 50) => {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
};

const formatVersionString = (rawVersion) => {
  const num = Number.parseInt(rawVersion, 10);
  if (!Number.isFinite(num) || num <= 0) return 'v2.0.0';
  return `v${num}.0.0`;
};

// ── GET /api/admin/field-mappings ─────────────────────────────
// Returns full array with updatedAt — for the admin editor UI.
// Unlike the public config route (GET /api/config/field-mappings), this
// returns updatedAt and is sorted by most recently updated.
// Arrays are explicitly normalised (‖ []) so lean() missing fields never
// reach the client as undefined.
router.get('/field-mappings', async (_req, res) => {
  try {
    const raw = await FieldMapping.find({})
      .select('-_id key path fieldType primary secondary generic negative updatedAt')
      .sort({ updatedAt: -1 })
      .lean();

    const mappings = raw.map(m => ({
      key:       m.key,
      path:      m.path,
      fieldType: m.fieldType || 'text',
      primary:   m.primary   || [],
      secondary: m.secondary || [],
      generic:   m.generic   || [],
      negative:  m.negative  || [],
      updatedAt: m.updatedAt,
    }));

    res.json({ success: true, mappings, total: mappings.length });
  } catch (err) {
    logger.error('[adminRoutes] GET field-mappings error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load field mappings.' });
  }
});

// ── GET /api/admin/mappings/debug-match?label=... ───────────
// Admin-only mapping debugger for scoring quality checks.
router.get('/mappings/debug-match', async (req, res) => {
  const { error, value } = mappingDebugQuerySchema.validate(req.query, { stripUnknown: true });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  try {
    const mappings = await FieldMapping.find({})
      .select('key primary secondary generic negative')
      .lean();

    const inputTokens = tokenize(value.label);

    let topKey = null;
    let topScore = 0;
    let topConfidence = 0;

    mappings.forEach((mapping) => {
      const config = {
        primary: preprocessKeywords(mapping.primary),
        secondary: preprocessKeywords(mapping.secondary),
        generic: preprocessKeywords(mapping.generic),
        negative: preprocessKeywords(mapping.negative),
      };

      const result = calculateAdvancedScore(inputTokens, config);
      if (result.score > topScore) {
        topKey = mapping.key;
        topScore = result.score;
        topConfidence = result.confidence;
      }
    });

    res.json({
      success: true,
      input: value.label,
      topMatch: topKey,
      score: topScore,
      confidence: Number((topConfidence * 100).toFixed(2)),
    });
  } catch (err) {
    logger.error('[adminRoutes] GET mappings/debug-match error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to debug mapping match.' });
  }
});

// ── POST /api/admin/field-mappings ────────────────────────────
// Create new or overwrite existing mapping (upsert by key).
router.post('/field-mappings', async (req, res) => {
  const { error, value } = fieldMappingSchema.validate(req.body, { stripUnknown: true });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  try {
    const existing = await FieldMapping.findOne({ key: value.key }).select('_id').lean();

    const mapping = await FieldMapping.findOneAndUpdate(
      { key: value.key },
      {
        key:       value.key,
        path:      value.path,
        fieldType: value.fieldType || 'text',
        primary:   value.primary,
        secondary: value.secondary,
        generic:   value.generic,
        negative:  value.negative,
        updatedAt: new Date(),
      },
      { upsert: true, new: true, runValidators: true }
    );

    // Bump config version only for newly created mappings, not edits.
    if (!existing) {
      await ConfigVersion.bump();
    }

    // Audit log (fire-and-forget)
    logAdminAction({
      action:   ACTIONS.FIELD_MAPPING_UPSERT,
      adminId:  req.user._id,
      ip:       req.ip,
      metadata: {
        fieldId:        value.key,
        path:           value.path,
        primaryCount:   value.primary.length,
        secondaryCount: value.secondary.length,
        genericCount:   value.generic.length,
        negativeCount:  value.negative.length,
      },
    });

    res.json({
      success: true,
      message: `Field mapping '${value.key}' saved.`,
      mapping: {
        key:       mapping.key,
        path:      mapping.path,
        primary:   mapping.primary,
        secondary: mapping.secondary,
        generic:   mapping.generic,
        negative:  mapping.negative,
      },
    });
  } catch (err) {
    logger.error('[adminRoutes] POST field-mappings error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to save field mapping.' });
  }
});

// ── DELETE /api/admin/field-mappings/:key ─────────────────────
router.delete('/field-mappings/:key', async (req, res) => {
  const { error, value } = deleteParamSchema.validate(req.params, { stripUnknown: true });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  try {
    const result = await FieldMapping.findOneAndDelete({ key: value.key });
    if (!result) {
      return res.status(404).json({ success: false, message: `No mapping found for key '${value.key}'.` });
    }

    await ConfigVersion.bump();

    // Audit log (fire-and-forget)
    logAdminAction({
      action:   ACTIONS.FIELD_MAPPING_DELETE,
      adminId:  req.user._id,
      ip:       req.ip,
      metadata: { fieldId: value.key },
    });

    res.json({ success: true, message: `Field mapping '${value.key}' deleted.` });
  } catch (err) {
    logger.error('[adminRoutes] DELETE field-mappings error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete field mapping.' });
  }
});

// ── GET /api/admin/users ──────────────────────────────────────
// Returns a list of users with safe, non-PII fields only.
// No passwords, tokens, reset hashes, or ObjectId arrays exposed.
// Supports pagination: ?page=1&limit=20
router.get('/users', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page,  10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip  = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find()
        .select('email role isSuspended createdAt authProvider')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(),
    ]);

    res.json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      users,
    });
  } catch (err) {
    logger.error('[adminRoutes] GET users error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch users.' });
  }
});

// ── PATCH /api/admin/users/:id/role ──────────────────────────
// Change a user's role. Self-protection: admin cannot change their own role.
// Role is ONLY settable here — never from registration or profile update.
router.patch('/users/:id/role', async (req, res) => {
  // Validate ID
  const paramResult = userIdParamSchema.validate(req.params, { stripUnknown: true });
  if (paramResult.error) {
    return res.status(400).json({ success: false, message: paramResult.error.details[0].message });
  }

  // Validate new role
  const bodyResult = roleChangeSchema.validate(req.body, { stripUnknown: true });
  if (bodyResult.error) {
    return res.status(400).json({ success: false, message: bodyResult.error.details[0].message });
  }

  const targetId = paramResult.value.id;
  const newRole  = bodyResult.value.role;

  // Self-protection: admin cannot change their own role (prevents accidental self-demotion)
  if (String(req.user._id) === targetId) {
    return blockedAdminModification(req, res, {
      operation: 'ROLE_CHANGE',
      reason: 'SELF_MODIFICATION',
      targetUserId: targetId,
      attemptedRole: newRole,
    });
  }

  try {
    const target = await User.findById(targetId).select('role email').lean();
    if (!target) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const previousRole = target.role;

    await User.updateOne({ _id: targetId }, { role: newRole });

    // Audit log (fire-and-forget)
    logAdminAction({
      action:   ACTIONS.USER_ROLE_CHANGE,
      adminId:  req.user._id,
      ip:       req.ip,
      metadata: { targetUserId: targetId, previousRole, newRole },
    });

    res.json({ success: true, message: `User role updated to '${newRole}'.` });
  } catch (err) {
    logger.error('[adminRoutes] PATCH users/:id/role error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to update user role.' });
  }
});

// ── PATCH /api/admin/users/:id/suspend ───────────────────────
// Toggle isSuspended for a user.
// Self-protection: admin cannot suspend themselves.
router.patch('/users/:id/suspend', async (req, res) => {
  const { error, value } = userIdParamSchema.validate(req.params, { stripUnknown: true });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  const targetId = value.id;

  // Self-protection: admin cannot suspend themselves
  if (String(req.user._id) === targetId) {
    return res.status(403).json({ success: false, message: 'You cannot suspend your own account.' });
  }

  try {
    const target = await User.findById(targetId).select('isSuspended email').lean();
    if (!target) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const newSuspendedState = !target.isSuspended;
    await User.updateOne({ _id: targetId }, { isSuspended: newSuspendedState });

    // Audit log (fire-and-forget)
    logAdminAction({
      action:   ACTIONS.USER_SUSPEND_TOGGLE,
      adminId:  req.user._id,
      ip:       req.ip,
      metadata: { targetUserId: targetId, isSuspended: newSuspendedState },
    });

    const stateLabel = newSuspendedState ? 'suspended' : 'unsuspended';
    res.json({ success: true, message: `User ${stateLabel} successfully.`, isSuspended: newSuspendedState });
  } catch (err) {
    logger.error('[adminRoutes] PATCH users/:id/suspend error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to update suspension status.' });
  }
});

// ── DELETE /api/admin/users/:id ───────────────────────────────
// Hard-delete a user account.
// Self-protection: admin cannot delete their own account.
router.delete('/users/:id', async (req, res) => {
  const { error, value } = userIdParamSchema.validate(req.params, { stripUnknown: true });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  const targetId = value.id;

  // Self-protection: admin cannot delete themselves
  if (String(req.user._id) === targetId) {
    return blockedAdminModification(req, res, {
      operation: 'USER_DELETE',
      reason: 'SELF_MODIFICATION',
      targetUserId: targetId,
    });
  }

  try {
    const target = await User.findById(targetId).select('email role').lean();
    if (!target) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    if (target.role === ROLES.ADMIN) {
      const adminCount = await User.countDocuments({ role: ROLES.ADMIN });
      if (adminCount <= 1) {
        return blockedAdminModification(req, res, {
          operation: 'USER_DELETE',
          reason: 'LAST_ADMIN_DELETE_BLOCKED',
          targetUserId: targetId,
        });
      }
    }

    await User.deleteOne({ _id: targetId });

    // Audit log (fire-and-forget)
    logAdminAction({
      action:   ACTIONS.USER_DELETE,
      adminId:  req.user._id,
      ip:       req.ip,
      metadata: { targetUserId: targetId, deletedRole: target.role },
    });

    res.json({ success: true, message: 'User deleted successfully.' });
  } catch (err) {
    logger.error('[adminRoutes] DELETE users/:id error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete user.' });
  }
});

// ── GET /api/admin/metrics/summary ────────────────────────────
// Returns daily (today), weekly (rolling 7 days), and total (lifetime) metrics.
// No PII exposed — activeUsers count only, no IDs.
router.get('/metrics/summary', async (_req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

    // ── Daily: today's document ────────────────────────────
    const todayMetric = await SystemMetric.findOne({ date: today }).lean();

    // ── Weekly: rolling last 7 days ────────────────────────
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const weekKey = sevenDaysAgo.toISOString().slice(0, 10);

    const weeklyAgg = await SystemMetric.aggregate([
      { $match: { date: { $gte: weekKey } } },
      {
        $group: {
          _id: null,
          registrations:     { $sum: '$userRegistrations' },
          logins:            { $sum: '$loginRequests' },
          extensionAuth:     { $sum: '$extensionAuthRequests' },
          passwordResets:    { $sum: '$passwordResetRequests' },
          errors:            { $sum: '$apiErrors' },
          activeUsersNested: { $addToSet: '$activeUsers' },
        },
      },
    ]);

    const weeklyRaw = weeklyAgg[0] || {
      registrations: 0, logins: 0, extensionAuth: 0,
      passwordResets: 0, errors: 0, activeUsersNested: [],
    };

    // Flatten nested arrays from $addToSet of arrays → unique count
    const weeklyActiveCount = new Set(
      (weeklyRaw.activeUsersNested || []).flat().map(String)
    ).size;

    // ── Total: singleton lifetime document ────────────────
    const lifetime = await LifetimeMetric.findOne({ key: 'global' }).lean();

    // Total registered users count — numeric only, no IDs or PII
    const totalUsers = await User.countDocuments();

    res.json({
      success: true,
      totalUsers,
      daily: {
        registrations:  todayMetric?.userRegistrations     || 0,
        logins:         todayMetric?.loginRequests          || 0,
        extensionAuth:  todayMetric?.extensionAuthRequests  || 0,
        passwordResets: todayMetric?.passwordResetRequests  || 0,
        errors:         todayMetric?.apiErrors              || 0,
        activeUsers:    todayMetric?.activeUsers?.length    || 0,
      },
      weekly: {
        registrations:  weeklyRaw.registrations,
        logins:         weeklyRaw.logins,
        extensionAuth:  weeklyRaw.extensionAuth,
        passwordResets: weeklyRaw.passwordResets,
        errors:         weeklyRaw.errors,
        activeUsers:    weeklyActiveCount,
      },
      total: {
        registrations:  lifetime?.registrations || 0,
        logins:         lifetime?.logins || 0,
        extensionAuth:  lifetime?.extensionAuthRequests || 0,
        passwordResets: lifetime?.passwordResetRequests || 0,
        errors:         lifetime?.apiErrors || 0,
      },
    });
  } catch (err) {
    logger.error('[adminRoutes] GET metrics/summary error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch metrics.' });
  }
});

// ── GET /api/admin/system-health ─────────────────────────────
// Returns today's API health metrics (numeric only; no stack traces/paths).
router.get('/system-health', async (_req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const todayMetric = await SystemMetric.findOne({ date: today })
      .select('apiErrors totalRequests extensionAuthRequests loginRequests lastApiErrorAt')
      .lean();

    const apiErrorsToday = todayMetric?.apiErrors || 0;
    const totalRequestsToday = todayMetric?.totalRequests || 0;
    const extensionAuthRequestsToday = todayMetric?.extensionAuthRequests || 0;
    const loginRequestsToday = todayMetric?.loginRequests || 0;

    const fallbackDenominator = extensionAuthRequestsToday + loginRequestsToday;
    const denominator = totalRequestsToday > 0 ? totalRequestsToday : fallbackDenominator;
    const errorRateToday = denominator > 0
      ? Number(((apiErrorsToday / denominator) * 100).toFixed(2))
      : 0;

    res.json({
      success: true,
      data: {
        apiErrorsToday,
        totalRequestsToday,
        extensionAuthRequestsToday,
        loginRequestsToday,
        errorRateToday,
        lastApiErrorTimestamp: todayMetric?.lastApiErrorAt || null,
      },
    });
  } catch (err) {
    logger.error('[adminRoutes] GET system-health error:', err.message);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// ── GET /api/admin/security-summary ──────────────────────────
// Numeric security/access summaries only. No sensitive payloads.
router.get('/security-summary', async (_req, res) => {
  try {
    const [activeAdminCount, totalSecretKeysIssued, revokedSecretKeysCount] = await Promise.all([
      User.countDocuments({ role: ROLES.ADMIN, isSuspended: false }),
      ExtensionKey.countDocuments(),
      ExtensionKey.countDocuments({ isActive: false }),
    ]);

    res.json({
      success: true,
      data: {
        activeAdminCount,
        totalSecretKeysIssued,
        revokedSecretKeysCount,
        suspiciousAuthAttemptsTracked: false,
        suspiciousAuthAttempts: null,
      },
    });
  } catch (err) {
    logger.error('[adminRoutes] GET security-summary error:', err.message);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// ── GET /api/admin/audit?limit=5 ─────────────────────────────
// Returns most recent admin actions with action + timestamp only.
router.get('/audit', async (req, res) => {
  try {
    const limit = asPositiveInt(req.query.limit, 5, 1, 50);
    const logs = await AuditLog.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .select('action createdAt')
      .lean();

    const items = logs.map((log) => ({
      action: log.action,
      createdAt: log.createdAt,
    }));

    res.json({
      success: true,
      data: { items, count: items.length },
    });
  } catch (err) {
    logger.error('[adminRoutes] GET audit error:', err.message);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// ── GET /api/admin/config/version ────────────────────────────
// Returns expected extension config version in display-ready format.
router.get('/config/version', async (_req, res) => {
  try {
    const config = await ConfigVersion.current();
    res.json({
      success: true,
      data: {
        version: formatVersionString(config.version),
        numericVersion: config.version,
        updatedAt: config.updatedAt,
      },
    });
  } catch (err) {
    logger.error('[adminRoutes] GET config/version error:', err.message);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// ── GET /api/admin/audit-logs ─────────────────────────────────
// Paginated audit log. Query params: page (default 1), limit (default 20, max 50).
// adminId is an ObjectId (legitimate traceability field — visible only to admins).
router.get('/audit-logs', async (req, res) => {
  try {
    const page = asPositiveInt(req.query.page, 1, 1, Number.MAX_SAFE_INTEGER);
    const limit = asPositiveInt(req.query.limit, 20, 1, 50);
    const skip  = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      AuditLog.find()
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('action adminId metadata ip createdAt')
        .lean(),
      AuditLog.countDocuments(),
    ]);

    res.json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      logs,
    });
  } catch (err) {
    logger.error('[adminRoutes] GET audit-logs error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch audit logs.' });
  }
});

module.exports = router;
