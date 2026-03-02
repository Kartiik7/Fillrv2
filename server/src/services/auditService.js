/**
 * auditService.js — Admin audit trail logger
 *
 * Creates audit log entries for admin actions.
 * Fire-and-forget — never blocks the main request.
 *
 * Security:
 *  - never logs passwords, JWTs, reset tokens, or full user objects
 *  - sanitizeMetadata() strips any key matching a sensitive-word pattern
 *  - metadata should contain only action-relevant identifiers (keys, counts) — never secrets
 *
 * Action naming convention: UPPER_SNAKE_CASE string constants
 *  e.g. 'FIELD_MAPPING_UPSERT', 'USER_ROLE_CHANGE', 'USER_SUSPEND_TOGGLE'
 */

const AuditLog = require('../models/AuditLog');
const logger   = require('./logger');

/**
 * Strips any key from metadata whose name contains sensitive words.
 * Protects against accidental logging of passwords, tokens, secrets, etc.
 * @param {Object} raw - Raw metadata object
 * @returns {Object} Sanitized metadata
 */
// Sensitive-word detection for audit metadata field names.
//
// Rules:
//   Strip if: fieldName itself, OR its first/last camelCase word, is sensitive.
//   Keep if: a sensitive word appears only in the MIDDLE (e.g. 'mappingKey' → keep 'mapping', strip 'key' as last).
//
// Examples:
//   hashedKey  → segments: [hashed, key]  → last='key'      → STRIP  ✓
//   resetToken → segments: [reset, token] → last='token'    → STRIP  ✓
//   jwtSecret  → segments: [jwt, secret]  → first='jwt'     → STRIP  ✓
//   password   → exact match              →                  → STRIP  ✓
//   mappingKey → segments: [mapping, key] → last='key'      → STRIP  ✓ (intentional—field refers to a key)
//   keywordCount → segments: [keyword, count] → last='count' → KEEP  ✓
//   targetUserId → segments: [target, user, id] → KEEP       → KEEP  ✓
const SENSITIVE_SEGMENTS = new Set([
  'password', 'token', 'secret', 'hash', 'jwt', 'credential', 'key',
]);

// Extract all lowercase word segments from a camelCase / PascalCase identifier.
// 'hashedKey'  → ['hashed', 'key']
// 'resetToken' → ['reset', 'token']
// 'targetUserId' → ['target', 'user', 'id']
const getCamelSegments = (str) => {
  // Insert space before each uppercase letter, then split
  const spaced = str.replace(/([A-Z])/g, '_$1').toLowerCase();
  return spaced.split('_').filter(Boolean);
};

const isSensitiveKey = (fieldName) => {
  const lower = fieldName.toLowerCase();
  if (SENSITIVE_SEGMENTS.has(lower)) return true; // exact match
  const segs = getCamelSegments(fieldName);
  if (segs.length === 0) return false;
  if (SENSITIVE_SEGMENTS.has(segs[0])) return true;               // first segment
  if (SENSITIVE_SEGMENTS.has(segs[segs.length - 1])) return true; // last segment
  return false;
};

const sanitizeMetadata = (raw = {}) => {
  if (typeof raw !== 'object' || Array.isArray(raw) || raw === null) return {};
  return Object.fromEntries(
    Object.entries(raw).filter(([k]) => !isSensitiveKey(k))
  );
};


/**
 * Create an audit log entry (fire-and-forget).
 * @param {Object} params
 * @param {string} params.action    - Action constant (e.g. 'FIELD_MAPPING_UPSERT')
 * @param {*}      params.adminId   - Admin user's ObjectId
 * @param {Object} [params.metadata] - Action-specific data (no secrets — enforced by sanitizer)
 * @param {string} [params.ip]      - Request IP address
 */
const createAuditLog = ({ action, adminId, metadata = {}, ip = '' }) => {
  if (!action || !adminId) return;

  AuditLog.create({
    action:   action.toUpperCase(),           // normalize to UPPER_SNAKE_CASE
    adminId,
    metadata: sanitizeMetadata(metadata),     // strip sensitive keys
    ip,
    createdAt: new Date(),
  }).catch((err) => {
    logger.error('[Audit] Failed to create audit log:', err.message);
  });
};

// logAdminAction is the preferred alias going forward (semantic name)
const logAdminAction = createAuditLog;

module.exports = { createAuditLog, logAdminAction };
