/**
 * AuditLog.js — Admin action audit trail
 *
 * Records admin-initiated actions (field mapping CRUD, etc.)
 * for compliance and traceability.
 *
 * Security:
 *  - Never stores passwords, JWTs, reset tokens, or full user objects
 *  - metadata contains only action-relevant identifiers (e.g., mapping key)
 *  - Read only by admin via /api/admin/audit-logs
 */

const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    action: {
      type:      String,
      required:  true,
      maxlength: 100,
      uppercase: true,   // normalize to UPPER_SNAKE_CASE
    },
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    metadata: {
      type: Object,
      default: {},
    },
    ip: {
      type: String,
      maxlength: 45, // IPv6 max length
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { versionKey: false }
);

// Index on createdAt for efficient sorted queries + TTL if desired later
auditLogSchema.index({ createdAt: -1 });
// Index on adminId for efficient per-admin filtering
auditLogSchema.index({ adminId: 1 });
// Compound: filter by admin then sort by time (common admin audit log query)
auditLogSchema.index({ adminId: 1, createdAt: -1 });
// Index on action for filtering by action type
auditLogSchema.index({ action: 1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
