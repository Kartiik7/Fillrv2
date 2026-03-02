/**
 * adminMiddleware.js — Admin role enforcement
 *
 * Must be applied AFTER authMiddleware (req.user must be populated).
 *
 * Scope:
 *  - Gates all admin-specific routes
 *  - Does NOT grant access to passwords, JWT secrets, extension keys, or PII
 *
 * Protects against:
 *  - Horizontal privilege escalation: regular users cannot access admin routes
 *  - Token forgery: relies on authMiddleware's JWT verification first
 *
 * Future roles: to add 'moderator'/'superadmin', import ROLES and extend the check.
 */

const { ROLES } = require('../models/User');

module.exports = (req, res, next) => {
  // authMiddleware must run first — req.user is always set if we reach here.
  // isSuspended is already checked in authMiddleware — no need to repeat here.
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required.',
    });
  }

  if (req.user.role !== ROLES.ADMIN) {
    return res.status(403).json({
      success: false,
      message: 'Forbidden. Admin access required.',
    });
  }

  next();
};
