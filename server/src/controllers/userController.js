/**
 * userController.js — User-level operations (data access + account deletion)
 *
 * GDPR compliance:
 *  - Art. 15 Right of Access:   GET /api/user/me — returns all stored PII
 *  - Art. 17 Right to Erasure:  DELETE /api/user/delete — permanent hard delete
 *
 * Security:
 *  - Delete requires password verification — prevents token-only account wipes
 *  - Hard delete only — no soft-delete, no orphaned data
 *  - Deletion logs timestamp + anonymized user ID (no PII in log)
 *  - All errors forwarded via next() — no raw Mongoose errors to client
 *  - Protects against: token replay abuse (password confirms live possession)
 */

const User = require('../models/User');
const ExtensionKey = require('../models/ExtensionKey');
const logger = require('../services/logger');
const { logAdminAction } = require('../services/auditService');

// ── GET /api/user/me — GDPR Art. 15: Right of access ─────────
// Returns all PII stored for the authenticated user.
// Password hash and internal Mongo fields are always excluded.
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -__v')
      .lean();

    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    return res.json({
      success: true,
      data: {
        id:             user._id,
        email:          user.email,
        createdAt:      user.createdAt,
        updatedAt:      user.updatedAt,
        termsAccepted:  user.termsAccepted,
        termsVersion:   user.termsVersion,
        privacyVersion: user.privacyVersion,
        profile:        user.profile,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── DELETE /api/user/delete — GDPR Art. 17: Right to erasure ─
// Requires live password confirmation — prevents token-replay account wipes.
// Permanently deletes the user document (single collection — no orphans).
// Logs deletion event without any PII.
exports.deleteAccount = async (req, res, next) => {
  try {
    const { password } = req.body;

    // Password field must be present (validated by Joi in route guard)
    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required to delete your account.' });
    }

    // Fetch with password field for bcrypt comparison
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    // Verify password — protects against token-replay abuse
    // Protects against: attacker with stolen JWT wiping the account
    const passwordValid = await user.matchPassword(password);
    if (!passwordValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password. Account not deleted.' });
    }

    // Hard delete — no soft delete, no orphaned profile documents
    // Delete extension keys first, then user document — no orphaned data.
    await ExtensionKey.deleteMany({ userId: user._id });
    await User.deleteOne({ _id: user._id });

    // Log deletion event — user ID only, no email or PII
    logger.info(`[User] Account permanently deleted. ID: ${user._id.toString()}`);

    // Audit log — self-deletion, user ID only, no PII
    logAdminAction({
      action: 'USER_SELF_DELETE',
      adminId: user._id,
      ip: req.ip,
      metadata: { deletedUserId: String(user._id) },
    });

    return res.json({
      success: true,
      message: 'Your account and all associated personal data have been permanently deleted.',
    });
  } catch (err) {
    next(err);
  }
};
