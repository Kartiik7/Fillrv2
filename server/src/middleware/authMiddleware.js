/**
 * authMiddleware.js — JWT verification middleware
 *
 * Protects against:
 *  - Unauthorized access:    Rejects requests without a valid Bearer token
 *  - Token replay:           jwt.verify checks expiry — expired tokens rejected
 *  - Password hash leakage:  .select('-password') never returns hash to handlers
 *  - Deleted-user tokens:    User.findById check ensures account still exists
 *  - Suspended user access:  isSuspended check blocks all protected routes
 */

const jwt  = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  // Reject immediately if header is absent or malformed
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Not authorized. No token provided.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verify signature + expiry in one call
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Confirm the account still exists — catches deleted-user token reuse
    // .lean() returns a plain object; no password field ever reaches handlers
    // resetPasswordHash, verificationTokenHash excluded via schema select: false
    const user = await User.findById(decoded.id)
      .select('-password -__v -resetPasswordHash -resetPasswordExpiry -verificationTokenHash -verificationTokenExpiry')
      .lean();

    if (!user) {
      return res.status(401).json({ success: false, message: 'Account not found. Please log in again.' });
    }

    // Block suspended accounts — applies to ALL protected routes (admin, profile, keys, etc.)
    if (user.isSuspended) {
      return res.status(403).json({ success: false, message: 'Account suspended. Contact support.' });
    }

    req.user = user;
    next();
  } catch (err) {
    // TokenExpiredError — give a specific, actionable message
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
    }
    // JsonWebTokenError, NotBeforeError, etc. — generic to avoid oracle
    return res.status(401).json({ success: false, message: 'Invalid token.' });
  }
};
