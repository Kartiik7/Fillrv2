/**
 * keyRoutes.js — Extension secret key management routes
 *
 * All routes require JWT authentication via authMiddleware.
 * Generate and rotate also require password confirmation (in controller).
 *
 * Protects against:
 *  - Unauthorized key management: JWT required for all routes
 *  - Key generation spam:         Stricter rate limiter (10 req/hr)
 *  - Multiple device abuse:       Max 5 active keys per user (enforced in controller)
 */

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const keyController  = require('../controllers/keyController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Stricter rate limit for key generation/rotation endpoints
// Protects against: key generation spam / denial-of-service via bcrypt cost
const keyGenLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many key operations. Please try again later.' },
});

// GET    /api/keys         — List all keys (metadata only, no secrets)
router.get('/',       authMiddleware, keyController.listKeys);

// POST   /api/keys/generate — Generate new extension key (password required)
router.post('/generate', authMiddleware, keyGenLimiter, keyController.generateKey);

// POST   /api/keys/rotate   — Rotate key(s) (password required)
router.post('/rotate',   authMiddleware, keyGenLimiter, keyController.rotateKey);

// POST   /api/keys/revoke   — Revoke a specific key
router.post('/revoke',   authMiddleware, keyController.revokeKey);

module.exports = router;
