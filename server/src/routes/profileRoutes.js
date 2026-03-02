/**
 * profileRoutes.js — Profile routes (all require valid JWT)
 *
 * Rate limiting:
 *  - GET endpoints: capped by global limiter (100/15min)
 *  - PUT /        : separate 20/15min to throttle repeated profile saves
 */

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const profileController = require('../controllers/profileController');
const authMiddleware    = require('../middleware/authMiddleware');

const router = express.Router();

// Prevent profile-update spam (accidental or adversarial rapid saves)
const profileUpdateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many profile updates. Please slow down.' },
});

// Core profile endpoints
router.get('/',  authMiddleware, profileController.getProfile);
router.put('/',  authMiddleware, profileUpdateLimiter, profileController.updateProfile);

// GDPR compliance endpoints
// GET  /api/profile/my-data  — Art. 15: Right of access
router.get('/my-data',  authMiddleware, profileController.getMyData);

module.exports = router;
