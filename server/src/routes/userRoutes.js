/**
 * userRoutes.js — User-level routes (data access + account deletion)
 *
 * All routes are JWT-protected via authMiddleware.
 * DELETE /delete has a separate stricter rate limiter.
 */

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Stricter rate limit for the destructive delete endpoint
// Protects against: brute-force password guessing via delete endpoint
const deleteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many delete attempts. Please try again in 1 hour.' },
});

// GET /api/user/me — GDPR Art. 15: Right of access
router.get('/me', authMiddleware, userController.getMe);

// DELETE /api/user/delete — GDPR Art. 17: Right to erasure (password-confirmed)
router.delete('/delete', authMiddleware, deleteLimiter, userController.deleteAccount);

module.exports = router;
