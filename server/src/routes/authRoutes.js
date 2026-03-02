/**
 * authRoutes.js — Authentication routes with stricter rate limiting
 *
 * Stricter limiter here than the global one:
 *  - Protects against: brute force login, credential stuffing, registration spam
 *  - skipSuccessfulRequests: only counts failed attempts — legit users unaffected
 *
 * Extension auth has its own even stricter limiter:
 *  - 5 requests per 15 minutes — bcrypt cost (~100ms) + rate limit makes
 *    brute force on secret keys computationally infeasible.
 */

const express   = require('express');
const rateLimit = require('express-rate-limit');
const authController  = require('../controllers/authController');
const keyController   = require('../controllers/keyController');
const resetController = require('../controllers/resetController');
const verificationController = require('../controllers/verificationController');

const router = express.Router();

// Stricter auth-specific rate limit — 10 failed attempts per 15 min per IP
// Protects against: credential stuffing, brute force, registration spam
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Only count failures — benign users unaffected
  message: { success: false, message: 'Too many attempts. Please try again in 15 minutes.' },
});

// Extreme rate limit for extension key auth — 5 requests per 15 min per IP
// Protects against: brute force on secret keys
// bcrypt comparison (~100ms per key × up to 5 keys) makes each attempt expensive.
const extensionAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many extension auth attempts. Please try again later.' },
});

// Email/Password auth
router.post('/register', authLimiter, authController.register);
router.post('/login',    authLimiter, authController.login);

// Google OAuth
router.post('/google',   authLimiter, authController.googleLogin);

// Extension secret key auth
router.post('/extension', extensionAuthLimiter, keyController.extensionAuth);

// ── Password reset ────────────────────────────────────────────
// Tight rate limits — prevents token generation spam and brute force.
// forgot: 3 req / 15 min (email flood prevention)
// reset:  5 req / 15 min (token brute-force prevention)
const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many reset requests. Please try again later.' },
});
const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many attempts. Please try again later.' },
});
router.post('/forgot-password', forgotLimiter, resetController.forgotPassword);
router.post('/reset-password',  resetLimiter,  resetController.resetPassword);

// ── Email verification ────────────────────────────────────────
// verify:  GET — user clicks link in email, token in query param
// resend:  POST — user requests new verification email
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many verification requests. Please try again later.' },
});
router.get('/verify-email',           verificationController.verifyEmail);
router.post('/resend-verification', verifyLimiter, verificationController.resendVerification);

module.exports = router;
