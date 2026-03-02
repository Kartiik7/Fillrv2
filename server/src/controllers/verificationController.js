/**
 * verificationController.js — Email verification for new accounts
 *
 * Flow:
 *  1. User registers → server sends verification email (async, non-blocking)
 *  2. User clicks link → GET /api/auth/verify-email?token=xxx
 *  3. Server verifies SHA-256 hash + expiry → sets isVerified = true
 *
 * Security:
 *  - 256-bit random token, stored as SHA-256 hash (same pattern as password reset)
 *  - 24-hour expiry — ample time for inbox delivery
 *  - Single-use — cleared after successful verification
 *  - Rate-limited resend endpoint (3 req / 15 min)
 *  - Anti-enumeration on resend — always returns generic message
 *
 * Environment variables:
 *  - RESEND_API_KEY, RESEND_FROM, FRONTEND_URL (shared with resetController)
 */

const crypto   = require('crypto');
const Joi      = require('joi');
const { Resend } = require('resend');
const User     = require('../models/User');
const logger   = require('../services/logger');

const HAS_RESEND_KEY = !!process.env.RESEND_API_KEY;
const resend  = new Resend(process.env.RESEND_API_KEY || '');

// ── Helpers ───────────────────────────────────────────────────
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const buildVerificationEmailHtml = (verifyUrl) => `
  <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px 24px;">
    <h2 style="color: #0f172a; font-size: 20px; margin-bottom: 8px;">Verify your email</h2>
    <p style="color: #475569; font-size: 14px; line-height: 1.6;">
      Welcome to Fillr! Click the button below to verify your email address and activate your account.
      This link expires in <strong>24 hours</strong>.
    </p>
    <a href="${verifyUrl}"
       style="display: inline-block; margin: 24px 0; padding: 12px 28px;
              background: #2563eb; color: #fff; font-size: 14px; font-weight: 600;
              text-decoration: none; border-radius: 8px;">
      Verify Email
    </a>
    <p style="color: #94a3b8; font-size: 12px; line-height: 1.6;">
      If you didn't create a Fillr account, you can safely ignore this email.
    </p>
    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">
    <p style="color: #cbd5e1; font-size: 11px;">Fillr — Placement Form Autofill</p>
  </div>
`;

/**
 * Send verification email asynchronously (fire-and-forget).
 * Mirrors the pattern from resetController — never blocks the HTTP response.
 *
 * @param {string} email
 * @param {string} verifyUrl
 */
const sendVerificationEmailAsync = async (email, verifyUrl) => {
  const masked = email.replace(/(.{2}).*(@.*)/, '$1***$2');

  if (!HAS_RESEND_KEY) {
    logger.debug('[Verify][NO-KEY] Verification link for %s: %s', masked, verifyUrl);
    logger.debug('[Verify][NO-KEY] Email NOT sent (RESEND_API_KEY not configured).');
    return;
  }

  logger.info('[Verify] Sending verification email to %s', masked);

  try {
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Email send timed out after 5 seconds')), 5000)
    );

    const result = await Promise.race([
      resend.emails.send({
        from:    process.env.RESEND_FROM || 'Fillr <onboarding@resend.dev>',
        to:      email,
        subject: 'Verify your Fillr email',
        html:    buildVerificationEmailHtml(verifyUrl),
      }),
      timeout,
    ]);

    if (result.error) {
      logger.error('[Verify] Resend API error for %s — %s', masked, result.error.message);
    } else {
      logger.info('[Verify] Email sent to %s — id: %s', masked, result.data?.id);
    }
  } catch (err) {
    logger.error('[Verify] Email delivery failed for %s — %s', masked, err.message);
  }
};

/**
 * Generate a verification token, save hash to user, and fire async email.
 * Called from authController.register after user creation.
 *
 * @param {Object} user - Mongoose User document
 */
exports.sendVerificationEmail = async (user) => {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const hashed   = hashToken(rawToken);
  const expiry   = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  user.verificationTokenHash   = hashed;
  user.verificationTokenExpiry = expiry;
  await user.save({ validateBeforeSave: false });

  const frontendUrl = process.env.FRONTEND_URL || 'https://fillr-placement-autofill.netlify.app';
  const verifyUrl   = `${frontendUrl}/verify-email.html?token=${rawToken}`;

  // Fire and forget — don't block registration response
  sendVerificationEmailAsync(user.email, verifyUrl).catch((err) => {
    logger.error('[Verify] Unexpected error in async email:', err.message);
  });
};

// ── GET /api/auth/verify-email ────────────────────────────────
// User clicks email link → token is verified → account activated.
exports.verifyEmail = async (req, res, next) => {
  try {
    const token = req.query.token;

    if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(400).json({ success: false, message: 'Invalid verification link.' });
    }

    const hashed = hashToken(token);

    const user = await User.findOne({
      verificationTokenHash:   hashed,
      verificationTokenExpiry: { $gt: new Date() },
    }).select('+verificationTokenHash +verificationTokenExpiry');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Verification link is invalid or has expired. Please request a new one.',
      });
    }

    // Activate account
    user.isVerified              = true;
    user.verificationTokenHash   = null;
    user.verificationTokenExpiry = null;
    await user.save({ validateBeforeSave: false });

    return res.json({ success: true, message: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    next(err);
  }
};

// ── POST /api/auth/resend-verification ─────────────────────────
// Resends verification email. Anti-enumeration: always returns generic message.
const resendSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).max(254).lowercase().required(),
});

exports.resendVerification = async (req, res, next) => {
  try {
    const { error, value } = resendSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const GENERIC_MSG = 'If an unverified account with that email exists, a verification link has been sent.';
    const { email } = value;

    const user = await User.findOne({ email, isVerified: false })
      .select('+verificationTokenHash +verificationTokenExpiry');

    if (!user) {
      return res.json({ success: true, message: GENERIC_MSG });
    }

    // Generate new token
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.verificationTokenHash   = hashToken(rawToken);
    user.verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await user.save({ validateBeforeSave: false });

    const frontendUrl = process.env.FRONTEND_URL || 'https://fillr-placement-autofill.netlify.app';
    const verifyUrl   = `${frontendUrl}/verify-email.html?token=${rawToken}`;

    res.json({ success: true, message: GENERIC_MSG });

    sendVerificationEmailAsync(email, verifyUrl).catch((err) => {
      logger.error('[Verify] Unexpected error in async resend:', err.message);
    });
  } catch (err) {
    next(err);
  }
};
