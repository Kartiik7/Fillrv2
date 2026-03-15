/**
 * resetController.js — Secure password reset with async email delivery
 *
 * Architecture:
 *  - HTTP response is sent IMMEDIATELY after token generation (never blocked by email)
 *  - Email is sent asynchronously via Resend API (fire-and-forget with logging)
 *  - 5-second timeout on email delivery — failure is logged, never breaks the response
 *  - In development mode (NODE_ENV !== 'production'), reset link is logged to console
 *
 * Flow:
 *  1. POST /api/auth/forgot-password  — user submits email
 *     → Validate → Find user → Generate 256-bit token → Store SHA-256 hash
 *     → Respond instantly with generic message
 *     → Fire async: Send email via Resend (or log in dev mode)
 *
 *  2. POST /api/auth/reset-password   — user submits token + new password
 *     → Hash incoming token → Find user by hash + valid expiry
 *     → Set new password → Invalidate token → Respond success
 *
 * Security (unchanged):
 *  - 256-bit random token — unguessable
 *  - Stored as SHA-256 hash — DB breach doesn't reveal token
 *  - 30-minute expiry — limits attack window
 *  - Single-use — cleared after successful reset
 *  - Rate limited at route level (3/15min forgot, 5/15min reset)
 *  - Anti-enumeration — identical response regardless of email existence
 *  - Google OAuth users CAN set a password via this flow
 *
 * Environment variables:
 *  - RESEND_API_KEY     — Resend API key (required in production)
 *  - RESEND_FROM        — Verified sender (e.g. "Fillr <noreply@fillr.app>")
 *  - FRONTEND_URL       — Frontend origin for reset link (HTTPS)
 *  - NODE_ENV           — 'production' | 'development'
 */

const crypto   = require('crypto');
const Joi      = require('joi');
const { Resend } = require('resend');
const User     = require('../models/User');
const logger   = require('../services/logger');

// ── Resend initialisation ────────────────────────────────────
// Instantiate once at module load. Emails are sent if RESEND_API_KEY exists,
// otherwise logged to console (for local development).
const HAS_RESEND_KEY = !!process.env.RESEND_API_KEY;
const resend = new Resend(process.env.RESEND_API_KEY || '');

// Startup logging
logger.info('[Reset] RESEND_API_KEY: %s', HAS_RESEND_KEY ? 'SET' : 'NOT SET');
logger.debug('[Reset] RESEND_FROM: %s', process.env.RESEND_FROM || '(using default)');
logger.debug('[Reset] NODE_ENV: %s', process.env.NODE_ENV || '(not set)');

if (!HAS_RESEND_KEY) {
  logger.warn('[Reset] No RESEND_API_KEY — password reset emails will be logged to console only.');
}

// ── Input schemas ─────────────────────────────────────────────
const forgotSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).max(254).lowercase().required(),
});

const resetSchema = Joi.object({
  token: Joi.string().hex().length(64).required(), // 32 bytes → 64 hex chars
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, and one number.',
      'string.min':          'Password must be at least 8 characters.',
      'string.max':          'Password is too long.',
    }),
});

// ── Helpers ───────────────────────────────────────────────────

// SHA-256 token hash — deterministic, allows DB lookup.
// Safe because the raw token has 256-bit entropy (no brute-force risk).
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

// Build branded HTML email body
const buildResetEmailHtml = (resetUrl) => `
  <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px 24px;">
    <h2 style="color: #0f172a; font-size: 20px; margin-bottom: 8px;">Reset your password</h2>
    <p style="color: #475569; font-size: 14px; line-height: 1.6;">
      You requested a password reset for your Fillr account. Click the button below to set a new password.
      This link expires in <strong>30 minutes</strong>.
    </p>
    <a href="${resetUrl}"
       style="display: inline-block; margin: 24px 0; padding: 12px 28px;
              background: #2563eb; color: #fff; font-size: 14px; font-weight: 600;
              text-decoration: none; border-radius: 8px;">
      Reset Password
    </a>
    <p style="color: #94a3b8; font-size: 12px; line-height: 1.6;">
      If you didn't request this, you can safely ignore this email.<br>
      Your password will remain unchanged.
    </p>
    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">
    <p style="color: #cbd5e1; font-size: 11px;">Fillr — Placement Form Autofill</p>
  </div>
`;

/**
 * Send reset email asynchronously with a 5-second timeout.
 * In development mode, logs the reset URL to console instead.
 *
 * This function NEVER throws — all errors are caught and logged.
 * The token is NOT cleared on failure (user can retry via the link
 * if it arrives late, or request a new one).
 *
 * @param {string} email   - Recipient address
 * @param {string} resetUrl - Full HTTPS reset link
 */
const sendResetEmailAsync = async (email, resetUrl) => {
  const logCtx = { email: email.replace(/(.{2}).*(@.*)/, '$1***$2'), timestamp: new Date().toISOString() };

  // ── No API key — log to console only ──────────────────────
  if (!HAS_RESEND_KEY) {
    logger.debug('[Reset][NO-KEY] Reset link for %s: %s', logCtx.email, resetUrl);
    logger.debug('[Reset][NO-KEY] Email NOT sent (RESEND_API_KEY not configured).');
    return;
  }

  // ── Send via Resend API with 5s timeout ─────────────────
  logger.info('[Reset] Sending reset email to %s', logCtx.email);

  try {
    // Race between Resend send and a 5-second timeout
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Email send timed out after 5 seconds')), 5000)
    );

    const result = await Promise.race([
      resend.emails.send({
        from:    process.env.RESEND_FROM || 'Fillr <onboarding@resend.dev>',
        to:      email,
        subject: 'Reset your Fillr password',
        html:    buildResetEmailHtml(resetUrl),
      }),
      timeout,
    ]);

    if (result.error) {
      logger.error('[Reset] Resend API error for %s — %s', logCtx.email, result.error.message);
    } else {
      logger.info('[Reset] Email sent to %s — id: %s', logCtx.email, result.data?.id);
    }
  } catch (err) {
    // Log failure but do NOT throw — response already sent to client
    logger.error('[Reset] Email delivery failed for %s — %s', logCtx.email, err.message);
    // Note: token stays valid in DB. The email may still arrive (network retry),
    // or the user can request a new reset. We do NOT clear the token here because
    // the HTTP response has already been sent — we can't signal failure to the client.
  }
};

// ── POST /api/auth/forgot-password ────────────────────────────
exports.forgotPassword = async (req, res, next) => {
  try {
    const { error, value } = forgotSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { email } = value;

    // ALWAYS return the same response — prevents email enumeration
    const GENERIC_MSG = 'If an account with that email exists, a password reset link has been sent.';

    const user = await User.findOne({ email }).select('+resetPasswordHash +resetPasswordExpiry');

    if (!user) {
      return res.json({ success: true, message: GENERIC_MSG });
    }

    // Google-only users (no password set) CAN use this to add local auth

    // Generate random token (32 bytes = 256-bit entropy)
    const rawToken = crypto.randomBytes(32).toString('hex'); // 64 hex chars
    const hashed   = hashToken(rawToken);
    const expiry   = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    // Store hashed token + expiry
    user.resetPasswordHash   = hashed;
    user.resetPasswordExpiry = expiry;
    await user.save({ validateBeforeSave: false });

    // Build reset URL (always HTTPS in production)
    const frontendUrl = (process.env.FRONTEND_URL || 'https://fillr-placement-autofill.netlify.app').replace(/\/$/, '');
    const resetUrl    = `${frontendUrl}/reset-password?token=${rawToken}`;

    // Fire-and-forget: track password reset metric
    require('../services/metricsService').incrementMetric('passwordResetRequests');

    // ── Respond IMMEDIATELY — email is fire-and-forget ──────
    res.json({ success: true, message: GENERIC_MSG });

    // ── Send email asynchronously (does not block response) ─
    // .catch() is a safety net — sendResetEmailAsync already handles errors internally
    sendResetEmailAsync(email, resetUrl).catch((err) => {
      logger.error('[Reset] Unexpected error in async email:', err.message);
    });
  } catch (err) {
    next(err);
  }
};

// ── POST /api/auth/reset-password ─────────────────────────────
exports.resetPassword = async (req, res, next) => {
  try {
    const { error, value } = resetSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { token, password } = value;

    // Hash the incoming token → compare with stored hash
    const hashed = hashToken(token);

    // Find user with matching hash AND non-expired token
    const user = await User.findOne({
      resetPasswordHash:   hashed,
      resetPasswordExpiry: { $gt: new Date() },
    }).select('+resetPasswordHash +resetPasswordExpiry');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Reset link is invalid or has expired. Please request a new one.',
      });
    }

    // Set new password (bcrypt hashing happens in User model pre-save hook)
    user.password    = password;
    user.authProvider = 'local'; // If they were Google-only, they now also have local auth

    // Invalidate token — single-use enforcement
    user.resetPasswordHash   = null;
    user.resetPasswordExpiry = null;

    await user.save();

    return res.json({
      success: true,
      message: 'Password has been reset successfully. You can now log in with your new password.',
    });
  } catch (err) {
    next(err);
  }
};
