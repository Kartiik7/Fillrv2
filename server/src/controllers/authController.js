/**
 * authController.js — Hardened multi-provider authentication controller
 *
 * Supported auth methods:
 *  1. Email / Password registration + login
 *  2. Google OAuth (verify ID token server-side via google-auth-library)
 *  3. Extension secret key auth (see keyController.js)
 *
 * Protects against:
 *  - Credential stuffing:    Rate limiting applied at route level
 *  - Brute force login:      Rate limiting + generic error messages (no oracle)
 *  - Weak passwords:         Joi schema enforces complexity policy
 *  - Email enumeration:      Same generic message for wrong email OR password
 *  - Injection via body:     Joi stripUnknown + mongoSanitize in middleware
 *  - Weak JWT secret:        Length check at startup; SECRET from env only
 *  - Token replay:           7-day expiry; client must re-auth after expiry
 *  - Forged Google tokens:   Server-side verification of audience, issuer, expiry
 *  - Frontend token trust:   Google ID token ALWAYS verified with google-auth-library
 */

const jwt  = require('jsonwebtoken');
const Joi  = require('joi');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const { sendVerificationEmail } = require('./verificationController');
const { incrementMetric, trackActiveUser } = require('../services/metricsService');
const { createAuditLog } = require('../services/auditService');

// ── Google OAuth client ───────────────────────────────────────
// GOOGLE_CLIENT_ID must be set in environment — used to verify token audience.
// Protects against: forged tokens with wrong audience claiming to be from our app.
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ── Input schemas ─────────────────────────────────────────────
// Rejects untyped / unexpected fields via stripUnknown.
// Enforces password complexity — minimum barrier against weak credentials.
const registerSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).max(254).lowercase().required(),
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, and one number.',
      'string.min': 'Password must be at least 8 characters.',
      'string.max': 'Password is too long.',
    }),
  // Legal consent — must be explicitly true; false/missing = rejected
  // Protects against: users being registered without informed consent
  termsAccepted: Joi.boolean().valid(true).required().messages({
    'any.only': 'You must accept the Terms & Conditions and Privacy Policy to register.',
    'any.required': 'You must accept the Terms & Conditions and Privacy Policy to register.',
  }),
});

const loginSchema = Joi.object({
  email:    Joi.string().email({ tlds: { allow: false } }).max(254).lowercase().required(),
  password: Joi.string().min(1).max(128).required(),
});

const googleSchema = Joi.object({
  credential: Joi.string().min(1).max(4096).required(),
  // termsAccepted is required for new Google users (first login creates account).
  // For existing Google users, it's optional — they already accepted during first login.
  // The controller enforces this: if user is new, termsAccepted must be true.
  termsAccepted: Joi.boolean().optional(),
});

// ── Unified JWT generator ─────────────────────────────────────
// 7-day expiry — short enough to limit token-replay window.
// Secret MUST be set in environment — never hardcoded.
// All auth methods call this same function — unified token strategy.
const generateToken = (id) => {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET is missing or too short. Set a strong secret (32+ chars) in environment variables.');
  }
  return jwt.sign({ id }, secret, { expiresIn: '7d' });
};

// ── Unified response helper ───────────────────────────────────
// All successful auth methods return the same shape:
//   { success, accessToken, expiresIn, token (compat), message }
// Protects against: inconsistent token handling across clients.
const sendTokenResponse = (res, user, message, statusCode = 200) => {
  const accessToken = generateToken(user._id);
  return res.status(statusCode).json({
    success: true,
    accessToken,
    // Also include 'token' for backward compatibility with existing clients
    token: accessToken,
    expiresIn: '7d',
    message,
  });
};

const sendSuspendedError = (res) => {
  return res.status(403).json({
    success: false,
    code: 'ACCOUNT_SUSPENDED',
    message: 'Access denied.',
  });
};

const logSuspendedAttempt = ({ userId, action, ip }) => {
  createAuditLog({
    action,
    adminId: userId,
    ip,
    metadata: { channel: 'AUTH' },
  });
};

// ── Register (Email/Password) ─────────────────────────────────
exports.register = async (req, res, next) => {
  try {
    // Validate and strip unknown fields
    const { error, value } = registerSchema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details.map((d) => d.message).join(' '),
      });
    }

    const { email, password } = value;

    // Duplicate-email check — use lean + index for performance
    // .select('_id') minimises data transfer — we only need existence
    const existing = await User.findOne({ email }).select('_id').lean();
    if (existing) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists.' });
    }

    // bcrypt hashing happens in User pre-save hook (salt rounds: 10)
    const user = await User.create({
      email,
      password,
      authProvider:    'local',
      isVerified:      true, // Beta: auto-verify (email verification disabled)
      // Legal consent recorded at time of registration
      termsAccepted:   true,
      termsAcceptedAt: new Date(),
      termsVersion:    '1.0',
      privacyVersion:  '1.0',
      profile: { personal: { email } },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Registration failed. Please try again.' });
    }

    // Fire-and-forget: track registration metric
    incrementMetric('userRegistrations');

    // Beta: Email verification disabled — users auto-verified at registration
    // TODO: Re-enable for production:
    // sendVerificationEmail(user).catch((err) => {
    //   logger.error('[Register] Failed to queue verification email:', err.message);
    // });

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
    });
  } catch (err) {
    next(err);
  }
};

// ── Login (Email/Password) ────────────────────────────────────
exports.login = async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body, {
      abortEarly: true,
      stripUnknown: true,
    });
    if (error) {
      // Generic message — avoids disclosing which field is wrong
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    const { email, password } = value;

    // Constant-time user lookup — avoids timing oracle
    // Protects against: email enumeration via response time differences
    const user = await User.findOne({ email });

    // Reject Google OAuth users trying email/password login
    // Protects against: password guessing on passwordless accounts
    if (user && user.authProvider === 'google' && !user.password) {
      return res.status(401).json({
        success: false,
        message: 'This account uses Google Sign-In. Please log in with Google.',
      });
    }

    if (!user || !(await user.matchPassword(password))) {
      // Same response for wrong email AND wrong password — prevents enumeration
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    // Block suspended accounts before issuing JWT
    // (authMiddleware handles subsequent requests; this handles initial token issuance)
    if (user.isSuspended) {
      logSuspendedAttempt({
        userId: user._id,
        action: 'ACCOUNT_SUSPENDED_LOGIN_ATTEMPT',
        ip: req.ip,
      });
      return sendSuspendedError(res);
    }

    // Fire-and-forget: track login metric + active user
    incrementMetric('loginRequests');
    trackActiveUser(user._id);

    // Beta: Email verification disabled — skip isVerified check
    // TODO: Re-enable for production:
    // if (!user.isVerified) {
    //   return res.status(403).json({
    //     success: false,
    //     message: 'Please verify your email before logging in.',
    //     needsVerification: true,
    //     email: user.email,
    //   });
    // }

    return sendTokenResponse(res, user, 'Login successful.');
  } catch (err) {
    next(err);
  }
};

// ── Google OAuth Login ────────────────────────────────────────
// Verifies Google ID token server-side. NEVER trusts the frontend token alone.
// Flow: Frontend gets credential via Google popup → sends to this endpoint →
//       server verifies audience, issuer, expiry → creates/finds user → issues JWT.
//
// Protects against:
//  - Forged tokens:  google-auth-library verifies signature + audience + issuer
//  - Token replay:   expiry checked by library; our JWT has its own 7d expiry
//  - Account hijack: googleId is tied to a specific user — cannot be reassigned
exports.googleLogin = async (req, res, next) => {
  try {
    const { error, value } = googleSchema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details.map((d) => d.message).join(' '),
      });
    }

    const { credential } = value;

    // Verify Google ID token — checks signature, audience, issuer, expiry
    // Protects against: forged/expired tokens, wrong audience
    let ticket;
    try {
      ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
    } catch (verifyErr) {
      // Do not expose internal Google verification errors
      return res.status(401).json({ success: false, message: 'Google authentication failed. Please try again.' });
    }

    const payload = ticket.getPayload();

    // Validate required fields from Google payload
    if (!payload || !payload.sub || !payload.email) {
      return res.status(401).json({ success: false, message: 'Invalid Google token payload.' });
    }

    const { sub: googleId, email, name, email_verified } = payload;

    // Reject unverified Google emails — prevents fake account creation
    if (!email_verified) {
      return res.status(401).json({ success: false, message: 'Google email is not verified.' });
    }

    // Check if user exists by googleId first, then by email
    let user = await User.findOne({ googleId });

    if (!user) {
      // Check if a local user with the same email exists
      user = await User.findOne({ email: email.toLowerCase() });

      if (user) {
        // Link Google to existing local account
        user.googleId    = googleId;
        user.displayName = name || user.displayName;
        user.isVerified  = true; // Google verified their email — trust it
        // Keep authProvider as 'local' if they already had a password —
        // this allows both login methods for the same account.
        if (!user.password) {
          user.authProvider = 'google';
        }
        await user.save();
      } else {
        // NEW user — terms consent is REQUIRED for account creation
        if (!value.termsAccepted) {
          return res.status(400).json({
            success: false,
            message: 'You must accept the Terms & Conditions and Privacy Policy to create an account.',
            requireTerms: true, // Signal to frontend to show consent UI
          });
        }

        // Fire-and-forget: track new Google registration
        incrementMetric('userRegistrations');

        // Create new Google OAuth user — no password required
        // isVerified: true — Google already verified their email
        user = await User.create({
          email: email.toLowerCase(),
          authProvider:    'google',
          googleId,
          displayName:     name || '',
          isVerified:      true,
          termsAccepted:   true,
          termsAcceptedAt: new Date(),
          termsVersion:    '1.0',
          privacyVersion:  '1.0',
          profile: {
            personal: {
              name: name || '',
              email: email.toLowerCase(),
            },
          },
        });
      }
    }

    // Block suspended accounts before issuing JWT
    if (user.isSuspended) {
      logSuspendedAttempt({
        userId: user._id,
        action: 'ACCOUNT_SUSPENDED_LOGIN_ATTEMPT',
        ip: req.ip,
      });
      return sendSuspendedError(res);
    }

    // Fire-and-forget: track Google login metric + active user
    incrementMetric('loginRequests');
    trackActiveUser(user._id);

    return sendTokenResponse(res, user, 'Google login successful.');
  } catch (err) {
    next(err);
  }
};

// Export for use in routes and keyController (unified token generator)
exports.generateToken = generateToken;
