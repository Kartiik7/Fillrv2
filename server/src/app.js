/**
 * app.js — Production-hardened Express application
 *
 * Threat model summary:
 *  - Helmet:              Clickjacking, MIME sniff, XSS reflections, referrer leaks
 *  - CORS whitelist:      CORS bypass via unexpected origin (origin whitelist, not wildcard)
 *  - Rate limiting:       Brute force, credential stuffing, rate abuse, DDoS
 *  - Body size limit:     Payload-based DoS / memory exhaustion
 *  - mongoSanitize:       NoSQL injection via $-operator keys in request body
 *  - Centralized errors:  Stack-trace / internal detail leakage in production
 *  - Logger:              Structured leveled logging (no raw console.* in production)
 */

const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const compression  = require('compression');
const rateLimit    = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const authRoutes    = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const userRoutes    = require('./routes/userRoutes');
const keyRoutes     = require('./routes/keyRoutes');
const configRoutes  = require('./routes/configRoutes');
const adminRoutes   = require('./routes/adminRoutes');

const { incrementError, incrementRequest } = require('./services/metricsService');
const logger = require('./services/logger');

const isProd = process.env.NODE_ENV === 'production';
const app    = express();

// ── Trust proxy (required for rate limiting behind Render/Heroku/etc) ─
// Tells Express to trust X-Forwarded-* headers from the first proxy
app.set('trust proxy', 1);

// ── Security headers (OWASP baseline) ────────────────────────
// Explicit Helmet config (don't rely on insecure defaults).
// Protects against: XSS, clickjacking, MIME sniffing, HSTS stripping.
app.use(helmet({
  // Content-Security-Policy: only allow resources from same origin by default.
  // Adjust if you serve inline scripts or fonts from CDNs.
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'"],
      styleSrc:       ["'self'", "'unsafe-inline'"], // allow Tailwind inline styles
      imgSrc:         ["'self'", 'data:', 'https:'],
      connectSrc:     ["'self'"],
      fontSrc:        ["'self'", 'https:', 'data:'],
      objectSrc:      ["'none'"],
      frameSrc:       ["'none'"],
      upgradeInsecureRequests: isProd ? [] : null,
    },
  },
  // Strict-Transport-Security: require HTTPS for 1 year in production
  hsts: isProd
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  // X-Frame-Options: deny clickjacking
  frameguard: { action: 'deny' },
  // X-Content-Type-Options: prevent MIME sniffing
  noSniff: true,
  // X-XSS-Protection: belt-and-suspenders for old browsers
  xssFilter: true,
  // Referrer-Policy: don't leak URL path to third parties
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Permissions-Policy: disable browser features not needed by this API
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));
app.disable('x-powered-by'); // belt-and-suspenders; helmet already removes it

// ── Gzip compression ──────────────────────────────────────────
app.use(compression());

// ── CORS — Strict Origin Whitelist ──────────────────────────
// Only allow known origins. In production, read from env.
// In development, allow localhost ports for convenience.
const allowedOrigins = isProd
  ? (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean)
  : [
      'http://localhost:3000',
      'http://localhost:5000',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5500',
    ];

app.use(cors({
  origin(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: Origin '${origin}' not allowed.`));
  },
  credentials: true,           // Allow cookies/auth headers cross-origin
  optionsSuccessStatus: 200,
}));

// ── Body parsing — with size limit ────────────────────────────
// Prevents payload-flooding DoS attacks
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ── NoSQL injection sanitization ──────────────────────────────
// Strips $ and . from keys — prevents $where, $gt, $regex injection
// Protects against: User.find(req.body) style injection attacks
// express-mongo-sanitize middleware is NOT used because Express 5 makes
// req.query read-only, causing "Cannot set property query" errors.
// Instead we use the sanitize() function directly on body & params.
app.use((req, _res, next) => {
  if (req.body)   mongoSanitize.sanitize(req.body);
  if (req.params) mongoSanitize.sanitize(req.params);
  next();
});

// ── Global rate limiter ───────────────────────────────────────
// Protects against: rate abuse, DDoS, brute force on non-auth routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please try again later.' },
});
app.use(globalLimiter);

// ── Request counter (fire-and-forget) ─────────────────────────
app.use((_req, _res, next) => {
  incrementRequest();
  next();
});

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth',    authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/user',    userRoutes);
app.use('/api/keys',    keyRoutes);
app.use('/api/config',  configRoutes);   // Public read-only config
app.use('/api/admin',   adminRoutes);    // Admin-only management

// Health check — includes DB readiness
const mongoose = require('mongoose');
app.get('/health', (_req, res) => {
  const dbReady = mongoose.connection.readyState === 1; // 1 = connected
  const status  = dbReady ? 'ok' : 'degraded';
  res.status(dbReady ? 200 : 503).json({ status, db: dbReady ? 'connected' : 'disconnected' });
});

// ── 404 handler ───────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found.' });
});

// ── Centralized error handler ─────────────────────────────────
// Does NOT leak stack traces or internal messages in production.
// Protects against: internal detail / path disclosure
//
// Error categorization (prioritized):
//  - Mongoose ValidationError  → 400 (invalid data from client)
//  - Mongoose CastError        → 400 (invalid ObjectId, etc.)
//  - Duplicate key (11000)     → 409 (e.g. duplicate email)
//  - JWT errors                → 401 (handled in authMiddleware too)
//  - Generic app errors        → status from err.status or 500
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  // Fire-and-forget: track error metric
  incrementError();

  // ── Mongoose: validation error ────────────────────────────
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ success: false, message: messages.join(' ') });
  }

  // ── Mongoose: bad ObjectId / type cast ───────────────────
  if (err.name === 'CastError') {
    return res.status(400).json({ success: false, message: `Invalid value for field '${err.path}'.` });
  }

  // ── MongoDB: duplicate key (e.g. duplicate email) ─────────
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    return res.status(409).json({ success: false, message: `${field} already exists.` });
  }

  // ── JWT errors (belt-and-suspenders for middleware misses) ─
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({ success: false, message: 'Invalid or expired session. Please log in again.' });
  }

  const status = err.status || err.statusCode || 500;

  if (isProd) {
    // Log server-side only — never expose to client
    logger.error(`[${status}] ${err.message}`);
    return res.status(status).json({
      success: false,
      message: err.expose ? err.message : 'An unexpected error occurred.',
    });
  }
  // Development — richer detail ok
  logger.error(err);
  res.status(status).json({ success: false, message: err.message, stack: err.stack });
});

module.exports = app;
