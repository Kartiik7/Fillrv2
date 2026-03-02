/**
 * configRoutes.js — Public read-only config endpoints
 *
 * GET /api/config/full              — Returns version + mappings in one trip (preferred)
 * GET /api/config/field-mappings    — Returns clean JSON field mappings (legacy)
 * GET /api/config/version           — Returns current config version number (legacy)
 *
 * No auth required — these are consumed by the extension before login.
 *
 * Network-call budget per extension load (using /full):
 *   1 request  — version + mappings combined
 *   0 requests — subsequent calls within the same session when cached
 *
 * Security:
 *  - Read-only, no mutations
 *  - No internal fields exposed (_id stripped)
 *  - No metadata leakage
 *  - Rate limited: 60 requests per 15 min per IP (extension poll protection)
 */

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const FieldMapping   = require('../models/FieldMapping');
const ConfigVersion  = require('../models/ConfigVersion');
const logger         = require('../services/logger');

const router = express.Router();

// Rate limit — protects against polling abuse from extensions.
// Extensions now call /full (1 request per load) instead of /version + /field-mappings
// (2 requests). Limit raised to 60 to give headroom for retries without tightening UX.
const configLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many config requests. Please retry later.' },
});

router.use(configLimiter);

/**
 * GET /api/config/full
 * Returns the current config version AND all field mappings in a single response.
 *
 * This is the preferred endpoint for the extension — it replaces the two-trip
 * pattern (/version then /field-mappings) with one HTTP round trip.
 *
 * The extension compares the returned `version` against its last cached value:
 *   • Same version  → skip re-processing; re-use the in-memory processed map.
 *   • New version   → rebuild the processed map from the returned `mappings`.
 *
 * Response shape:
 *   { success: true, version: number, updatedAt: Date,
 *     mappings: { [key]: { path, primary, secondary, generic, negative } } }
 */
router.get('/full', async (_req, res) => {
  try {
    // Single await — both queries run against indexed singleton + indexed collection.
    const [config, rawMappings] = await Promise.all([
      ConfigVersion.current(),
      FieldMapping.find({})
        .select('-_id key path fieldType primary secondary generic negative')
        .lean(),
    ]);

    const mappings = {};
    for (const m of rawMappings) {
      mappings[m.key] = {
        path:      m.path,
        fieldType: m.fieldType || 'text',
        primary:   m.primary   || [],
        secondary: m.secondary || [],
        generic:   m.generic   || [],
        negative:  m.negative  || [],
      };
    }

    res.json({
      success:   true,
      version:   config.version,
      updatedAt: config.updatedAt,
      mappings,
    });
  } catch (err) {
    logger.error('[configRoutes] /full error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load config.' });
  }
});

/**
 * GET /api/config/field-mappings
 * Returns all field mappings as a clean { key → { path, primary, secondary, generic, negative } } map.
 * No _id, no __v, no updatedAt — only what the extension needs.
 */
router.get('/field-mappings', async (_req, res) => {
  try {
    const mappings = await FieldMapping.find({})
      .select('-_id key path fieldType primary secondary generic negative')
      .lean();

    // Transform array into { key: { path, fieldType, primary, secondary, generic, negative } } object
    const result = {};
    for (const m of mappings) {
      result[m.key] = {
        path:      m.path,
        fieldType: m.fieldType || 'text',
        primary:   m.primary   || [],
        secondary: m.secondary || [],
        generic:   m.generic   || [],
        negative:  m.negative  || [],
      };
    }

    res.json({ success: true, mappings: result });
  } catch (err) {
    logger.error('[configRoutes] field-mappings error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load field mappings.' });
  }
});

/**
 * GET /api/config/version
 * Returns the current config version number.
 * Extension compares this to its cached version to decide whether to refetch.
 */
router.get('/version', async (_req, res) => {
  try {
    const config = await ConfigVersion.current();
    res.json({ success: true, version: config.version, updatedAt: config.updatedAt });
  } catch (err) {
    logger.error('[configRoutes] version error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load config version.' });
  }
});

/**
 * GET /api/config/meta
 * Lightweight metadata about field mappings. Public-safe.
 * Returns only the latest updatedAt across all mappings (no PII, no payload bloat).
 */
router.get('/meta', async (_req, res) => {
  try {
    const agg = await FieldMapping.aggregate([
      { $group: { _id: null, lastUpdated: { $max: '$updatedAt' } } },
    ]);
    const lastUpdated = agg[0]?.lastUpdated || null;
    res.json({ success: true, lastUpdated });
  } catch (err) {
    logger.error('[configRoutes] meta error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load config metadata.' });
  }
});

module.exports = router;
